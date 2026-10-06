// RPC-backed `Ledger` (SAC-006). Reads the cluster Clock and accounts, simulates with the
// sponsor signature absent (`sigVerify: false`, `replaceRecentBlockhash: false`), and submits
// the exact co-signed bytes once, classifying the result into the three-way outcome the
// facilitator requires (see `ledger.ts`). The program's onchain guards remain authoritative;
// this adapter never replaces a blockhash, re-signs, or retries an ambiguous submission. It also
// serves the read-only `ChainReader` evidence manual reconciliation uses (`reconciliation.ts`).
import {
  type Address,
  createSolanaRpc,
  getBase64Encoder,
  type Blockhash,
  getBase64EncodedWireTransaction,
  getSignatureFromTransaction,
  getTransactionDecoder,
  isSolanaError,
  type Rpc,
  signature as asSignature,
  SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE,
  SOLANA_ERROR__TRANSACTION_ERROR__ALREADY_PROCESSED,
  SOLANA_ERROR__TRANSACTION_ERROR__BLOCKHASH_NOT_FOUND,
  type SolanaRpcApi,
  type Transaction,
} from "@solana/kit";
import type { FinalizedOutcome, Ledger, LedgerAccount, SimulationOutcome, SubmitResult } from "./ledger.ts";
import type { BlockhashCheck, ChainReader, MessageSearch, SignatureLookup, SlotAccount } from "./reconciliation.ts";
import type { Lifetime } from "./transactions.ts";

const CLOCK_SYSVAR = "SysvarC1ock11111111111111111111111111111111" as Address;
const base64Encoder = getBase64Encoder();
const decodeBase64 = (data: string): Uint8Array => new Uint8Array(base64Encoder.encode(data));
const transactionDecoder = getTransactionDecoder();
const describe = (error: unknown): string => (error instanceof Error ? error.message : String(error));

/** Bounded history scan for `findSignaturesByMessage`; a demo payment PDA sees a handful of transactions. */
const MESSAGE_SEARCH_LIMIT = 50;

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

export type RpcLedgerConfig = {
  /** CAIP-2 identity this ledger reports; the facilitator rejects a configuration mismatch against it. */
  network: string;
  /** Full base58 genesis hash the configured RPC endpoint must observe; checked by `verifyGenesis`. */
  genesisHash: string;
  rpcUrl: string;
  /**
   * Settlement deadline for `submit`, in milliseconds from the moment it is called: it bounds the
   * `sendTransaction` call (itself also limited to `requestTimeoutMs`) and every status request
   * after it. A finalized failure's log fetch gets one further `requestTimeoutMs`. Default 60s:
   * Devnet finalization has been observed to exceed 30s.
   */
  confirmTimeoutMs?: number;
  pollIntervalMs?: number;
  /** Bound on every other single RPC request (reads, simulation, genesis). Default 10s. */
  requestTimeoutMs?: number;
  /** Test seam: injects an RPC client instead of creating one from `rpcUrl`. Unused in production. */
  rpc?: Rpc<SolanaRpcApi>;
};

function decodeClockUnixTimestamp(data: Uint8Array): bigint {
  // Clock sysvar layout: slot:u64, epoch_start_timestamp:i64, epoch:u64, leader_schedule_epoch:u64,
  // unix_timestamp:i64 (https://docs.rs/solana-clock/latest/solana_clock/struct.Clock.html).
  if (data.length < 40) throw new Error(`RpcLedger.now: unexpected Clock sysvar length ${data.length}`);
  return new DataView(data.buffer, data.byteOffset, data.byteLength).getBigInt64(32, true);
}

/**
 * An RPC URL safe to log or put in an error: scheme, host, and path only. Provider API keys
 * travel in the query string or userinfo, and every message here can end up in evidence.
 */
export function redactRpcUrl(url: string): string {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}${u.pathname === "/" ? "" : u.pathname}${u.search || u.username ? " (credentials redacted)" : ""}`;
  } catch {
    return "<unparseable RPC URL>";
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** A network await that did not finish by its deadline; what it would have returned is unknown. */
export class RpcDeadlineExceeded extends Error {
  constructor() {
    super("RPC request did not complete before its deadline");
  }
}

/**
 * Runs one RPC request that must finish by `deadline` (epoch ms). The request receives an abort
 * signal, and the wait is raced against the deadline too, so a transport that ignores aborts
 * still cannot hold the caller past it.
 */
async function byDeadline<T>(deadline: number, request: (abortSignal: AbortSignal) => Promise<T>): Promise<T> {
  const remaining = deadline - Date.now();
  if (remaining <= 0) throw new RpcDeadlineExceeded();
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expired = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      // Reject first, so a transport that rejects synchronously on abort cannot win the race
      // with its own error.
      reject(new RpcDeadlineExceeded());
      controller.abort();
    }, remaining);
  });
  try {
    return await Promise.race([request(controller.signal), expired]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * A cluster clock for request paths that must not cost one RPC read per anonymous request (the
 * 402 challenge): reads the Clock sysvar at most once per `maxAgeMs` (one read in flight at a
 * time), advances it by local elapsed time in between, and never steps backwards.
 */
export function cachedClusterClock(read: () => Promise<bigint>, maxAgeMs = 10_000): () => Promise<bigint> {
  let base: { cluster: bigint; at: number } | undefined;
  let refreshing: Promise<void> | undefined;
  let last = 0n;
  return async () => {
    if (!base || Date.now() - base.at > maxAgeMs) {
      refreshing ??= read()
        .then((cluster) => {
          base = { cluster, at: Date.now() };
        })
        .finally(() => {
          refreshing = undefined;
        });
      await refreshing;
    }
    const now = base!.cluster + BigInt(Math.floor((Date.now() - base!.at) / 1000));
    if (now > last) last = now;
    return last;
  };
}

export class RpcLedger implements Ledger, ChainReader {
  readonly network: string;
  private readonly rpcUrl: string;
  private readonly genesisHash: string;
  private readonly rpc: Rpc<SolanaRpcApi>;
  private readonly confirmTimeoutMs: number;
  private readonly pollIntervalMs: number;
  private readonly requestTimeoutMs: number;

  // Plain-field assignment, not a TS constructor parameter property: this file must stay runnable
  // under Node's `--experimental-strip-types`, which does not support parameter properties.
  constructor(config: RpcLedgerConfig) {
    this.network = config.network;
    this.rpcUrl = config.rpcUrl;
    this.genesisHash = config.genesisHash;
    this.rpc = config.rpc ?? createSolanaRpc(config.rpcUrl);
    this.confirmTimeoutMs = config.confirmTimeoutMs ?? 60_000;
    this.pollIntervalMs = config.pollIntervalMs ?? 1_000;
    this.requestTimeoutMs = config.requestTimeoutMs ?? 10_000;
    if (!(this.confirmTimeoutMs > 0) || !(this.requestTimeoutMs > 0)) throw new Error("RpcLedger timeouts must be positive");
  }

  /** One bounded RPC request outside the settlement path. */
  private request<T>(send: (abortSignal: AbortSignal) => Promise<T>): Promise<T> {
    return byDeadline(Date.now() + this.requestTimeoutMs, send);
  }

  /**
   * Must be called and awaited once before this ledger is handed to the facilitator: rejects a
   * configured RPC endpoint whose genesis does not match the pinned deployment record.
   */
  async verifyGenesis(): Promise<void> {
    const observed = await this.request((abortSignal) => this.rpc.getGenesisHash().send({ abortSignal }));
    if (observed !== this.genesisHash) {
      throw new Error(`RpcLedger genesis mismatch at ${redactRpcUrl(this.rpcUrl)}: configured ${this.genesisHash}, observed ${observed}`);
    }
  }

  async now(): Promise<bigint> {
    const { value } = await this.request((abortSignal) => this.rpc.getAccountInfo(CLOCK_SYSVAR, { encoding: "base64" }).send({ abortSignal }));
    if (!value) throw new Error("RpcLedger.now: Clock sysvar account not found");
    return decodeClockUnixTimestamp(decodeBase64(value.data[0]));
  }

  /** A finalized blockhash and its last valid block height, for building a new transaction. */
  async latestBlockhash(): Promise<Lifetime> {
    const { value } = await this.request((abortSignal) => this.rpc.getLatestBlockhash({ commitment: "finalized" }).send({ abortSignal }));
    return { blockhash: value.blockhash, lastValidBlockHeight: value.lastValidBlockHeight };
  }

  async getAccount(address: Address): Promise<LedgerAccount | null> {
    const { value } = await this.request((abortSignal) => this.rpc.getAccountInfo(address, { encoding: "base64" }).send({ abortSignal }));
    if (!value) return null;
    return { owner: value.owner, data: decodeBase64(value.data[0]), lamports: value.lamports, executable: value.executable };
  }

  async simulate(transaction: Transaction): Promise<SimulationOutcome> {
    const wire = getBase64EncodedWireTransaction(transaction);
    const { value } = await this.request((abortSignal) =>
      this.rpc.simulateTransaction(wire, { encoding: "base64", sigVerify: false, replaceRecentBlockhash: false }).send({ abortSignal }),
    );
    if (value.err === null) return { ok: true };
    return { ok: false, error: JSON.stringify(value.err), logs: [...(value.logs ?? [])] };
  }

  async submit(transaction: Transaction): Promise<SubmitResult> {
    const wire = getBase64EncodedWireTransaction(transaction);
    const expectedSignature = getSignatureFromTransaction(transaction);
    // The settlement deadline starts before the broadcast: it bounds the send itself and every
    // status/log request after it.
    const deadline = Date.now() + this.confirmTimeoutMs;

    let signature: string;
    try {
      // The send gets its own bound inside the settlement deadline, so a slow send cannot use up
      // the whole polling budget.
      signature = await byDeadline(Math.min(deadline, Date.now() + this.requestTimeoutMs), (abortSignal) =>
        this.rpc
          .sendTransaction(wire, { encoding: "base64", skipPreflight: false, preflightCommitment: "processed", maxRetries: 0n })
          .send({ abortSignal }),
      );
    } catch (error) {
      if (isSolanaError(error, SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE)) {
        const cause = (error as { cause?: unknown }).cause;
        if (
          isSolanaError(cause, SOLANA_ERROR__TRANSACTION_ERROR__ALREADY_PROCESSED) ||
          isSolanaError(cause, SOLANA_ERROR__TRANSACTION_ERROR__BLOCKHASH_NOT_FOUND)
        ) {
          // A refusal without execution is not proof these bytes never landed: `AlreadyProcessed`
          // says this exact signature is in the status cache, and `BlockhashNotFound` can follow
          // an earlier broadcast of the same bytes whose blockhash has since aged out. Resolve the
          // original signature's own outcome; until it is finalized it stays unresolved.
          return { kind: "submitted", outcome: await this.pollForFinalized(expectedSignature, deadline) };
        }
        if (cause === undefined) {
          // A preflight refusal with no transaction error attached is a malformed response: it
          // proves nothing about these bytes, so it cannot become `not-submitted`.
          return { kind: "submitted" };
        }
        // The node's own preflight simulation rejected these bytes with an execution error
        // before broadcasting them: this call put nothing on the cluster.
        return { kind: "not-submitted", reason: `${error.message}: ${describe(cause)}` };
      }
      // Any other failure (transport error, an expired deadline, a malformed response) cannot
      // prove the exact bytes were never broadcast: stay in the ambiguous `submitted` branch,
      // never guess `not-submitted`, and never send again.
      return { kind: "submitted" };
    }

    if (signature !== expectedSignature) {
      // Cannot trust a status lookup for a signature the facilitator did not derive locally from
      // these exact bytes.
      return { kind: "submitted" };
    }

    return { kind: "submitted", outcome: await this.pollForFinalized(signature, deadline) };
  }

  /** Polls the exact signature until `deadline`; every request, sleep, and log fetch ends by then. */
  private async pollForFinalized(signature: string, deadline: number): Promise<FinalizedOutcome | undefined> {
    while (Date.now() < deadline) {
      try {
        const { value } = await byDeadline(deadline, (abortSignal) =>
          this.rpc.getSignatureStatuses([asSignature(signature)], { searchTransactionHistory: true }).send({ abortSignal }),
        );
        const status = value[0];
        if (status && status.confirmationStatus === "finalized") {
          if (status.err === null) return { status: "succeeded", commitment: "finalized" };
          return { status: "failed", commitment: "finalized", error: JSON.stringify(status.err), logs: await this.fetchFinalizedLogs(signature) };
        }
        // `null` (missing history) or a weaker commitment is missing evidence, not proof of
        // non-finality: keep polling within the bounded wait.
      } catch {
        // A transport/lookup failure or expired request is also missing evidence, not proof.
      }
      await sleep(Math.min(this.pollIntervalMs, Math.max(0, deadline - Date.now())));
    }
    // Deadline reached without a finalized status: stays ambiguous, never guessed or resent.
    return undefined;
  }

  // --- ChainReader: read-only evidence for manual reconciliation (`reconciliation.ts`). Every
  // RPC failure is reported as `unavailable`, never as absence.

  async getSignatureStatus(signature: string): Promise<SignatureLookup> {
    try {
      const { value } = await this.request((abortSignal) =>
        this.rpc.getSignatureStatuses([asSignature(signature)], { searchTransactionHistory: true }).send({ abortSignal }),
      );
      const status = value[0];
      if (!status) return { kind: "not-found" };
      const commitment = status.confirmationStatus;
      if (commitment !== "processed" && commitment !== "confirmed" && commitment !== "finalized") {
        return { kind: "unavailable", detail: `malformed confirmationStatus ${JSON.stringify(commitment)}` };
      }
      return { kind: "found", slot: BigInt(status.slot), commitment, err: status.err === null ? null : JSON.stringify(status.err) };
    } catch (error) {
      return { kind: "unavailable", detail: describe(error) };
    }
  }

  async findSignaturesByMessage(address: Address, messageBytes: Uint8Array): Promise<MessageSearch> {
    // One deadline for the whole search, not per request: a slow RPC cannot stretch it to
    // `MESSAGE_SEARCH_LIMIT` request timeouts.
    const deadline = Date.now() + this.confirmTimeoutMs;
    try {
      const entries = await byDeadline(deadline, (abortSignal) =>
        this.rpc.getSignaturesForAddress(address, { limit: MESSAGE_SEARCH_LIMIT, commitment: "confirmed" }).send({ abortSignal }),
      );
      for (const entry of entries) {
        const tx = await byDeadline(deadline, (abortSignal) =>
          this.rpc.getTransaction(entry.signature, { encoding: "base64", commitment: "confirmed", maxSupportedTransactionVersion: 0 }).send({ abortSignal }),
        );
        if (!tx) return { kind: "unavailable", detail: `history for ${entry.signature} is listed but not retrievable` };
        const decoded = transactionDecoder.decode(decodeBase64(tx.transaction[0]));
        // Identical message bytes always carry the identical sponsor signature: one match is all.
        if (sameBytes(new Uint8Array(decoded.messageBytes), messageBytes)) return { kind: "ok", signatures: [entry.signature], truncated: false };
      }
      return { kind: "ok", signatures: [], truncated: entries.length >= MESSAGE_SEARCH_LIMIT };
    } catch (error) {
      return { kind: "unavailable", detail: describe(error) };
    }
  }

  async isBlockhashValid(blockhash: string): Promise<BlockhashCheck> {
    try {
      // Latest (processed) bank: a blockhash newer than the finalized bank is still unknown
      // there and would look expired, so finalized cannot be used. A blockhash invalid at the
      // latest bank is invalid for every later bank. The returned slot is where any landing must
      // already be visible, so callers read state at a finalized slot no older than it.
      const { context, value } = await this.request((abortSignal) =>
        this.rpc.isBlockhashValid(blockhash as Blockhash, { commitment: "processed" }).send({ abortSignal }),
      );
      return { kind: "ok", valid: value, slot: BigInt(context.slot) };
    } catch (error) {
      return { kind: "unavailable", detail: describe(error) };
    }
  }

  async getAccountAtLeast(address: Address, minContextSlot: bigint): Promise<SlotAccount> {
    // Finalization trails the latest slot by ~32 slots: wait, within the bounded window, for the
    // finalized bank to reach `minContextSlot` instead of reporting older state.
    const deadline = Date.now() + this.confirmTimeoutMs;
    let detail = "finalized bank did not reach the required slot";
    do {
      try {
        const { context, value } = await byDeadline(deadline, (abortSignal) =>
          this.rpc.getAccountInfo(address, { encoding: "base64", commitment: "finalized", minContextSlot }).send({ abortSignal }),
        );
        const account = value
          ? { owner: value.owner, data: decodeBase64(value.data[0]), lamports: value.lamports, executable: value.executable }
          : null;
        return { kind: "ok", slot: BigInt(context.slot), account };
      } catch (error) {
        detail = describe(error);
      }
      await sleep(Math.min(this.pollIntervalMs, Math.max(0, deadline - Date.now())));
    } while (Date.now() < deadline);
    return { kind: "unavailable", detail };
  }

  /**
   * Logs are auxiliary to an already-established finalized failure: one request with its own
   * bound (so a failure seen at the end of the settlement window still gets a chance at its
   * diagnostics), and an empty list when they cannot be fetched.
   */
  private async fetchFinalizedLogs(signature: string): Promise<string[]> {
    try {
      const tx = await this.request((abortSignal) =>
        this.rpc.getTransaction(asSignature(signature), { commitment: "finalized", encoding: "json" }).send({ abortSignal }),
      );
      return [...(tx?.meta?.logMessages ?? [])];
    } catch {
      return [];
    }
  }
}
