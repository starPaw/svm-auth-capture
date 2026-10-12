// RPC-backed `Ledger` (SAC-006). Reads the cluster Clock and accounts, simulates with the
// sponsor signature absent (`sigVerify: false`, `replaceRecentBlockhash: false`), and submits
// the exact co-signed bytes once, classifying the result into the three-way outcome the
// facilitator requires (see `ledger.ts`). The program's onchain guards remain authoritative;
// this adapter never replaces a blockhash, re-signs, or retries an ambiguous submission. It also
// serves the read-only `ChainReader` evidence manual reconciliation uses (`reconciliation.ts`).
import { createHash } from "node:crypto";
import {
  type Address,
  createSolanaRpc,
  getAddressDecoder,
  getBase64Encoder,
  type Blockhash,
  getBase64EncodedWireTransaction,
  getCompiledTransactionMessageDecoder,
  getPublicKeyFromAddress,
  getSignatureFromTransaction,
  getSolanaErrorFromTransactionError,
  getTransactionDecoder,
  isSolanaError,
  type Rpc,
  signature as asSignature,
  type SignatureBytes,
  SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE,
  SOLANA_ERROR__TRANSACTION_ERROR__UNKNOWN,
  SOLANA_ERROR__INSTRUCTION_ERROR__UNKNOWN,
  SOLANA_ERROR__RPC__TRANSPORT_HTTP_ERROR,
  type SolanaRpcApi,
  type Transaction,
  type TransactionError,
  verifySignature,
} from "@solana/kit";
import type { FinalizedOutcome, Ledger, LedgerAccount, SimulationOutcome, SubmitResult } from "./ledger.ts";
import type { BlockhashCheck, ChainReader, MessageSearch, SignatureLookup, SlotAccount } from "./reconciliation.ts";
import type { Lifetime } from "./transactions.ts";
import { isObject } from "./types.ts";
import type { DeploymentRecord } from "./deployment-record.ts";

import { isU64Decimal, type CanonicalOrigin } from "./lifetime-provenance.ts";
import { RpcRequestScheduler } from './rpc-request-scheduler.ts';

const CLOCK_SYSVAR = "SysvarC1ock11111111111111111111111111111111" as Address;
const base64Encoder = getBase64Encoder();
const decodeBase64 = (data: string): Uint8Array => new Uint8Array(base64Encoder.encode(data));
const transactionDecoder = getTransactionDecoder();
const describe = (_error: unknown): string => 'RPC evidence unavailable';

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
  /** Accepted identity to compare with the live loader accounts at startup. */
  deployment?: DeploymentRecord;
  /**
   * Settlement deadline for `submit`, in milliseconds from the moment it is called: it bounds the
   * `sendTransaction` call (itself also limited to `requestTimeoutMs`) and every status request
   * after it, including transaction/log lookup. No request extends this deadline. Default 60s:
   * Devnet finalization has been observed to exceed 30s.
   */
  confirmTimeoutMs?: number;
  pollIntervalMs?: number;
  /** Bound on every other single RPC request (reads, simulation, genesis). Default 10s. */
  requestTimeoutMs?: number;
  /** Test seam: injects an RPC client instead of creating one from `rpcUrl`. Unused in production. */
  rpc?: Rpc<SolanaRpcApi>;
  /** E2E self-imposed pacing, independent of a provider's changing limits. */
  rpcMinIntervalMs?: number;
  /** Reads alone may retry HTTP429, respecting Retry-After and the existing deadline. */
  rpcReadRetries?: number;
};

function decodeClockUnixTimestamp(data: Uint8Array): bigint {
  // Clock sysvar layout: slot:u64, epoch_start_timestamp:i64, epoch:u64, leader_schedule_epoch:u64,
  // unix_timestamp:i64 (https://docs.rs/solana-clock/latest/solana_clock/struct.Clock.html).
  if (data.length < 40) throw new Error(`RpcLedger.now: unexpected Clock sysvar length ${data.length}`);
  return new DataView(data.buffer, data.byteOffset, data.byteLength).getBigInt64(32, true);
}

/**
 * Provider credentials can occur in any path, query, userinfo, or fragment. Keep only the
 * endpoint origin; do not guess which path segments a provider uses for credentials.
 */
export function redactRpcUrl(url: string): string {
  try {
    const u = new URL(url);
    return `${u.origin}${u.pathname !== "/" || u.search || u.username || u.password || u.hash ? " (credentials redacted)" : ""}`;
  } catch {
    return "<unparseable RPC URL>";
  }
}

const validSlot = (v: unknown): v is number | bigint =>
  (typeof v === "bigint" && v >= 0n) || (typeof v === "number" && Number.isSafeInteger(v) && v >= 0);

const isIndex = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= 255;

/** Require a known SDK error variant and its payload before treating it as failure evidence. */
function validTransactionError(value: unknown): boolean {
  if (typeof value !== "string") {
    if (!isObject(value) || Object.keys(value).length !== 1) return false;
    if ("InstructionError" in value) {
      const parts = value.InstructionError;
      if (!Array.isArray(parts) || parts.length !== 2 || !isIndex(parts[0])) return false;
      const error = parts[1];
      if (typeof error !== "string" && !(isObject(error) && Object.keys(error).length === 1 && typeof error.Custom === "number" && Number.isInteger(error.Custom) && error.Custom >= 0 && error.Custom <= 0xffff_ffff)) return false;
    } else if ("DuplicateInstruction" in value) {
      if (!isIndex(value.DuplicateInstruction)) return false;
    } else {
      const detail = value.InsufficientFundsForRent ?? value.ProgramExecutionTemporarilyRestricted;
      if (!isObject(detail) || Object.keys(detail).length !== 1 || !isIndex(detail.account_index)) return false;
    }
  }
  try {
    const error = getSolanaErrorFromTransactionError(value as TransactionError);
    return !isSolanaError(error, SOLANA_ERROR__TRANSACTION_ERROR__UNKNOWN) && !isSolanaError(error, SOLANA_ERROR__INSTRUCTION_ERROR__UNKNOWN);
  } catch {
    return false;
  }
}

/** Runtime validation: SDK types do not establish that the provider returned these fields. */
function signatureLookup(response: unknown): SignatureLookup {
  const unavailable = (): SignatureLookup => ({ kind: "unavailable", detail: "malformed signature status response" });
  if (!isObject(response) || !Array.isArray(response.value) || response.value.length !== 1) return unavailable();
  const status: unknown = response.value[0];
  if (status === null) return { kind: "not-found" };
  if (!isObject(status) || !Object.hasOwn(status, "err")) return unavailable();
  const commitment = status.confirmationStatus;
  if (commitment !== "processed" && commitment !== "confirmed" && commitment !== "finalized") return unavailable();
  const slot = status.slot;
  if (!(typeof slot === "bigint" && slot >= 0n) && !(typeof slot === "number" && Number.isSafeInteger(slot) && slot >= 0)) return unavailable();
  if (status.err !== null && !validTransactionError(status.err)) return unavailable();
  return { kind: "found", slot: BigInt(slot as bigint | number), commitment, err: status.err === null ? null : JSON.stringify(status.err) };
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
  if (!Number.isFinite(deadline) || remaining <= 0) throw new RpcDeadlineExceeded();
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
  } catch (error) {
    // Retain a bounded diagnostic before callers sanitize/drop provider details. Never
    // log messages, stacks, headers, URLs, request bodies or signed transaction bytes.
    // This is evidence only: preserve the original exception and never retry a request.
    try {
      const category = error instanceof RpcDeadlineExceeded ? "deadline"
        : isSolanaError(error, SOLANA_ERROR__RPC__TRANSPORT_HTTP_ERROR) ? "http"
        : isSolanaError(error) ? "sdk" : "other";
      const code = isSolanaError(error, SOLANA_ERROR__RPC__TRANSPORT_HTTP_ERROR)
        ? error.context.statusCode : isSolanaError(error) ? error.context.__code : undefined;
      console.warn("rpc_request_failed", { category, ...(Number.isSafeInteger(code) ? { code } : {}) });
    } catch { /* Diagnostics must not change the request outcome. */ }
    throw error;
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
  private readonly deployment?: DeploymentRecord;
  private readonly scheduler:RpcRequestScheduler;

  // Plain-field assignment, not a TS constructor parameter property: this file must stay runnable
  // under Node's `--experimental-strip-types`, which does not support parameter properties.
  constructor(config: RpcLedgerConfig) {
    this.network = config.network;
    this.rpcUrl = config.rpcUrl;
    this.deployment = config.deployment;
    this.genesisHash = config.genesisHash;
    this.rpc = config.rpc ?? createSolanaRpc(config.rpcUrl);
    this.scheduler=new RpcRequestScheduler(config.rpcMinIntervalMs ?? 0,config.rpcReadRetries ?? 3);
    this.confirmTimeoutMs = config.confirmTimeoutMs ?? 60_000;
    this.pollIntervalMs = config.pollIntervalMs ?? 1_000;
    this.requestTimeoutMs = config.requestTimeoutMs ?? 10_000;
    if (!(this.confirmTimeoutMs > 0) || !(this.requestTimeoutMs > 0)) throw new Error("RpcLedger timeouts must be positive");
  }

  /** One bounded RPC request outside the settlement path. */
  private request<T>(send: (abortSignal: AbortSignal) => Promise<T>): Promise<T> {
    return this.readRequest(Date.now()+this.requestTimeoutMs,send);
  }
  private readRequest<T>(deadline:number,send:(abortSignal:AbortSignal)=>Promise<T>):Promise<T> {
    return byDeadline(deadline,signal=>this.scheduler.read(signal,send));
  }

  /**
   * Must be called and awaited once before this ledger is handed to the facilitator: rejects a
   * configured RPC endpoint whose genesis does not match the pinned deployment record.
   */
  async verifyGenesis(): Promise<void> {
    const observed = await this.request((abortSignal) => this.rpc.getGenesisHash().send({ abortSignal }));
    if (observed !== this.genesisHash) {
      throw new Error('RpcLedger genesis mismatch; endpoint and provider response details withheld');
    }
    if (this.deployment) await this.verifyLiveDeployment(this.deployment);
  }

  /** Compare one finalized bank's loader metadata and executable with the accepted record. */
  private async verifyLiveDeployment(record: DeploymentRecord): Promise<void> {
    if (record.network.caip2 !== this.network || record.network.genesisHash !== this.genesisHash) throw new Error("deployment network mismatch");
    const pin = record.deployment;
    const response = await this.request((abortSignal) => this.rpc.getMultipleAccounts([record.programId, pin.programData], {
      encoding: "base64", commitment: "finalized", minContextSlot: pin.slot,
    }).send({ abortSignal }));
    const mismatch = () => { throw new Error("live deployment differs from the accepted SAC-007 record; stop for deployment review"); };
    if (!validSlot(response?.context?.slot) || BigInt(response.context.slot) < pin.slot || response.value?.length !== 2) mismatch();
    const [program, programData] = response.value;
    if (!program || !programData || program.owner !== pin.loader || programData.owner !== pin.loader || !program.executable || programData.executable) return mismatch();
    const p = decodeBase64(program.data[0]);
    const d = decodeBase64(programData.data[0]);
    const address = getAddressDecoder();
    if (p.length !== 36 || new DataView(p.buffer, p.byteOffset).getUint32(0, true) !== 2 || address.decode(p.slice(4)) !== pin.programData) return mismatch();
    if (d.length < 45 + pin.executableSize) return mismatch();
    const view = new DataView(d.buffer, d.byteOffset);
    if (view.getUint32(0, true) !== 3 || view.getBigUint64(4, true) !== pin.slot) return mismatch();
    if (pin.upgradeAuthority === null ? d[12] !== 0 : d[12] !== 1 || address.decode(d.slice(13, 45)) !== pin.upgradeAuthority) return mismatch();
    if (createHash("sha256").update(d.slice(45, 45 + pin.executableSize)).digest("hex") !== pin.executableSha256 || d.slice(45 + pin.executableSize).some(byte => byte !== 0)) mismatch();
  }

  async now(): Promise<bigint> {
    const { value } = await this.request((abortSignal) => this.rpc.getAccountInfo(CLOCK_SYSVAR, { encoding: "base64", commitment: "finalized" }).send({ abortSignal }));
    if (!value) throw new Error("RpcLedger.now: Clock sysvar account not found");
    return decodeClockUnixTimestamp(decodeBase64(value.data[0]));
  }

  /** One non-renewing deadline for every recovery evidence phase; ordinary interfaces remain unchanged. */
  recoveryReader(deadline: number) {
    if (!Number.isFinite(deadline)) throw new RpcDeadlineExceeded();
    return {
      getSignatureStatus: (signature: string) => this.getSignatureStatus(signature, deadline, true),
      findSignaturesByMessage: (address: Address, bytes: Uint8Array) => this.findSignaturesByMessage(address, bytes, deadline),
      getAccountAtLeast: (address: Address, slot: bigint) => this.getAccountAtLeast(address, slot, deadline),
      getClockAtLeast: (slot: bigint) => this.getClockAtLeast(slot, deadline),
      verifyBlockhashOrigin: (blockhash: string, slot: bigint, genesis: string, network: string) => this.verifyBlockhashOrigin(blockhash, slot, genesis, network, deadline),
      getFinalizedBlockhashStatus: (blockhash: string, slot: bigint) => this.getFinalizedBlockhashStatus(blockhash, slot, deadline),
      isBlockhashValid: (blockhash:string) => this.isBlockhashValid(blockhash,deadline),
    };
  }

  /** Recovery-only Clock evidence. Caller supplies the deadline shared with all other phases. */
  async getClockAtLeast(minContextSlot: bigint, deadline: number): Promise<
    { kind: "ok"; commitment: "finalized"; slot: bigint; unixTimestamp: bigint } | { kind: "unavailable"; detail: string }
  > {
    try {
      if (!isU64Decimal(minContextSlot.toString()) || !Number.isFinite(deadline)) throw new Error("invalid Clock fence");
      const { context, value } = await this.readRequest(Math.min(deadline, Date.now() + this.requestTimeoutMs), abortSignal =>
        this.rpc.getAccountInfo(CLOCK_SYSVAR, { encoding: "base64", commitment: "finalized", minContextSlot }).send({ abortSignal }));
      if (!validSlot(context?.slot) || BigInt(context.slot) < minContextSlot || !value || value.executable !== false ||
          value.owner !== "Sysvar1111111111111111111111111111111111111" || !Array.isArray(value.data) || value.data[1] !== "base64") throw new Error("invalid finalized Clock account");
      const data = decodeBase64(value.data[0]);
      if (data.length !== 40 || new DataView(data.buffer, data.byteOffset).getBigUint64(0, true) !== BigInt(context.slot)) throw new Error("stale or malformed Clock");
      return { kind: "ok", commitment: "finalized", slot: BigInt(context.slot), unixTimestamp: decodeClockUnixTimestamp(data) };
    } catch { return { kind: "unavailable", detail: "finalized Clock evidence unavailable" }; }
  }

  /** A finalized blockhash and its last valid block height, for building a new transaction. */
  async latestBlockhash(): Promise<Lifetime> {
    const { context, value } = await this.request((abortSignal) => this.rpc.getLatestBlockhash({ commitment: "finalized" }).send({ abortSignal }));
    if (!validSlot(context?.slot) || !isU64Decimal(context.slot.toString()) ||
        !(typeof value.lastValidBlockHeight === "bigint" || (typeof value.lastValidBlockHeight === "number" && Number.isSafeInteger(value.lastValidBlockHeight))) ||
        !isU64Decimal(value.lastValidBlockHeight.toString())) throw new Error("malformed blockhash lifetime");
    return { blockhash: value.blockhash, lastValidBlockHeight: BigInt(value.lastValidBlockHeight), blockhashSlot: BigInt(context.slot),
      contextSlot: BigInt(context.slot), commitment: "finalized", network: this.network, genesisHash: this.genesisHash };
  }

  /** Authenticate one origin candidate; no fresh hash, slot search, validity/expiry inference or retry. */
  async verifyBlockhashOrigin(blockhash: string, candidateSlot: bigint, genesisHash: string, network: string, deadline = Date.now() + this.requestTimeoutMs): Promise<CanonicalOrigin> {
    const unavailable = (reason: "network-mismatch" | "origin-unavailable" | "lookup-unavailable"): CanonicalOrigin => ({ state: "unverified", reason });
    if (genesisHash !== this.genesisHash || network !== this.network || network !== `solana:${genesisHash.slice(0, 32)}`) return unavailable("network-mismatch");
    if (!isU64Decimal(candidateSlot.toString())) return unavailable("origin-unavailable");
    deadline = Math.min(deadline, Date.now() + this.requestTimeoutMs);
    try {
      const observed = await this.readRequest(deadline, abortSignal => this.rpc.getGenesisHash().send({ abortSignal }));
      if (observed !== this.genesisHash) return unavailable("network-mismatch");
      const block = await this.readRequest(deadline, abortSignal => this.rpc.getBlock(candidateSlot, {
        commitment: "finalized", transactionDetails: "none", rewards: false,
      }).send({ abortSignal }));
      if (!block || block.blockhash !== blockhash) return unavailable("origin-unavailable");
      return { state: "verified", blockhash, slot: candidateSlot.toString(), commitment: "finalized", network: this.network, genesisHash: this.genesisHash };
    } catch { return unavailable("lookup-unavailable"); }
  }

  async getAccount(address: Address): Promise<LedgerAccount | null> {
    const { value } = await this.request((abortSignal) => this.rpc.getAccountInfo(address, { encoding: "base64" }).send({ abortSignal }));
    if (value === null) return null;
    if (!isObject(value)) throw new Error("malformed account response");
    return { owner: value.owner, data: decodeBase64(value.data[0]), lamports: value.lamports, executable: value.executable };
  }

  async simulate(transaction: Transaction): Promise<SimulationOutcome> {
    const wire = getBase64EncodedWireTransaction(transaction);
    const { value } = await this.request((abortSignal) =>
      this.rpc.simulateTransaction(wire, { encoding: "base64", sigVerify: false, replaceRecentBlockhash: false }).send({ abortSignal }),
    );
    if (value.err === null) {
      const units = value.unitsConsumed;
      const valid = typeof units === "bigint" && units > 0n || typeof units === "number" && Number.isSafeInteger(units) && units > 0;
      return { ok: true, ...(valid ? { unitsConsumed: BigInt(units!) } : {}) };
    }
    // The pinned SDK transforms numeric InstructionError fields to bigint. A failed
    // simulation must remain a refusal, rather than throwing during error reporting.
    return { ok: false, error: JSON.stringify(value.err, (_key, v) => typeof v === "bigint" ? v.toString() : v), logs: [...(value.logs ?? [])] };
  }

  async offerBlockhashValid(blockhash: string): Promise<boolean> {
    const { context, value } = await this.request(abortSignal => this.rpc.isBlockhashValid(blockhash as Blockhash,
      { commitment:'finalized' }).send({abortSignal}));
    if (!validSlot(context?.slot) || typeof value !== 'boolean') throw Error('offer lifetime evidence unavailable');
    return value;
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
      signature = await byDeadline(Math.min(deadline, Date.now() + this.requestTimeoutMs), async (abortSignal) => {
        await this.scheduler.pace(abortSignal);
        if(abortSignal.aborted)throw new RpcDeadlineExceeded();
        return this.rpc
          .sendTransaction(wire, { encoding: "base64", skipPreflight: false, preflightCommitment: "processed", maxRetries: 0n })
          .send({ abortSignal });
      },
      );
    } catch (error) {
      this.scheduler.noteRateLimit(error); // Delay read-side observation; never retry this send.
      if (isSolanaError(error, SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE)) {
        // A preflight refusal describes this call, not the history of these signed bytes.
        // Even an execution error can follow an earlier landing at a different bank. The SDK
        // also accepts unknown/malformed error variants. Only the original signature's own
        // finalized status resolves any of these cases; never infer global non-submission.
        return { kind: "submitted", outcome: await this.pollForFinalized(expectedSignature, deadline) };
      }
      // A lost acknowledgement can follow a successful broadcast. Observe only the locally
      // derived original signature within the remaining settlement deadline. Missing status
      // stays ambiguous; an exhausted deadline performs no further requests. Never resend.
      return { kind: "submitted", outcome: await this.pollForFinalized(expectedSignature, deadline) };
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
        const response = await this.readRequest(deadline, (abortSignal) =>
          this.rpc.getSignatureStatuses([asSignature(signature)], { searchTransactionHistory: true }).send({ abortSignal }),
        );
        const status = signatureLookup(response);
        if (status.kind === "found" && status.commitment === "finalized") {
          if (status.err === null) return { status: "succeeded", commitment: "finalized" };
          return { status: "failed", commitment: "finalized", error: status.err, logs: await this.fetchFinalizedLogs(signature, deadline) };
        }
        // `null` (missing history) or a weaker commitment is missing evidence, not proof of
        // non-finality: keep polling within the bounded wait.
      } catch {
        // A transport/lookup failure or expired request is also missing evidence, not proof.
      }
      if (Date.now() >= deadline) return undefined;
      await sleep(Math.min(this.pollIntervalMs, Math.max(0, deadline - Date.now())));
    }
    // Deadline reached without a finalized status: stays ambiguous, never guessed or resent.
    return undefined;
  }

  // --- ChainReader: read-only evidence for manual reconciliation (`reconciliation.ts`). Every
  // RPC failure is reported as `unavailable`, never as absence.

  async getSignatureStatus(signature: string, deadline = Date.now() + this.requestTimeoutMs, requireObservation = false): Promise<SignatureLookup> {
    try {
      const response = await this.readRequest(Math.min(deadline, Date.now() + this.requestTimeoutMs), (abortSignal) =>
        this.rpc.getSignatureStatuses([asSignature(signature)], { searchTransactionHistory: true }).send({ abortSignal }),
      );
      const status = signatureLookup(response);
      if (!requireObservation || status.kind !== "found") return status;
      if (!validSlot(response.context?.slot) || response.context.slot < status.slot) return { kind:"unavailable",detail:"signature observation context unavailable or stale" };
      return { ...status,observedSlot:response.context.slot };
    } catch (error) {
      return { kind: "unavailable", detail: describe(error) };
    }
  }

  async findSignaturesByMessage(address: Address, messageBytes: Uint8Array, deadline = Date.now() + this.confirmTimeoutMs): Promise<MessageSearch> {
    // One deadline for the whole search, not per request: a slow RPC cannot stretch it to
    // `MESSAGE_SEARCH_LIMIT` request timeouts.
    try {
      const entries = await this.readRequest(deadline, (abortSignal) =>
        this.rpc.getSignaturesForAddress(address, { limit: MESSAGE_SEARCH_LIMIT, commitment: "confirmed" }).send({ abortSignal }),
      );
      if (!Array.isArray(entries) || entries.length > MESSAGE_SEARCH_LIMIT) {
        return { kind: "unavailable", detail: "malformed or oversized transaction history" };
      }
      for (const entry of entries) {
        const tx = await this.readRequest(deadline, (abortSignal) =>
          this.rpc.getTransaction(entry.signature, { encoding: "base64", commitment: "confirmed", maxSupportedTransactionVersion: 1 }).send({ abortSignal }),
        );
        if (!tx) return { kind: "unavailable", detail: `history for ${entry.signature} is listed but not retrievable` };
        if (!Array.isArray(tx.transaction) || tx.transaction.length !== 2 || typeof tx.transaction[0] !== "string" || tx.transaction[1] !== "base64") {
          return { kind: "unavailable", detail: "malformed transaction history wire response" };
        }
        const decoded = transactionDecoder.decode(decodeBase64(tx.transaction[0]));
        if (getSignatureFromTransaction(decoded) !== entry.signature) {
          return { kind: "unavailable", detail: "transaction history signature does not match its wire bytes" };
        }
        // The wire decoder extracts the signer prefix only. Decode the entire message before
        // filtering an unrelated entry; malformed or future-version history is not absence.
        const [message, end] = getCompiledTransactionMessageDecoder().read(decoded.messageBytes, 0);
        if (end !== decoded.messageBytes.length) {
          return { kind: "unavailable", detail: "transaction history message has trailing bytes" };
        }
        const payer = message.staticAccounts[0];
        const signature = payer && decoded.signatures[payer];
        // Authenticate the listed fee-payer signature even for nonmatches. Key import and
        // verification share the search deadline, just like the RPC requests.
        if (!payer || !signature || !(await byDeadline(deadline, async () =>
          verifySignature(await getPublicKeyFromAddress(payer), signature as SignatureBytes, decoded.messageBytes),
        ))) {
          return { kind: "unavailable", detail: "transaction history signature does not authenticate its message" };
        }
        if (sameBytes(new Uint8Array(decoded.messageBytes), messageBytes)) {
          return { kind: "ok", signatures: [entry.signature], truncated: false };
        }
      }
      return { kind: "ok", signatures: [], truncated: entries.length >= MESSAGE_SEARCH_LIMIT };
    } catch (error) {
      return { kind: "unavailable", detail: describe(error) };
    }
  }

  async isBlockhashValid(blockhash: string, deadline=Date.now()+this.requestTimeoutMs): Promise<BlockhashCheck> {
    try {
      // Latest (processed) bank: a blockhash newer than the finalized bank is still unknown
      // there and would look expired. Even processed false can mean unknown to that bank,
      // not expired; reconciliation never treats it as proof of non-execution. Keep the
      // observation slot to fence subsequent finalized account evidence.
      const { context, value } = await this.readRequest(Math.min(deadline,Date.now()+this.requestTimeoutMs),(abortSignal) =>
        this.rpc.isBlockhashValid(blockhash as Blockhash, { commitment: "processed" }).send({ abortSignal }),
      );
      if (typeof value !== "boolean" || !validSlot(context?.slot)) throw new Error("malformed blockhash response");
      return { kind: "ok", valid: value, slot: BigInt(context.slot) };
    } catch (error) {
      return { kind: "unavailable", detail: describe(error) };
    }
  }

  /** Authenticate a canonical finalized origin before treating an invalid hash as expired.
   * A bare invalid hash could be unknown/newer than the bank; this ancestor cannot become
   * valid again on the finalized chain. No wall-clock or fixed block-age assumption. */
  async getFinalizedBlockhashStatus(blockhash: string, originSlot: bigint, deadline = Date.now() + this.requestTimeoutMs): Promise<BlockhashCheck> {
    try {
      if (originSlot < 0n) throw new Error("invalid blockhash origin slot");
      const block = await this.readRequest(Math.min(deadline, Date.now() + this.requestTimeoutMs), (abortSignal) => this.rpc.getBlock(originSlot, {
        commitment: "finalized", transactionDetails: "none", rewards: false,
      }).send({ abortSignal }));
      if (!block || block.blockhash !== blockhash) throw new Error("blockhash does not match its finalized origin");
      const { context, value } = await this.readRequest(Math.min(deadline, Date.now() + this.requestTimeoutMs), (abortSignal) => this.rpc.isBlockhashValid(blockhash as Blockhash, {
        commitment: "finalized", minContextSlot: originSlot,
      }).send({ abortSignal }));
      if (typeof value !== "boolean" || !validSlot(context?.slot) || BigInt(context.slot) < originSlot) throw new Error("malformed finalized blockhash response");
      return { kind: "ok", valid: value, slot: BigInt(context.slot) };
    } catch (error) {
      return { kind: "unavailable", detail: describe(error) };
    }
  }

  async getAccountAtLeast(address: Address, minContextSlot: bigint, deadline = Date.now() + this.confirmTimeoutMs): Promise<SlotAccount> {
    // Finalization trails the latest slot by ~32 slots: wait, within the bounded window, for the
    // finalized bank to reach `minContextSlot` instead of reporting older state.
    let detail = "finalized bank did not reach the required slot";
    do {
      try {
        const { context, value } = await this.readRequest(deadline, (abortSignal) =>
          this.rpc.getAccountInfo(address, { encoding: "base64", commitment: "finalized", minContextSlot }).send({ abortSignal }),
        );
        if (!validSlot(context?.slot) || (value !== null && !isObject(value))) throw new Error("malformed account response");
        if (BigInt(context.slot) < minContextSlot) throw new Error("RPC returned an account older than minContextSlot");
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
   * Log lookup shares the original settlement deadline. An expired lookup leaves the whole
   * attempt unresolved; an ordinary diagnostic lookup failure can return empty logs while
   * retaining the original signature's independently established finalized failure.
   */
  private async fetchFinalizedLogs(signature: string, deadline: number): Promise<string[]> {
    try {
      const tx = await this.readRequest(deadline, (abortSignal) =>
        this.rpc.getTransaction(asSignature(signature), { commitment: "finalized", encoding: "json" }).send({ abortSignal }),
      );
      return [...(tx?.meta?.logMessages ?? [])];
    } catch (error) {
      if (error instanceof RpcDeadlineExceeded || Date.now() >= deadline) throw new RpcDeadlineExceeded();
      return [];
    }
  }
}
