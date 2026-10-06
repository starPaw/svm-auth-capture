// RPC-backed `Ledger` (SAC-006). Reads the cluster Clock and accounts, simulates with the
// sponsor signature absent (`sigVerify: false`, `replaceRecentBlockhash: false`), and submits
// the exact co-signed bytes once, classifying the result into the three-way outcome the
// facilitator requires (see `ledger.ts`). The program's onchain guards remain authoritative;
// this adapter never replaces a blockhash, re-signs, or retries an ambiguous submission.
import {
  type Address,
  createSolanaRpc,
  getBase64Encoder,
  getBase64EncodedWireTransaction,
  getSignatureFromTransaction,
  isSolanaError,
  type Rpc,
  signature as asSignature,
  SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE,
  type SolanaRpcApi,
  type Transaction,
} from "@solana/kit";
import type { FinalizedOutcome, Ledger, LedgerAccount, SimulationOutcome, SubmitResult } from "./ledger.js";

const CLOCK_SYSVAR = "SysvarC1ock11111111111111111111111111111111" as Address;
const base64Encoder = getBase64Encoder();
const decodeBase64 = (data: string): Uint8Array => new Uint8Array(base64Encoder.encode(data));

export type RpcLedgerConfig = {
  /** CAIP-2 identity this ledger reports; the facilitator rejects a configuration mismatch against it. */
  network: string;
  /** Full base58 genesis hash the configured RPC endpoint must observe; checked by `verifyGenesis`. */
  genesisHash: string;
  rpcUrl: string;
  /** Bounded wait for `submit` to observe a finalized result, in milliseconds. Default 30s. */
  confirmTimeoutMs?: number;
  pollIntervalMs?: number;
  /** Test seam: injects an RPC client instead of creating one from `rpcUrl`. Unused in production. */
  rpc?: Rpc<SolanaRpcApi>;
};

function decodeClockUnixTimestamp(data: Uint8Array): bigint {
  // Clock sysvar layout: slot:u64, epoch_start_timestamp:i64, epoch:u64, leader_schedule_epoch:u64,
  // unix_timestamp:i64 (https://docs.rs/solana-clock/latest/solana_clock/struct.Clock.html).
  if (data.length < 40) throw new Error(`RpcLedger.now: unexpected Clock sysvar length ${data.length}`);
  return new DataView(data.buffer, data.byteOffset, data.byteLength).getBigInt64(32, true);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class RpcLedger implements Ledger {
  readonly network: string;
  private readonly rpcUrl: string;
  private readonly genesisHash: string;
  private readonly rpc: Rpc<SolanaRpcApi>;
  private readonly confirmTimeoutMs: number;
  private readonly pollIntervalMs: number;

  // Plain-field assignment, not a TS constructor parameter property: this file must stay runnable
  // under Node's `--experimental-strip-types`, which does not support parameter properties.
  constructor(config: RpcLedgerConfig) {
    this.network = config.network;
    this.rpcUrl = config.rpcUrl;
    this.genesisHash = config.genesisHash;
    this.rpc = config.rpc ?? createSolanaRpc(config.rpcUrl);
    this.confirmTimeoutMs = config.confirmTimeoutMs ?? 30_000;
    this.pollIntervalMs = config.pollIntervalMs ?? 1_000;
  }

  /**
   * Must be called and awaited once before this ledger is handed to the facilitator: rejects a
   * configured RPC endpoint whose genesis does not match the pinned deployment record.
   */
  async verifyGenesis(): Promise<void> {
    const observed = await this.rpc.getGenesisHash().send();
    if (observed !== this.genesisHash) {
      throw new Error(`RpcLedger genesis mismatch at ${this.rpcUrl}: configured ${this.genesisHash}, observed ${observed}`);
    }
  }

  async now(): Promise<bigint> {
    const { value } = await this.rpc.getAccountInfo(CLOCK_SYSVAR, { encoding: "base64" }).send();
    if (!value) throw new Error("RpcLedger.now: Clock sysvar account not found");
    return decodeClockUnixTimestamp(decodeBase64(value.data[0]));
  }

  async getAccount(address: Address): Promise<LedgerAccount | null> {
    const { value } = await this.rpc.getAccountInfo(address, { encoding: "base64" }).send();
    if (!value) return null;
    return { owner: value.owner, data: decodeBase64(value.data[0]), lamports: value.lamports, executable: value.executable };
  }

  async simulate(transaction: Transaction): Promise<SimulationOutcome> {
    const wire = getBase64EncodedWireTransaction(transaction);
    const { value } = await this.rpc
      .simulateTransaction(wire, { encoding: "base64", sigVerify: false, replaceRecentBlockhash: false })
      .send();
    if (value.err === null) return { ok: true };
    return { ok: false, error: JSON.stringify(value.err), logs: [...(value.logs ?? [])] };
  }

  async submit(transaction: Transaction): Promise<SubmitResult> {
    const wire = getBase64EncodedWireTransaction(transaction);
    const expectedSignature = getSignatureFromTransaction(transaction);

    let signature: string;
    try {
      signature = await this.rpc
        .sendTransaction(wire, { encoding: "base64", skipPreflight: false, preflightCommitment: "processed", maxRetries: 0n })
        .send();
    } catch (error) {
      if (isSolanaError(error, SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE)) {
        // The node's own preflight simulation rejected these bytes before ever broadcasting
        // them: nothing reached the cluster, so a retry of the same bytes is fresh.
        return { kind: "not-submitted", reason: error.message };
      }
      // Any other failure (transport error, timeout, malformed response) cannot prove the exact
      // bytes were never broadcast: stay in the ambiguous `submitted` branch, never guess
      // `not-submitted`.
      return { kind: "submitted" };
    }

    if (signature !== expectedSignature) {
      // Cannot trust a status lookup for a signature the facilitator did not derive locally from
      // these exact bytes.
      return { kind: "submitted" };
    }

    return { kind: "submitted", outcome: await this.pollForFinalized(signature) };
  }

  private async pollForFinalized(signature: string): Promise<FinalizedOutcome | undefined> {
    const deadline = Date.now() + this.confirmTimeoutMs;
    while (Date.now() < deadline) {
      try {
        const { value } = await this.rpc
          .getSignatureStatuses([asSignature(signature)], { searchTransactionHistory: true })
          .send();
        const status = value[0];
        if (status && status.confirmationStatus === "finalized") {
          if (status.err === null) return { status: "succeeded", commitment: "finalized" };
          return { status: "failed", commitment: "finalized", error: JSON.stringify(status.err), logs: await this.fetchFinalizedLogs(signature) };
        }
        // `null` (missing history) or a weaker commitment is missing evidence, not proof of
        // non-finality: keep polling within the bounded wait.
      } catch {
        // A transport/lookup failure here is also missing evidence, not proof of anything.
      }
      await sleep(this.pollIntervalMs);
    }
    // Bounded wait exhausted without a finalized status: stays ambiguous, never guessed.
    return undefined;
  }

  private async fetchFinalizedLogs(signature: string): Promise<string[]> {
    try {
      const tx = await this.rpc
        .getTransaction(asSignature(signature), { commitment: "finalized", encoding: "json" })
        .send();
      return [...(tx?.meta?.logMessages ?? [])];
    } catch {
      return [];
    }
  }
}
