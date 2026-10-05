import type { Address, Transaction } from "@solana/kit";

export type LedgerAccount = {
  owner: Address;
  data: Uint8Array;
  lamports: bigint;
  executable: boolean;
};

export type SimulationOutcome = { ok: true } | { ok: false; error: string; logs: string[] };

/**
 * A submission whose exact signature reached finalized commitment, with its execution result.
 * A processed or confirmed (not yet finalized) or otherwise unknown outcome must throw instead:
 * the facilitator then reports it as pending. A send-time refusal that did not execute these
 * bytes (already processed, blockhash not found) is not this signature's result either: resolve
 * the signature's actual finalized status, or throw. v1 gates success on finalized (ARCHITECTURE).
 */
export type SubmitOutcome =
  | { status: "succeeded"; commitment: "finalized" }
  | { status: "failed"; commitment: "finalized"; error: string; logs: string[] };

/**
 * The facilitator's only view of the SVM. Reads and simulation are preflight; the program's
 * onchain guards remain authoritative. `simulate` receives bytes without the sponsor signature
 * and must simulate without signature verification and against the signed blockhash (RPC
 * `sigVerify: false`, `replaceRecentBlockhash: false`). `submit`
 * broadcasts exact signed bytes once and must throw when it cannot establish a finalized outcome.
 */
export interface Ledger {
  /** CAIP-2 identity of the connected cluster (the genesis check for an RPC-backed ledger). */
  readonly network: string;
  /** Latest cluster `Clock.unix_timestamp`; execution time onchain may be later. */
  now(): Promise<bigint>;
  getAccount(address: Address): Promise<LedgerAccount | null>;
  simulate(transaction: Transaction): Promise<SimulationOutcome>;
  submit(transaction: Transaction): Promise<SubmitOutcome>;
}
