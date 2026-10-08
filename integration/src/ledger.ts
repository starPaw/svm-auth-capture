import type { Address, Transaction } from "@solana/kit";

export type LedgerAccount = {
  owner: Address;
  data: Uint8Array;
  lamports: bigint;
  executable: boolean;
};

export type SimulationOutcome = { ok: true; unitsConsumed?: bigint } | { ok: false; error: string; logs: string[] };

/**
 * A submission whose exact signature reached finalized commitment, with its execution result.
 */
export type FinalizedOutcome =
  | { status: "succeeded"; commitment: "finalized" }
  | { status: "failed"; commitment: "finalized"; error: string; logs: string[] };

/**
 * The three-way submission outcome the facilitator must be able to tell apart:
 *
 * - `not-submitted`: the adapter established these exact bytes were never broadcast (a
 *   send-time refusal before anything landed). The facilitator reports a non-pending failure
 *   with an empty `transaction`; a later retry of the same bytes is safe to consider fresh.
 * - `submitted` without a finalized outcome: the bytes reached the cluster, but their
 *   confirmation could not be established (response lost, processed/confirmed only, an
 *   already-processed refusal whose recorded status is unresolved). The facilitator reports
 *   `settlement_pending` with the broadcast signature; it must never be reclassified as
 *   not-submitted, because an earlier broadcast may have landed.
 * - `submitted` with a finalized outcome: the exact signature's execution result.
 *
 * A processed or confirmed (not yet finalized) result must never be labeled finalized: v1
 * gates success on finalized (ARCHITECTURE). An ordinary transport timeout, a missing RPC
 * acknowledgement, or `AlreadyProcessed` must stay in the `submitted` branch, never
 * `not-submitted`.
 */
export type SubmitResult =
  | { kind: "not-submitted"; reason: string }
  | { kind: "submitted"; outcome?: FinalizedOutcome };

/**
 * The facilitator's only view of the SVM. Reads and simulation are preflight; the program's
 * onchain guards remain authoritative. `simulate` receives bytes without the sponsor signature
 * and must simulate without signature verification and against the signed blockhash (RPC
 * `sigVerify: false`, `replaceRecentBlockhash: false`). `submit` broadcasts exact signed bytes
 * once and reports which of the three submission outcomes above it could establish.
 */
export interface Ledger {
  /** CAIP-2 identity of the connected cluster (the genesis check for an RPC-backed ledger). */
  readonly network: string;
  /** Latest cluster `Clock.unix_timestamp`; execution time onchain may be later. */
  now(): Promise<bigint>;
  getAccount(address: Address): Promise<LedgerAccount | null>;
  simulate(transaction: Transaction): Promise<SimulationOutcome>;
  submit(transaction: Transaction): Promise<SubmitResult>;
}
