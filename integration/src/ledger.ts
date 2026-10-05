import type { Address, Transaction } from "@solana/kit";

export type LedgerAccount = {
  owner: Address;
  data: Uint8Array;
  lamports: bigint;
  executable: boolean;
};

export type SimulationOutcome = { ok: true } | { ok: false; error: string; logs: string[] };

/** A submission that reached a confirmed outcome. Anything else must throw: the outcome is unknown. */
export type SubmitOutcome = { status: "succeeded" } | { status: "failed"; error: string; logs: string[] };

/**
 * The facilitator's only view of the SVM. Reads and simulation are preflight; the program's
 * onchain guards remain authoritative. `submit` broadcasts exact signed bytes once and must
 * throw when it cannot establish a confirmed outcome.
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
