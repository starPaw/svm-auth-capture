// Durable local operation journal for the demo resource server (SAC-006 gap #3; ARCHITECTURE,
// "Relay, recovery, and separation from application state"). The facilitator's in-process
// `inFlight` duplicate guard (`facilitator.ts`) only protects one economic event across a
// concurrent identical `/settle`; it does nothing across separate requests, processes, or a
// restart, and an HTTP idempotency key carries no economic authority on its own. This store
// binds one authorization to one protected request via a caller/resource/payment fingerprint,
// reserved atomically *before* the handler runs, and persists the pre-submission facts
// (signed authorize bytes, its locally derived signature, the blockhash lifetime, and the
// expected `(H,F)` pair) before `/settle` is ever called. Handler-started and handler-result
// state is recorded separately, so a crash can never be misread as "the handler never ran."
//
// One JSON file per fingerprint, written with the exclusive `wx` flag so a concurrent duplicate
// request can never win a second reservation, and updated via write-to-temp-then-rename so a
// crash mid-write cannot corrupt a record. No new service: this is a local file store the
// resource-server process reads and writes directly. On an unresolved outcome the record stays
// in a non-terminal status; `reconcileEntry` inspects live chain state and reports what it
// found, but never resubmits, re-signs, or invents a result — only an operator decides how to
// close the entry out.
import { createHash } from "node:crypto";
import { mkdirSync, readdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Address } from "@solana/kit";
import type { Ledger } from "./ledger.js";
import { decodePayment } from "./program.js";

export type OperationStatus =
  | "reserved" // fingerprint claimed; settle(authorize) not yet attempted
  | "authorizing" // settle(authorize) in flight; pre-submission facts are recorded below
  | "authorize-rejected" // authorize failed preflight or was not submitted; the handler must never run
  | "authorize-pending" // authorize was broadcast but its outcome could not be established
  | "authorized" // authorize observed finalized-success; the handler may run
  | "handler-started" // handler invoked; its result is not yet known
  | "handler-succeeded"
  | "handler-failed"
  | "terminal-settling" // settle(capture|void) in flight for the handler's outcome
  | "terminal-pending" // the terminal settle was broadcast but its outcome could not be established
  | "completed" // the terminal settle observed a finalized result (success or classified failure)
  | "pending"; // execution stopped for explicit manual reconciliation (see `reconcileEntry`)

/**
 * Facts persisted before a `/settle` call is ever made: the exact signed bytes, their locally
 * derived signature, the blockhash the message was built against (its lifetime anchor; this
 * demo does not separately track a last-valid-block-height expiry), the payment identity, and
 * the expected `(H,F)` pair the signed instruction carries.
 */
export type PreSubmission = {
  transactionBase64: string;
  signature: string;
  blockhash: string;
  payment: string;
  expectedHeld: string;
  expectedRefundable: string;
};

export type OperationRecord = {
  fingerprint: string;
  caller: string;
  resource: string;
  createdAt: string;
  updatedAt: string;
  status: OperationStatus;
  authorize?: PreSubmission;
  handlerResult?: { ok: boolean; detail?: string };
  terminal?: PreSubmission & { op: "capture" | "void" };
  note?: string;
};

export class ReservationConflict extends Error {
  constructor(readonly fingerprint: string) {
    super(`fingerprint ${fingerprint} is already reserved`);
  }
}

/** The caller/resource/payment-identity binding this store enforces one authorization per. */
export function fingerprint(caller: string, resource: string, salt: Uint8Array): string {
  const hash = createHash("sha256");
  hash.update(caller);
  hash.update("\u0000");
  hash.update(resource);
  hash.update("\u0000");
  hash.update(salt);
  return hash.digest("hex");
}

export class OperationStore {
  constructor(private readonly dir: string) {
    mkdirSync(dir, { recursive: true });
  }

  private path(fp: string): string {
    return join(this.dir, `${fp}.json`);
  }

  /** Atomically claims a fresh fingerprint. Throws `ReservationConflict` if already reserved. */
  reserve(fp: string, caller: string, resource: string): OperationRecord {
    const now = new Date().toISOString();
    const record: OperationRecord = { fingerprint: fp, caller, resource, createdAt: now, updatedAt: now, status: "reserved" };
    try {
      writeFileSync(this.path(fp), JSON.stringify(record, null, 2), { flag: "wx" });
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "EEXIST") throw new ReservationConflict(fp);
      throw e;
    }
    return record;
  }

  read(fp: string): OperationRecord | undefined {
    try {
      return JSON.parse(readFileSync(this.path(fp), "utf8")) as OperationRecord;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw e;
    }
  }

  update(fp: string, patch: Partial<Omit<OperationRecord, "fingerprint" | "createdAt">>): OperationRecord {
    const existing = this.read(fp);
    if (!existing) throw new Error(`no reservation for fingerprint ${fp}`);
    const next: OperationRecord = { ...existing, ...patch, updatedAt: new Date().toISOString() };
    const tmp = `${this.path(fp)}.tmp-${process.pid}-${Date.now()}`;
    writeFileSync(tmp, JSON.stringify(next, null, 2));
    renameSync(tmp, this.path(fp));
    return next;
  }

  list(): OperationRecord[] {
    return readdirSync(this.dir)
      .filter((f) => f.endsWith(".json") && !f.includes(".tmp-"))
      .map((f) => JSON.parse(readFileSync(join(this.dir, f), "utf8")) as OperationRecord);
  }

  /** Every record stopped for manual reconciliation (never auto-retried). */
  pending(): OperationRecord[] {
    return this.list().filter((r) => r.status === "pending" || r.status === "authorize-pending" || r.status === "terminal-pending");
  }
}

/**
 * Inspects live chain state for a non-terminal record and reports what it finds. Never
 * resubmits, re-signs, or marks anything completed on its own — reconciliation is a read-only
 * diagnostic; an operator uses `OperationStore.update` to close the entry out only after
 * deciding what the real outcome was.
 */
export async function reconcileEntry(
  store: OperationStore,
  ledger: Ledger,
  programId: Address,
  fp: string,
): Promise<{ record: OperationRecord; onchainPayment?: { exists: boolean; held?: string; refundable?: string } }> {
  const record = store.read(fp);
  if (!record) throw new Error(`no reservation for fingerprint ${fp}`);
  if (!record.authorize) return { record };
  const account = await ledger.getAccount(record.authorize.payment as Address);
  if (!account || account.owner !== programId) return { record, onchainPayment: { exists: false } };
  const decoded = decodePayment(account.data);
  if (!decoded) return { record, onchainPayment: { exists: false } };
  return { record, onchainPayment: { exists: true, held: decoded.held.toString(), refundable: decoded.refundable.toString() } };
}
