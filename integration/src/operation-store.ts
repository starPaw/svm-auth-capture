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
// resource-server process reads and writes directly. On an unresolved outcome — including a
// crash or lost response at any intermediate status — the record stays non-terminal and is
// listed by `unresolved()`; `reconcileEntry` (`reconciliation.ts`) inspects the original
// transaction and live chain state and reports what it found, but never resubmits, re-signs,
// or invents a result — only an operator decides how to close the entry out.
//
// The sponsor's signature (which is the transaction's Solana signature) is added inside the
// facilitator, so this server-side journal holds the exact message bytes it consented to, and
// the signature only once a facilitator receipt — success, failure, or pending — reports it.
// The facilitator's own `SubmissionJournal` holds the fully co-signed bytes and signature,
// written before broadcast; both share the same message bytes.
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createDurableFile, ensureDurableDirectory, replaceDurableFile } from "./durable-file.ts";
import type { SettleResponse } from "./types.ts";

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
  | "terminal-pending" // the terminal settle may have been broadcast but its outcome could not be established
  | "terminal-rejected" // the terminal settle was refused or failed finalized; the hold remains for manual handling
  | "completed"; // the terminal settle observed a finalized success

/** Statuses that need no reconciliation: nothing is in flight and no hold is left behind by this server. */
const SETTLED_STATUSES: ReadonlySet<OperationStatus> = new Set(["authorize-rejected", "completed"]);

/**
 * Facts persisted before a `/settle` call is ever made: the exact signed bytes this server
 * consented to (message bytes identical to what the facilitator broadcasts), the blockhash the
 * message was built against (its lifetime anchor) and, when this server fetched it, its
 * last-valid block height, the payment identity, and the expected `(H,F)` pair the signed
 * instruction carries. `signature` is empty until a facilitator receipt reports it.
 */
export type PreSubmission = {
  transactionBase64: string;
  signature: string;
  blockhash: string;
  lastValidBlockHeight?: string;
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
  /** The facilitator's settle response for the authorize, including a pending or failed one. */
  authorizeReceipt?: SettleResponse;
  handlerResult?: { ok: boolean; detail?: string };
  terminal?: PreSubmission & { op: "capture" | "void" };
  terminalReceipt?: SettleResponse;
  note?: string;
};

export class ReservationConflict extends Error {
  readonly fingerprint: string;

  // Plain-field assignment, not a TS constructor parameter property: this file must stay runnable
  // under Node's `--experimental-strip-types`, which does not support parameter properties.
  constructor(fingerprint: string) {
    super(`fingerprint ${fingerprint} is already reserved`);
    this.fingerprint = fingerprint;
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
  private readonly dir: string;

  // Plain-field assignment, not a TS constructor parameter property: this file must stay runnable
  // under Node's `--experimental-strip-types`, which does not support parameter properties.
  constructor(dir: string) {
    this.dir = dir;
    ensureDurableDirectory(dir);
  }

  private path(fp: string): string {
    return join(this.dir, `${fp}.json`);
  }

  /** Atomically claims a fresh fingerprint. Throws `ReservationConflict` if already reserved. */
  reserve(fp: string, caller: string, resource: string): OperationRecord {
    const now = new Date().toISOString();
    const record: OperationRecord = { fingerprint: fp, caller, resource, createdAt: now, updatedAt: now, status: "reserved" };
    try {
      createDurableFile(this.path(fp), JSON.stringify(record, null, 2));
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
    replaceDurableFile(this.path(fp), JSON.stringify(next, null, 2));
    return next;
  }

  list(): OperationRecord[] {
    return readdirSync(this.dir)
      .filter((f) => f.endsWith(".json") && !f.includes(".tmp-"))
      .map((f) => JSON.parse(readFileSync(join(this.dir, f), "utf8")) as OperationRecord);
  }

  /**
   * Every record that is not settled: unresolved outcomes, refused terminal settles, and any
   * intermediate status a crash or lost response left behind (`reserved`, `authorizing`,
   * `handler-*`, `terminal-settling`, ...). Never auto-retried; listed for manual reconciliation.
   */
  unresolved(): OperationRecord[] {
    return this.list().filter((r) => !SETTLED_STATUSES.has(r.status));
  }
}
