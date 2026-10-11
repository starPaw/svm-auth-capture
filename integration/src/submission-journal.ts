import { assertStoreAccess, domainFromEnvironment, type RecoveryDomain } from "./coordination.ts";
// Facilitator-side durable submission journal (SAC-006 gap #3; ARCHITECTURE, "Relay, recovery,
// and separation from application state"). The facilitator is the only party that ever holds
// the fully co-signed bytes: the economic party signs first, and the sponsor signature that
// completes the transaction (and *is* its Solana signature) is added inside `/settle`. So the
// exact broadcast bytes, their signature, and their blockhash lifetime are persisted here,
// before `Ledger.submit` is called. If that write fails, nothing is broadcast.
//
// One exclusively reserved JSON file per signature; outcomes use write-temp-then-rename. `messageHash` (SHA-256 of
// the message bytes) lets an operator correlate an entry with a resource server's own journal,
// which holds the same message bytes without the sponsor signature. Existing entries prevent any new broadcast of the same message, including after restart;
// they never drive a retry.
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createDurableFile, ensureDurableDirectory, replaceDurableFile } from "./durable-file.ts";
import type { Operation } from "./types.ts";
import type { SubmitResult } from "./ledger.ts";

import type { RelayProvenance } from "./lifetime-provenance.ts";

export type SubmissionOutcome = "not-submitted" | "unresolved" | "finalized-succeeded" | "finalized-failed" | "submit-threw";

/** One classification for relay/reclaim responses and their durable outcome evidence. */
export function submissionOutcome(outcome: SubmitResult): { result: SubmissionOutcome; detail?: string } {
  if (outcome.kind === "not-submitted") return { result: "not-submitted", detail: outcome.reason };
  const r = outcome.outcome;
  if (!r || r.commitment !== "finalized") return { result: "unresolved" };
  if (r.status === "succeeded") return { result: "finalized-succeeded" };
  if (r.status === "failed") return { result: "finalized-failed", detail: r.error };
  return { result: "unresolved" };
}

export type SubmissionAttempt = { preparedAt: string; outcome?: { result: SubmissionOutcome; recordedAt: string; detail?: string } };

/** What the facilitator knows before broadcasting; the journal adds the attempt history. */
export type PreparedSubmission = {
  signature: string;
  /** SHA-256 (hex) of the exact message bytes; identical to the resource server's unsponsored copy. */
  messageHash: string;
  /** Base64 wire transaction, fully co-signed, exactly as handed to `Ledger.submit`. */
  transactionBase64: string;
  /** The message's recent blockhash: its lifetime anchor. */
  blockhash: string;
  operation: Operation | "reclaim" | "setup";
  payment: string;
  payer: string;
  expectedHeld: string;
  expectedRefundable: string;
  /** Relay evidence only; does not feed the legacy reclaim/receipt gates. */
  lifetimeProvenance?: RelayProvenance;
  /** Legacy reclaim fields; relay observations never backfill these. */
  blockhashSlot?: string;
  lastValidBlockHeight?: string;
  /** Reclaim-only proof retained on the successor; original outcome remains unmodified. */
  reclaimRecovery?: { kind: "expired-no-effect"; blockhash: string; originSlot: string; expirySlot: string; paymentSlot: string };
  /** Explicit payer continuation after finalized failure or proven expiry without reclaim effect. */
  retryAfter?: string;
};

/**
 * One reservation per signature. Legacy entries can contain multiple attempts; new entries
 * permit one attempt only. Existing outcomes, including not-submitted, require manual
 * reconciliation rather than automatic reuse.
 */
export type SubmissionEntry = PreparedSubmission & { attempts: SubmissionAttempt[] };

export interface SubmissionJournal {
  readonly coordination?: RecoveryDomain;
  assertAccess?(): void;
  findByMessageHash(hash: string): SubmissionEntry[];
  read(signature: string): SubmissionEntry | undefined;
  /** Must exclusively reserve `entry` durably before returning; a throw prevents broadcast. */
  prepare(entry: PreparedSubmission): void;
  /** Records the adapter's classification of the latest attempt; evidence only. */
  resolve(signature: string, outcome: NonNullable<SubmissionAttempt["outcome"]>): void;
}

export class SubmissionAlreadyReserved extends Error {}

export function messageHash(messageBytes: ArrayLike<number>): string {
  return createHash("sha256").update(Uint8Array.from(messageBytes)).digest("hex");
}

export class FileSubmissionJournal implements SubmissionJournal {
  readonly dir: string;
  readonly coordination?: RecoveryDomain;
  private readonly readOnly: boolean;

  // Plain-field assignment, not a TS constructor parameter property: this file must stay runnable
  // under Node's `--experimental-strip-types`, which does not support parameter properties.
  /** `create: false` opens an existing journal read-only (a mistyped path is an error, not an empty journal). */
  constructor(dir: string, options: { create?: boolean; coordination?: RecoveryDomain } = {}) {
    this.dir = dir;
    this.readOnly = options.create === false;
    this.coordination = options.coordination ?? (this.readOnly ? undefined : domainFromEnvironment());
    this.coordination?.assertMember(dir);
    if (options.create === false) {
      if (!existsSync(dir)) throw new Error(`submission journal ${dir} does not exist`);
    } else {
      ensureDurableDirectory(dir);
    }
  }

  assertAccess(): void { if (this.readOnly) throw new Error("read-only journal cannot be a writer"); assertStoreAccess(this.dir, this.coordination); }

  private path(signature: string): string {
    return join(this.dir, `${signature}.json`);
  }

  private write(entry: SubmissionEntry): void {
    replaceDurableFile(this.path(entry.signature), JSON.stringify(entry, null, 2));
  }

  prepare(entry: PreparedSubmission): void {
    if (this.readOnly) throw new Error("read-only submission journal");
    assertStoreAccess(this.dir, this.coordination);
    // Refuse reused signatures before creating a successor: an identical or older reclaim
    // must not add a cycle that would block a later continuation with fresh signed bytes.
    if (existsSync(this.path(entry.signature))) throw new SubmissionAlreadyReserved("original submission requires reconciliation; never rebroadcast");
    if (entry.operation === "reclaim") this.reserveReclaim(entry);
    try {
      createDurableFile(this.path(entry.signature), JSON.stringify({ ...entry, attempts: [{ preparedAt: new Date().toISOString() }] }, null, 2));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") throw new SubmissionAlreadyReserved("original submission requires reconciliation; never rebroadcast");
      throw error;
    }
  }

  private reserveReclaim(entry: PreparedSubmission): void {
    // Reclaim reservations form an append-only chain. An explicit continuation after proven
    // failure or proven expiry without effect reserves one successor exclusively;
    // old locks/evidence are never deleted.
    const root = join(this.dir, `reclaim-${entry.payment}.lock`);
    let lock = root;
    if (entry.retryAfter !== undefined) {
      const previous = this.read(entry.retryAfter);
      if (!previous || previous.operation !== "reclaim" || previous.payment !== entry.payment || previous.payer !== entry.payer ||
          (previous.attempts.at(-1)?.outcome?.result !== "finalized-failed" && !this.expiredReclaimProof(entry, previous))) {
        throw new SubmissionAlreadyReserved("reclaim continuation requires finalized failure or expiry without effect");
      }
      let current = readFileSync(root, "utf8");
      const seen = new Set<string>();
      for (;;) {
        if (seen.has(current)) throw new Error("invalid reclaim reservation chain");
        seen.add(current);
        const successor = this.reclaimSuccessor(entry.payment, current);
        if (!existsSync(successor)) break;
        current = readFileSync(successor, "utf8");
      }
      if (current !== entry.retryAfter) throw new SubmissionAlreadyReserved(`reclaim requires reconciliation of original signature ${current}`);
      lock = this.reclaimSuccessor(entry.payment, entry.retryAfter);
    }
    try {
      createDurableFile(lock, entry.signature);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") throw new SubmissionAlreadyReserved(`reclaim requires reconciliation of original signature ${readFileSync(lock, "utf8")}`);
      throw error;
    }
  }

  private expiredReclaimProof(entry: PreparedSubmission, previous: SubmissionEntry): boolean {
    const proof = entry.reclaimRecovery;
    if (!proof || previous.attempts.at(-1)?.outcome?.result === "finalized-succeeded" ||
        proof.kind !== "expired-no-effect" || proof.blockhash !== previous.blockhash ||
        entry.expectedHeld !== previous.expectedHeld || entry.expectedRefundable !== previous.expectedRefundable ||
        !/^[1-9][0-9]*$/.test(entry.expectedHeld) ||
        ![proof.originSlot, proof.expirySlot, proof.paymentSlot].every(s => /^(0|[1-9][0-9]*)$/.test(s))) return false;
    return BigInt(proof.expirySlot) > BigInt(proof.originSlot) && BigInt(proof.paymentSlot) >= BigInt(proof.expirySlot);
  }

  private reclaimSuccessor(payment: string, signature: string): string {
    return join(this.dir, `reclaim-${payment}-after-${signature}.lock`);
  }

  resolve(signature: string, outcome: NonNullable<SubmissionAttempt["outcome"]>): void {
    if (this.readOnly) throw new Error("read-only submission journal");
    assertStoreAccess(this.dir, this.coordination);
    const existing = this.read(signature);
    const last = existing?.attempts.at(-1);
    if (!existing || !last) throw new Error(`no prepared submission for ${signature}`);
    this.write({ ...existing, attempts: [...existing.attempts.slice(0, -1), { ...last, outcome }] });
  }

  read(signature: string): SubmissionEntry | undefined {
    if (!this.readOnly) assertStoreAccess(this.dir, this.coordination);
    try {
      return JSON.parse(readFileSync(this.path(signature), "utf8")) as SubmissionEntry;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw e;
    }
  }

  list(): SubmissionEntry[] {
    if (!this.readOnly) assertStoreAccess(this.dir, this.coordination);
    return readdirSync(this.dir)
      .filter((f) => f.endsWith(".json") && !f.includes(".tmp-"))
      .map((f) => JSON.parse(readFileSync(join(this.dir, f), "utf8")) as SubmissionEntry);
  }

  /** The entries whose message bytes hash to `hash` (at most one signature per message). */
  findByMessageHash(hash: string): SubmissionEntry[] {
    return this.list().filter((e) => e.messageHash === hash);
  }
}
