// Facilitator-side durable submission journal (SAC-006 gap #3; ARCHITECTURE, "Relay, recovery,
// and separation from application state"). The facilitator is the only party that ever holds
// the fully co-signed bytes: the economic party signs first, and the sponsor signature that
// completes the transaction (and *is* its Solana signature) is added inside `/settle`. So the
// exact broadcast bytes, their signature, and their blockhash lifetime are persisted here,
// before `Ledger.submit` is called. If that write fails, nothing is broadcast.
//
// One JSON file per signature, written via write-to-temp-then-rename. `messageHash` (SHA-256 of
// the message bytes) lets an operator correlate an entry with a resource server's own journal,
// which holds the same message bytes without the sponsor signature. This journal never drives a
// retry: it is evidence for manual reconciliation only.
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Operation } from "./types.ts";

export type SubmissionOutcome = "not-submitted" | "unresolved" | "finalized-succeeded" | "finalized-failed" | "submit-threw";

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
  operation: Operation;
  payment: string;
  payer: string;
  expectedHeld: string;
  expectedRefundable: string;
};

/**
 * One file per signature. Identical bytes always carry the same signature, so a later
 * re-broadcast of the same bytes (for example after a `not-submitted` refusal, or by another
 * facilitator process) appends an attempt instead of erasing the earlier one's evidence.
 */
export type SubmissionEntry = PreparedSubmission & { attempts: SubmissionAttempt[] };

export interface SubmissionJournal {
  /** Must durably persist a new attempt for `entry` before returning; a throw prevents the broadcast. */
  prepare(entry: PreparedSubmission): void;
  /** Records the adapter's classification of the latest attempt; evidence only. */
  resolve(signature: string, outcome: NonNullable<SubmissionAttempt["outcome"]>): void;
}

export function messageHash(messageBytes: ArrayLike<number>): string {
  return createHash("sha256").update(Uint8Array.from(messageBytes)).digest("hex");
}

export class FileSubmissionJournal implements SubmissionJournal {
  private readonly dir: string;

  // Plain-field assignment, not a TS constructor parameter property: this file must stay runnable
  // under Node's `--experimental-strip-types`, which does not support parameter properties.
  /** `create: false` opens an existing journal read-only (a mistyped path is an error, not an empty journal). */
  constructor(dir: string, options: { create?: boolean } = {}) {
    this.dir = dir;
    if (options.create === false) {
      if (!existsSync(dir)) throw new Error(`submission journal ${dir} does not exist`);
    } else {
      mkdirSync(dir, { recursive: true });
    }
  }

  private path(signature: string): string {
    return join(this.dir, `${signature}.json`);
  }

  private write(entry: SubmissionEntry): void {
    const tmp = `${this.path(entry.signature)}.tmp-${process.pid}-${Date.now()}`;
    writeFileSync(tmp, JSON.stringify(entry, null, 2));
    renameSync(tmp, this.path(entry.signature));
  }

  prepare(entry: PreparedSubmission): void {
    const previous = this.read(entry.signature)?.attempts ?? [];
    this.write({ ...entry, attempts: [...previous, { preparedAt: new Date().toISOString() }] });
  }

  resolve(signature: string, outcome: NonNullable<SubmissionAttempt["outcome"]>): void {
    const existing = this.read(signature);
    const last = existing?.attempts.at(-1);
    if (!existing || !last) throw new Error(`no prepared submission for ${signature}`);
    this.write({ ...existing, attempts: [...existing.attempts.slice(0, -1), { ...last, outcome }] });
  }

  read(signature: string): SubmissionEntry | undefined {
    try {
      return JSON.parse(readFileSync(this.path(signature), "utf8")) as SubmissionEntry;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw e;
    }
  }

  list(): SubmissionEntry[] {
    return readdirSync(this.dir)
      .filter((f) => f.endsWith(".json") && !f.includes(".tmp-"))
      .map((f) => JSON.parse(readFileSync(join(this.dir, f), "utf8")) as SubmissionEntry);
  }

  /** The entries whose message bytes hash to `hash` (at most one signature per message). */
  findByMessageHash(hash: string): SubmissionEntry[] {
    return this.list().filter((e) => e.messageHash === hash);
  }
}
