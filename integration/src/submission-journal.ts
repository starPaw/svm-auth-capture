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
  operation: Operation | "reclaim" | "setup";
  payment: string;
  payer: string;
  expectedHeld: string;
  expectedRefundable: string;
};

/**
 * One reservation per signature. Legacy entries can contain multiple attempts; new entries
 * permit one attempt only. Existing outcomes, including not-submitted, require manual
 * reconciliation rather than automatic reuse.
 */
export type SubmissionEntry = PreparedSubmission & { attempts: SubmissionAttempt[] };

export interface SubmissionJournal {
  findByMessageHash(hash: string): SubmissionEntry[];
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
  private readonly dir: string;

  // Plain-field assignment, not a TS constructor parameter property: this file must stay runnable
  // under Node's `--experimental-strip-types`, which does not support parameter properties.
  /** `create: false` opens an existing journal read-only (a mistyped path is an error, not an empty journal). */
  constructor(dir: string, options: { create?: boolean } = {}) {
    this.dir = dir;
    if (options.create === false) {
      if (!existsSync(dir)) throw new Error(`submission journal ${dir} does not exist`);
    } else {
      ensureDurableDirectory(dir);
    }
  }

  private path(signature: string): string {
    return join(this.dir, `${signature}.json`);
  }

  private write(entry: SubmissionEntry): void {
    replaceDurableFile(this.path(entry.signature), JSON.stringify(entry, null, 2));
  }

  prepare(entry: PreparedSubmission): void {
    try {
      createDurableFile(this.path(entry.signature), JSON.stringify({ ...entry, attempts: [{ preparedAt: new Date().toISOString() }] }, null, 2));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") throw new SubmissionAlreadyReserved("original submission requires reconciliation; never rebroadcast");
      throw error;
    }
    // Reclaim is a single payer action per payment. A second CLI invocation with a new
    // blockhash must not hide an unresolved original, even across concurrent processes.
    if (entry.operation === "reclaim") {
      const lock = join(this.dir, `reclaim-${entry.payment}.lock`);
      try {
        createDurableFile(lock, entry.signature);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EEXIST") throw new SubmissionAlreadyReserved(`reclaim requires reconciliation of original signature ${readFileSync(lock, "utf8")}`);
        throw error;
      }
    }
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
