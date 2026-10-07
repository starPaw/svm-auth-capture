// Tests for the facilitator's pre-broadcast submission journal (SAC-006 gap #3) against the
// LiteSVM-backed harness: the exact co-signed bytes, signature, and blockhash are durable before
// `Ledger.submit` runs; a journal write failure prevents the broadcast; and the adapter's
// classification is recorded afterwards as evidence.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getBase64EncodedWireTransaction, getCompiledTransactionMessageDecoder, getTransactionDecoder } from "@solana/kit";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { Facilitator } from "../src/facilitator.js";
import { FileSubmissionJournal, messageHash, type SubmissionEntry, type SubmissionJournal } from "../src/submission-journal.js";
import { authorizePayload } from "../src/transactions.js";
import { createHarness, type Harness } from "./fixture.js";

let h: Harness;

beforeAll(async () => {
  h = await createHarness();
});

afterAll(async () => {
  h.ledger.beforeSubmit = undefined;
  await h.close();
});

const facilitatorWith = (journal: SubmissionJournal) =>
  new Facilitator({ network: h.ledger.network, programId: h.facilitator.programId, feePayer: h.facilitatorKey, ledger: h.ledger, journal });

describe("FileSubmissionJournal through Facilitator.settle", () => {
  test("restart never resubmits an unresolved original, even while state still permits it", async () => {
    const dir = mkdtempSync(join(tmpdir(), "sac006-restart-"));
    const submit = h.ledger.submit;
    let broadcasts = 0;
    h.ledger.submit = async () => { broadcasts += 1; return { kind: "submitted" }; };
    try {
      const body = h.body(authorizePayload(await h.signedAuthorize({ salt: h.newSalt() })));
      const first = await facilitatorWith(new FileSubmissionJournal(dir)).settle(body);
      const second = await facilitatorWith(new FileSubmissionJournal(dir)).settle(body);
      expect(first.errorReason).toBe("settlement_pending");
      expect(second).toMatchObject({ success: false, errorReason: "settlement_pending", transaction: first.transaction });
      expect(broadcasts).toBe(1);
    } finally { h.ledger.submit = submit; }
  });

  test("separate facilitators atomically reserve one broadcast", async () => {
    const dir = mkdtempSync(join(tmpdir(), "sac006-concurrent-journal-"));
    const submit = h.ledger.submit;
    let broadcasts = 0;
    h.ledger.submit = async () => { broadcasts += 1; return { kind: "submitted" }; };
    try {
      const body = h.body(authorizePayload(await h.signedAuthorize({ salt: h.newSalt() })));
      const results = await Promise.all([facilitatorWith(new FileSubmissionJournal(dir)).settle(body), facilitatorWith(new FileSubmissionJournal(dir)).settle(body)]);
      expect(results.every(r => !r.success)).toBe(true);
      expect(broadcasts).toBe(1);
      expect(new FileSubmissionJournal(dir).list()[0]!.attempts).toHaveLength(1);
    } finally { h.ledger.submit = submit; }
  });

  test("persists the exact co-signed bytes, signature, and blockhash before broadcasting", async () => {
    const journal = new FileSubmissionJournal(mkdtempSync(join(tmpdir(), "sac006-journal-")));
    let atSubmit: SubmissionEntry[] = [];
    h.ledger.beforeSubmit = () => {
      atSubmit = journal.list();
    };
    const unsigned = await h.signedAuthorize({ salt: h.newSalt() });
    const res = await facilitatorWith(journal).settle(h.body(authorizePayload(unsigned)));
    h.ledger.beforeSubmit = undefined;
    expect(res.success).toBe(true);

    expect(atSubmit).toHaveLength(1);
    const prepared = atSubmit[0]!;
    expect(prepared.signature).toBe(res.transaction);
    expect(prepared.attempts).toHaveLength(1);
    expect(prepared.attempts[0]!.outcome).toBeUndefined();
    const broadcast = h.ledger.submissions.at(-1)!.transaction;
    expect(prepared.transactionBase64).toBe(getBase64EncodedWireTransaction(broadcast));
    expect(Object.values(getTransactionDecoder().decode(Buffer.from(prepared.transactionBase64, "base64")).signatures).every((s) => s !== null)).toBe(true);
    expect(prepared.messageHash).toBe(messageHash(unsigned.messageBytes));
    expect(prepared.blockhash).toBe(getCompiledTransactionMessageDecoder().decode(unsigned.messageBytes).lifetimeToken);
    expect(prepared).toMatchObject({ operation: "authorize", payer: h.payer.address, expectedHeld: "0", expectedRefundable: "0" });

    expect(journal.read(res.transaction)!.attempts[0]!.outcome?.result).toBe("finalized-succeeded");
    expect(journal.findByMessageHash(prepared.messageHash).map((e) => e.signature)).toEqual([res.transaction]);
  });

  test("records an unresolved outcome for a broadcast whose finality is not established", async () => {
    const journal = new FileSubmissionJournal(mkdtempSync(join(tmpdir(), "sac006-journal-")));
    h.ledger.commitment = "confirmed";
    try {
      const res = await facilitatorWith(journal).settle(h.body(authorizePayload(await h.signedAuthorize({ salt: h.newSalt() }))));
      expect(res.errorReason).toBe("settlement_pending");
      expect(journal.read(res.transaction)!.attempts[0]!.outcome?.result).toBe("unresolved");
    } finally {
      h.ledger.commitment = "finalized";
    }
  });

  test("identical bytes cannot overwrite or append to the original unresolved reservation", async () => {
    const journal = new FileSubmissionJournal(mkdtempSync(join(tmpdir(), "sac006-journal-")));
    const base = {
      signature: "sig",
      messageHash: "hash",
      transactionBase64: "tx",
      blockhash: "bh",
      operation: "authorize" as const,
      payment: "p",
      payer: "payer",
      expectedHeld: "0",
      expectedRefundable: "0",
    };
    journal.prepare(base);
    journal.resolve("sig", { result: "unresolved", recordedAt: "t1" });
    expect(() => journal.prepare(base)).toThrow(/reconciliation/);
    const entry = journal.read("sig")!;
    expect(entry.attempts).toHaveLength(1);
    expect(entry.attempts[0]!.outcome?.result).toBe("unresolved");

  });

  test("opening a missing journal read-only fails instead of looking empty", () => {
    expect(() => new FileSubmissionJournal(join(tmpdir(), "sac006-no-such-journal-dir"), { create: false })).toThrow(/does not exist/);
  });

  test("reclaim continuation cannot reuse an old approval once a successor is reserved", () => {
    const dir = mkdtempSync(join(tmpdir(), "sac006-reclaim-successor-"));
    const journal = new FileSubmissionJournal(dir);
    const entry = { signature: "first", messageHash: "hash", transactionBase64: "tx", blockhash: "bh", operation: "reclaim" as const, payment: "payment", payer: "payer", expectedHeld: "100", expectedRefundable: "0" };
    journal.prepare(entry);
    journal.resolve("first", { result: "finalized-failed", recordedAt: "t1" });
    journal.prepare({ ...entry, signature: "second", retryAfter: "first" });
    expect(() => new FileSubmissionJournal(dir).prepare({ ...entry, signature: "third", retryAfter: "first" })).toThrow(/second/);
    expect(journal.read("third")).toBeUndefined();
    expect(journal.read("first")?.attempts[0]?.outcome?.result).toBe("finalized-failed");
    expect(journal.read("second")?.retryAfter).toBe("first");
  });

  test("refused reuse of any reclaim signature leaves a fresh continuation usable", () => {
    const journal = new FileSubmissionJournal(mkdtempSync(join(tmpdir(), "sac006-reclaim-reused-signature-")));
    const entry = { signature: "first", messageHash: "hash", transactionBase64: "tx", blockhash: "bh", operation: "reclaim" as const, payment: "payment", payer: "payer", expectedHeld: "100", expectedRefundable: "0" };
    journal.prepare(entry);
    journal.resolve("first", { result: "finalized-failed", recordedAt: "t1" });
    expect(() => journal.prepare({ ...entry, retryAfter: "first" })).toThrow(/reconciliation/);
    journal.prepare({ ...entry, signature: "second", retryAfter: "first" });
    journal.resolve("second", { result: "finalized-failed", recordedAt: "t2" });
    expect(() => journal.prepare({ ...entry, retryAfter: "second" })).toThrow(/reconciliation/);
    journal.prepare({ ...entry, signature: "third", retryAfter: "second" });
    expect(journal.read("second")?.retryAfter).toBe("first");
    expect(journal.read("third")?.retryAfter).toBe("second");
    expect(journal.read("first")?.attempts[0]?.outcome?.result).toBe("finalized-failed");
  });

  test("a journal write failure prevents the broadcast", async () => {
    const failing: SubmissionJournal = {
      findByMessageHash: () => [],
      read: () => undefined,
      prepare: () => {
        throw new Error("disk full");
      },
      resolve: () => {},
    };
    const before = h.ledger.submissions.length;
    const res = await facilitatorWith(failing).settle(h.body(authorizePayload(await h.signedAuthorize({ salt: h.newSalt() }))));
    expect(res).toMatchObject({ success: false, errorReason: "settlement_not_submitted", transaction: "" });
    expect(h.ledger.submissions.length).toBe(before);
  });
});

test("expiry successor is exclusive while unresolved and cannot erase or reuse original approval", () => {
  const dir = mkdtempSync(join(tmpdir(), "sac006-expiry-successor-"));
  const journal = new FileSubmissionJournal(dir);
  const original = { signature: "old", messageHash: "hash", transactionBase64: "tx", blockhash: "bh", operation: "reclaim" as const, payment: "payment", payer: "payer", expectedHeld: "10", expectedRefundable: "0" };
  journal.prepare(original);
  journal.resolve("old", { result: "unresolved", recordedAt: "t1" });
  const old = journal.read("old");
  const successor = { ...original, signature: "new", retryAfter: "old", reclaimRecovery: { kind: "expired-no-effect" as const, blockhash: "bh", originSlot: "10", expirySlot: "200", paymentSlot: "201" } };
  journal.prepare(successor);
  journal.resolve("new", { result: "unresolved", recordedAt: "t2" });
  expect(() => new FileSubmissionJournal(dir).prepare({ ...successor, signature: "third" })).toThrow(/new/);
  expect(journal.read("old")).toEqual(old);
  expect(journal.read("third")).toBeUndefined();
});

test.each(["zero-held", "stale-snapshot", "invalid-origin", "wrong-blockhash", "changed-pair", "recorded-success"])("journal refuses invalid expiry recovery proof: %s", mode => {
  const journal = new FileSubmissionJournal(mkdtempSync(join(tmpdir(), "sac006-expiry-proof-")));
  const original = { signature: "old", messageHash: "hash", transactionBase64: "tx", blockhash: "bh", operation: "reclaim" as const, payment: "payment", payer: "payer", expectedHeld: "10", expectedRefundable: "0" };
  journal.prepare(original);
  journal.resolve("old", { result: mode === "recorded-success" ? "finalized-succeeded" : "unresolved", recordedAt: "t1" });
  const successor = { ...original, signature: "new", retryAfter: "old", reclaimRecovery: { kind: "expired-no-effect" as const, blockhash: mode === "wrong-blockhash" ? "other" : "bh", originSlot: mode === "invalid-origin" ? "200" : "10", expirySlot: "200", paymentSlot: mode === "stale-snapshot" ? "199" : "201" } };
  if (mode === "zero-held") successor.expectedHeld = "0";
  if (mode === "changed-pair") successor.expectedRefundable = "1";
  expect(() => journal.prepare(successor)).toThrow(/finalized failure or expiry/);
  expect(journal.read("new")).toBeUndefined();
});
