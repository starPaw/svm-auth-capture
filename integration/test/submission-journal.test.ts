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

  test("a re-broadcast of identical bytes appends an attempt and keeps the earlier outcome", async () => {
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
    journal.prepare(base);
    const entry = journal.read("sig")!;
    expect(entry.attempts).toHaveLength(2);
    expect(entry.attempts[0]!.outcome?.result).toBe("unresolved");
    expect(entry.attempts[1]!.outcome).toBeUndefined();
  });

  test("opening a missing journal read-only fails instead of looking empty", () => {
    expect(() => new FileSubmissionJournal(join(tmpdir(), "sac006-no-such-journal-dir"), { create: false })).toThrow(/does not exist/);
  });

  test("a journal write failure prevents the broadcast", async () => {
    const failing: SubmissionJournal = {
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
