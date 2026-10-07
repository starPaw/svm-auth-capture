import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, expect, test } from "vitest";
import { submitReclaim } from "../src/reclaim.ts";
import { FileSubmissionJournal } from "../src/submission-journal.ts";
import { authorizePayload } from "../src/transactions.ts";
import { createHarness, type Harness } from "./fixture.ts";
import type { Address } from "@solana/kit";

let h: Harness;
beforeAll(async () => { h = await createHarness(); });
afterAll(async () => { await h.close(); });

test("payer reclaim records exact bytes before submission and refuses a fresh-blockhash retry", async () => {
  const response = await h.facilitator.settle(h.body(authorizePayload(await h.signedAuthorize({ salt: h.newSalt() }))));
  expect(response.success).toBe(true);
  const payment = (response.extensions!["auth-capture"] as { payment: Address }).payment;
  const dir = mkdtempSync(join(tmpdir(), "sac006-reclaim-journal-"));
  const journal = new FileSubmissionJournal(dir);
  const submit = h.ledger.submit;
  let calls = 0;
  h.ledger.submit = async () => {
    calls += 1;
    expect(journal.list()).toHaveLength(1);
    expect(journal.list()[0]).toMatchObject({ operation: "reclaim", payment, expectedHeld: "100", expectedRefundable: "0" });
    return { kind: "submitted" };
  };
  try {
    const args = { ledger: h.ledger, programId: h.facilitator.programId, payer: h.payer, payment, lifetime: h.lifetime(), journal };
    const first = await submitReclaim(args);
    expect(first.result).toEqual({ kind: "submitted" });
    h.svm.expireBlockhash();
    await expect(submitReclaim({ ...args, lifetime: h.lifetime(), journal: new FileSubmissionJournal(dir) })).rejects.toThrow(/reconciliation/);
    expect(calls).toBe(1);
    expect(journal.read(first.signature)?.transactionBase64).toBeTruthy();
  } finally { h.ledger.submit = submit; }
});
