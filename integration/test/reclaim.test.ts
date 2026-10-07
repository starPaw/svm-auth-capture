import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, expect, test } from "vitest";
import { submitReclaim } from "../src/reclaim.ts";
import { FileSubmissionJournal } from "../src/submission-journal.ts";
import { authorizePayload } from "../src/transactions.ts";
import { createHarness, DC, NOW, type Harness } from "./fixture.ts";
import type { SignatureLookup } from "../src/reconciliation.ts";
import type { Address } from "@solana/kit";

let h: Harness;
beforeAll(async () => { h = await createHarness(); });
afterAll(async () => { await h.close(); });
afterEach(() => { h.setTime(NOW); h.ledger.beforeSubmit = undefined; });

const argsFor = (payment: Address, journal: FileSubmissionJournal) => ({
  ledger: h.ledger, programId: h.facilitator.programId, payer: h.payer, payment, lifetime: h.lifetime(), journal,
});

test("payer reclaim records exact bytes before submission and refuses a fresh-blockhash retry", async () => {
  const response = await h.facilitator.settle(h.body(authorizePayload(await h.signedAuthorize({ salt: h.newSalt() }))));
  expect(response.success).toBe(true);
  const payment = (response.extensions!["auth-capture"] as { payment: Address }).payment;
  h.setTime(DC);
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
    expect(journal.read(first.signature)?.attempts[0]?.outcome?.result).toBe("unresolved");
  } finally { h.ledger.submit = submit; }
});

test("an early reclaim leaves no reservation and can run at Dc", async () => {
  const payment = await h.authorized();
  const journal = new FileSubmissionJournal(mkdtempSync(join(tmpdir(), "sac006-early-reclaim-")));
  const before = h.ledger.submissions.length;
  await expect(submitReclaim(argsFor(payment, journal))).rejects.toThrow(/captureDeadline/);
  expect(journal.list()).toHaveLength(0);
  expect(h.ledger.submissions).toHaveLength(before);
  h.setTime(DC);
  const reclaimed = await submitReclaim(argsFor(payment, journal));
  expect(reclaimed.result).toMatchObject({ kind: "submitted", outcome: { status: "succeeded", commitment: "finalized" } });
  expect(journal.read(reclaimed.signature)?.attempts[0]?.outcome?.result).toBe("finalized-succeeded");
  expect(h.state(payment).held).toBe(0n);
});

test("explicit continuation after finalized failure preserves the original and reclaims once", async () => {
  const payment = await h.authorized();
  const dir = mkdtempSync(join(tmpdir(), "sac006-failed-reclaim-"));
  const journal = new FileSubmissionJournal(dir);
  h.setTime(DC);
  // Preflight succeeds, then a controlled Clock change makes actual SBF execution fail.
  h.ledger.beforeSubmit = () => { h.setTime(NOW); };
  const failed = await submitReclaim(argsFor(payment, journal));
  expect(failed.result).toMatchObject({ kind: "submitted", outcome: { status: "failed", commitment: "finalized" } });
  expect(journal.read(failed.signature)?.attempts[0]?.outcome?.result).toBe("finalized-failed");
  h.ledger.beforeSubmit = undefined;
  h.setTime(DC);
  h.svm.expireBlockhash();
  const before = h.ledger.submissions.length;
  await expect(submitReclaim(argsFor(payment, new FileSubmissionJournal(dir)))).rejects.toThrow(/reconciliation/);
  const reader = { getSignatureStatus: async (): Promise<SignatureLookup> => ({ kind: "found", slot: 1n, commitment: "finalized", err: "controlled failed reclaim" }) };
  const args = { ...argsFor(payment, new FileSubmissionJournal(dir)), retryAfter: failed.signature, reader };
  // Two independent command invocations may authorize at most one successor.
  const results = await Promise.allSettled([submitReclaim(args), submitReclaim({ ...args, journal: new FileSubmissionJournal(dir) })]);
  expect(results.filter(r => r.status === "fulfilled")).toHaveLength(1);
  const success = results.find(r => r.status === "fulfilled")!;
  if (success.status !== "fulfilled") throw new Error("expected a completed reclaim");
  expect(success.value.result).toMatchObject({ kind: "submitted", outcome: { status: "succeeded", commitment: "finalized" } });
  expect(h.ledger.submissions).toHaveLength(before + 1);
  expect(h.state(payment).held).toBe(0n);
  expect(journal.read(failed.signature)?.transactionBase64).toBeTruthy();
  expect(journal.read(success.value.signature)?.retryAfter).toBe(failed.signature);
  expect(journal.read(success.value.signature)?.attempts[0]?.outcome?.result).toBe("finalized-succeeded");
});

test.each<SignatureLookup>([
  { kind: "unavailable", detail: "429" },
  { kind: "not-found" },
  { kind: "found", slot: 1n, commitment: "confirmed", err: "failed" },
  { kind: "found", slot: 1n, commitment: "finalized", err: null },
  { kind: "found", slot: 1n, commitment: "finalized", err: "" },
])("explicit reclaim continuation stays blocked without finalized failure: case %#", async (status) => {
  const payment = await h.authorized();
  const journal = new FileSubmissionJournal(mkdtempSync(join(tmpdir(), "sac006-pending-reclaim-")));
  h.setTime(DC);
  const submit = h.ledger.submit;
  h.ledger.submit = async () => ({ kind: "submitted" });
  let pending;
  try { pending = await submitReclaim(argsFor(payment, journal)); } finally { h.ledger.submit = submit; }
  const before = h.ledger.submissions.length;
  await expect(submitReclaim({ ...argsFor(payment, journal), retryAfter: pending.signature, reader: { getSignatureStatus: async () => status } })).rejects.toThrow(/not proved finalized-failed/);
  expect(h.ledger.submissions).toHaveLength(before);
  expect(journal.read(pending.signature)?.attempts[0]?.outcome?.result).toBe("unresolved");
});

test("an unusable destination fails simulation before reserving or releasing signed bytes", async () => {
  const payment = await h.authorized();
  const journal = new FileSubmissionJournal(mkdtempSync(join(tmpdir(), "sac006-reclaim-simulation-")));
  h.setTime(DC);
  const simulate = h.ledger.simulate;
  const before = h.ledger.submissions.length;
  h.ledger.simulate = async transaction => {
    expect(transaction.signatures[h.payer.address]).toBeNull();
    return { ok: false, error: "destination frozen", logs: [] };
  };
  try {
    await expect(submitReclaim(argsFor(payment, journal))).rejects.toThrow(/destination frozen/);
    expect(journal.list()).toHaveLength(0);
    expect(h.ledger.submissions).toHaveLength(before);
  } finally { h.ledger.simulate = simulate; }
  expect((await submitReclaim(argsFor(payment, journal))).result).toMatchObject({ kind: "submitted", outcome: { status: "succeeded" } });
});

test("a thrown submission is retained as unresolved evidence", async () => {
  const payment = await h.authorized();
  const journal = new FileSubmissionJournal(mkdtempSync(join(tmpdir(), "sac006-reclaim-transport-")));
  h.setTime(DC);
  const submit = h.ledger.submit;
  h.ledger.submit = async () => { throw new Error("response lost"); };
  try {
    await expect(submitReclaim(argsFor(payment, journal))).rejects.toThrow(/response lost/);
    expect(journal.list()).toHaveLength(1);
    expect(journal.list()[0]?.attempts[0]?.outcome?.result).toBe("submit-threw");
  } finally { h.ledger.submit = submit; }
});
