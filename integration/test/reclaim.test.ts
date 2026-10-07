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

async function pendingReclaim(captureAmount = 0n) {
  const payment = await h.authorized();
  if (captureAmount > 0n) expect((await h.facilitator.settle(h.body(await h.capture(payment, captureAmount, false, 100n, 0n)))).success).toBe(true);
  h.setTime(DC);
  const dir = mkdtempSync(join(tmpdir(), "sac006-expired-reclaim-"));
  const journal = new FileSubmissionJournal(dir);
  const submit = h.ledger.submit;
  h.ledger.submit = async () => ({ kind: "submitted" });
  let original;
  try { original = await submitReclaim({ ...argsFor(payment, journal), lifetime: { ...h.lifetime(), blockhashSlot: 10n } }); }
  finally { h.ledger.submit = submit; }
  h.svm.expireBlockhash();
  const reader = {
    getSignatureStatus: async (): Promise<SignatureLookup> => ({ kind: "not-found" }),
    getFinalizedBlockhashStatus: async (blockhash: string, originSlot: bigint) => {
      expect(blockhash).toBe(journal.read(original.signature)!.blockhash);
      expect(originSlot).toBe(10n);
      return { kind: "ok" as const, valid: false, slot: 200n };
    },
    getAccountAtLeast: async (address: Address, fence: bigint) => {
      expect(fence).toBe(200n);
      return { kind: "ok" as const, slot: 201n, account: await h.ledger.getAccount(address) };
    },
  };
  return { payment, dir, journal, original, reader, args: { ...argsFor(payment, journal), retryAfter: original.signature, reader } };
}

test("expired missing reclaim permits one explicit successor across concurrent invocations, preserving original evidence", async () => {
  const c = await pendingReclaim();
  const before = JSON.stringify(c.journal.read(c.original.signature));
  const payerBefore = h.tokens(await h.payerAta());
  const vaultBefore = h.tokens(await h.vault(c.payment));
  const n = h.ledger.submissions.length;
  const outcomes = await Promise.allSettled([submitReclaim(c.args), submitReclaim({ ...c.args, journal: new FileSubmissionJournal(c.dir) })]);
  expect(outcomes.filter(x => x.status === "fulfilled")).toHaveLength(1);
  const winner = outcomes.find(x => x.status === "fulfilled")!;
  if (winner.status !== "fulfilled") throw new Error("missing successor");
  expect(winner.value.result).toMatchObject({ kind: "submitted", outcome: { status: "succeeded", commitment: "finalized" } });
  expect(h.ledger.submissions.length).toBe(n + 1);
  expect(h.state(c.payment).held).toBe(0n);
  expect(h.tokens(await h.payerAta())).toBe(payerBefore + 100n);
  expect(h.tokens(await h.vault(c.payment))).toBe(vaultBefore - 100n);
  expect(JSON.stringify(c.journal.read(c.original.signature))).toBe(before);
  expect(c.journal.read(winner.value.signature)?.reclaimRecovery).toMatchObject({ kind: "expired-no-effect", originSlot: "10", expirySlot: "200", paymentSlot: "201" });
  await expect(submitReclaim(c.args)).rejects.toThrow(/positive remaining hold/);
});

test.each(["valid", "expiry-unavailable", "early-bank", "account-unavailable", "stale-slot", "wrong-owner", "changed-held", "changed-refundable", "zero-held", "changed-terms", "tampered-wire", "missing-origin", "status-unavailable", "status-confirmed", "status-succeeded", "recorded-success"])("expiry recovery fails closed: %s", async mode => {
  const c = await pendingReclaim();
  const original = c.journal.read(c.original.signature)!;
  const oldRead = c.reader.getAccountAtLeast;
  const reader: NonNullable<Parameters<typeof submitReclaim>[0]["reader"]> = { ...c.reader };
  if (mode === "valid") reader.getFinalizedBlockhashStatus = async () => ({ kind: "ok", valid: true, slot: 200n });
  if (mode === "expiry-unavailable") reader.getFinalizedBlockhashStatus = async () => ({ kind: "unavailable", detail: "429" });
  if (mode === "early-bank") reader.getFinalizedBlockhashStatus = async () => ({ kind: "ok", valid: false, slot: 10n });
  if (mode === "account-unavailable") reader.getAccountAtLeast = async () => ({ kind: "unavailable", detail: "timeout" });
  if (mode === "status-unavailable") reader.getSignatureStatus = async () => ({ kind: "unavailable", detail: "429" });
  if (mode === "status-confirmed") reader.getSignatureStatus = async () => ({ kind: "found", commitment: "confirmed", slot: 100n, err: null });
  if (mode === "status-succeeded") reader.getSignatureStatus = async () => ({ kind: "found", commitment: "finalized", slot: 100n, err: null });
  if (["stale-slot", "wrong-owner", "changed-held", "changed-refundable", "zero-held", "changed-terms"].includes(mode)) reader.getAccountAtLeast = async (a, fence) => {
    const r = await oldRead(a, fence);
    const account = { ...r.account!, data: new Uint8Array(r.account!.data) };
    const v = new DataView(account.data.buffer);
    if (mode === "changed-held") v.setBigUint64(160, 99n, true);
    if (mode === "zero-held") v.setBigUint64(160, 0n, true);
    if (mode === "changed-refundable") v.setBigUint64(168, 1n, true);
    if (mode === "changed-terms") v.setBigUint64(144, 1n, true);
    if (mode === "wrong-owner") account.owner = h.outsider.address;
    return { ...r, slot: mode === "stale-slot" ? 199n : r.slot, account };
  };
  // A read seam leaves durable evidence untouched while presenting malformed legacy metadata.
  const journal = { prepare: c.journal.prepare.bind(c.journal), resolve: c.journal.resolve.bind(c.journal), findByMessageHash: c.journal.findByMessageHash.bind(c.journal),
    read: (s: string) => s !== c.original.signature ? c.journal.read(s) : { ...original, ...(mode === "tampered-wire" ? { transactionBase64: "tampered" } : {}), ...(mode === "missing-origin" ? { blockhashSlot: undefined } : {}), ...(mode === "recorded-success" ? { attempts: [{ preparedAt: "t", outcome: { result: "finalized-succeeded" as const, recordedAt: "t" } }] } : {}) } };
  const n = h.ledger.submissions.length, state = await h.snapshot(c.payment);
  await expect(submitReclaim({ ...c.args, reader, journal })).rejects.toThrow(/continuation is blocked/);
  expect(h.ledger.submissions.length).toBe(n);
  expect(await h.snapshot(c.payment)).toBe(state);
  expect(c.journal.read(c.original.signature)?.attempts[0]?.outcome?.result).toBe("unresolved");
});

test("a concurrent release between proof and broadcast cannot pay twice", async () => {
  const c = await pendingReclaim();
  const concurrent = await import("../src/transactions.ts");
  const competitor = await concurrent.buildTransaction({ feePayer: h.server.address,
    instructions: [await concurrent.voidInstruction({ programId: h.facilitator.programId, payment: c.payment, payer: h.payer.address, server: h.server.address, mint: h.mint }, 100n, 0n)],
    signers: [h.server], lifetime: h.lifetime() });
  const before = h.tokens(await h.payerAta());
  h.ledger.beforeSubmit = async () => {
    h.ledger.beforeSubmit = undefined;
    expect(await h.ledger.submit(competitor)).toMatchObject({ kind: "submitted", outcome: { status: "succeeded" } });
  };
  const result = await submitReclaim({ ...c.args, lifetime: h.lifetime() });
  expect(result.result).toMatchObject({ kind: "submitted", outcome: { status: "failed", commitment: "finalized" } });
  expect(h.state(c.payment).held).toBe(0n);
  expect(h.tokens(await h.payerAta())).toBe(before + 100n);
});

test("legacy reclaim needs an authenticated operator origin and can recover without rewriting old metadata", async () => {
  const c = await pendingReclaim();
  const old = c.journal.read(c.original.signature)!;
  const legacy = { prepare: c.journal.prepare.bind(c.journal), resolve: c.journal.resolve.bind(c.journal), findByMessageHash: c.journal.findByMessageHash.bind(c.journal),
    read: (s: string) => s !== c.original.signature ? c.journal.read(s) : { ...old, blockhashSlot: undefined, lastValidBlockHeight: undefined } };
  expect((await submitReclaim({ ...c.args, journal: legacy, retryBlockhashSlot: 10n })).result).toMatchObject({ kind: "submitted", outcome: { status: "succeeded" } });
  expect(c.journal.read(c.original.signature)).toEqual(old);
});

test("concurrent server refund preserves its new F while reclaim returns only the remaining H", async () => {
  const c = await pendingReclaim(20n);
  const txs = await import("../src/transactions.ts");
  const refund = await txs.buildTransaction({ feePayer: h.server.address,
    instructions: [await txs.refundInstruction({ programId: h.facilitator.programId, payment: c.payment, payer: h.payer.address, server: h.server.address, mint: h.mint }, 10n, 80n, 20n)],
    signers: [h.server], lifetime: h.lifetime() });
  const before = h.tokens(await h.payerAta());
  h.ledger.beforeSubmit = async () => {
    h.ledger.beforeSubmit = undefined;
    expect(await h.ledger.submit(refund)).toMatchObject({ kind: "submitted", outcome: { status: "succeeded" } });
  };
  expect((await submitReclaim(c.args)).result).toMatchObject({ kind: "submitted", outcome: { status: "succeeded" } });
  expect(h.state(c.payment)).toMatchObject({ held: 0n, refundable: 10n });
  expect(h.tokens(await h.payerAta())).toBe(before + 90n);
});
