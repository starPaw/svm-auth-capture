// Acceptance 3 and 4: settlement outcome reporting, no automatic retry, reclaim kept out of
// /settle, and the HTTP surface limited to /verify and /settle.
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { FailedTransactionMetadata } from "litesvm";
import { LOCAL_PROGRAM_ID, reclaimAccounts, toInstruction } from "../src/program.js";
import { authorizePayload, buildTransaction, encodeTransaction } from "../src/transactions.js";
import { Reason } from "../src/types.js";
import { createHarness, DC, type Harness, inspect, NETWORK, NOW } from "./fixture.js";

let h: Harness;
beforeAll(async () => {
  h = await createHarness();
});
afterAll(() => h.close());

const reset = () => {
  h.ledger.beforeSubmit = undefined;
  h.ledger.failSubmit = undefined;
  h.setTime(NOW);
};

describe("settlement outcomes", () => {
  test("a confirmed failed transaction is reported as failure with its signature, once", async () => {
    const payment = await h.authorized();
    // A competing server void, relayed concurrently (fully signed), lands between the
    // facilitator's preflight and its broadcast.
    const competitor = await h.signedVoid(payment, 100n, 0n, [h.server, h.facilitatorKey]);
    h.ledger.beforeSubmit = () => {
      h.ledger.beforeSubmit = undefined;
      const r = h.svm.sendTransaction(competitor);
      if (r instanceof FailedTransactionMetadata) throw new Error(r.toString());
    };
    const server0 = h.tokens(await h.serverAta());
    const submitted = h.ledger.submissions.length;

    const s = await h.post("/settle", h.body(await h.capture(payment, 30n, false, 100n, 0n)));

    expect(h.ledger.submissions.length).toBe(submitted + 1);
    const landed = h.ledger.submissions.at(-1)!;
    expect(landed.status).toBe("failed");
    expect(s.json).toEqual({
      success: false,
      errorReason: Reason.transactionState,
      transaction: landed.signature,
      network: NETWORK,
      payer: h.payer.address,
    });
    // The program rejected the stale pair: the void's release stands, nothing was captured.
    expect(h.state(payment)).toMatchObject({ held: 0n, refundable: 0n });
    expect(h.tokens(await h.serverAta())).toBe(server0);
    reset();
  });

  test("an unknown outcome before landing is pending; the caller's resend reuses the exact bytes", async () => {
    const payment = await h.authorized();
    const body = h.body(await h.capture(payment, 30n, false, 100n, 0n));
    h.ledger.failSubmit = "before-landing";
    const submitted = h.ledger.submissions.length;

    const pending = await h.post("/settle", body);

    expect(pending.json).toMatchObject({ success: false, errorReason: Reason.settlementPending, network: NETWORK });
    expect(pending.json.transaction).toBe(h.ledger.submissions.at(-1)!.signature);
    expect(pending.json.transaction).not.toBe("");
    expect(h.ledger.submissions.length).toBe(submitted + 1); // no automatic retry
    expect(h.state(payment)).toMatchObject({ held: 100n, refundable: 0n });

    // A later explicit resend of the same payload broadcasts identical bytes: same signature,
    // same blockhash, no re-signing or new economic consent.
    h.ledger.failSubmit = undefined;
    const resent = await h.post("/settle", body);
    expect(resent.json).toMatchObject({ success: true, transaction: pending.json.transaction, amount: "30" });
    const [first, second] = h.ledger.submissions.slice(-2);
    expect(Buffer.from(second!.transaction.messageBytes)).toEqual(Buffer.from(first!.transaction.messageBytes));
    expect(h.state(payment)).toMatchObject({ held: 70n, refundable: 30n });
    reset();
  });

  test("an unknown outcome after landing is pending, never success, and cannot move funds twice", async () => {
    const payment = await h.authorized();
    const body = h.body(await h.capture(payment, 30n, false, 100n, 0n));
    h.ledger.failSubmit = "after-landing";

    const pending = await h.post("/settle", body);

    expect(pending.json).toMatchObject({ success: false, errorReason: Reason.settlementPending });
    const signature = pending.json.transaction as string;
    expect(signature).toBe(h.ledger.submissions.at(-1)!.signature);
    // The transaction did land; reconciliation must attribute it by signature.
    expect(h.state(payment)).toMatchObject({ held: 70n, refundable: 30n });
    h.ledger.failSubmit = undefined;
    const submitted = h.ledger.submissions.length;
    const again = await h.post("/settle", body);
    expect(again.json).toMatchObject({ success: false, errorReason: Reason.unexpectedState });
    expect(h.ledger.submissions.length).toBe(submitted);
    expect(h.state(payment)).toMatchObject({ held: 70n, refundable: 30n });
    reset();
  });

  test("two settles consented against the same pair: exactly one commits", async () => {
    const payment = await h.authorized();
    const capture = h.body(await h.capture(payment, 30n, false, 100n, 0n));
    const voidOp = h.body(await h.voidOp(payment, 100n, 0n));
    const results = await Promise.all([h.post("/settle", capture), h.post("/settle", voidOp)]);
    const winners = results.filter((r) => r.json.success === true);
    expect(winners).toHaveLength(1);
    const loser = results.find((r) => r.json.success !== true)!;
    expect([Reason.unexpectedState, Reason.transactionState]).toContain(loser.json.errorReason);
    const s = h.state(payment);
    expect([`${s.held},${s.refundable}`]).toContain(winners[0]!.json.extensions["auth-capture"].operation === "void" ? "0,0" : "70,30");
    reset();
  });
});

describe("reclaim stays payer-direct", () => {
  test("reclaim payloads are rejected at /verify and /settle; the payer reclaims directly", async () => {
    const payment = await h.authorized();
    const stored = await h.stored(payment);
    const reclaimIx = toInstruction(
      LOCAL_PROGRAM_ID,
      reclaimAccounts({ payer: h.payer.address, payment, mint: h.mint, vault: await h.vault(payment), payerAta: await h.payerAta() }),
      Uint8Array.of(1),
    );
    h.setTime(DC);
    const relayed = await buildTransaction({
      feePayer: h.facilitatorKey.address,
      instructions: [reclaimIx],
      signers: [h.payer],
      lifetime: h.lifetime(),
    });
    const submitted = h.ledger.submissions.length;
    for (const payload of [
      { type: "reclaim", payment, transaction: encodeTransaction(relayed) },
      authorizePayload(relayed),
    ]) {
      const v = await h.post("/verify", h.body(payload));
      expect(v.json).toMatchObject({ isValid: false, invalidReason: Reason.reclaimNotRelayed });
      const s = await h.post("/settle", h.body(payload));
      expect(s.json).toMatchObject({ success: false, errorReason: Reason.reclaimNotRelayed, transaction: "" });
    }
    expect(h.ledger.submissions.length).toBe(submitted);
    expect(h.state(payment).held).toBe(100n);

    // Outside the facilitator: payer-built, payer-signed, payer-paid reclaim at t = Dc.
    const payer0 = h.tokens(await h.payerAta());
    const direct = await buildTransaction({
      feePayer: h.payer.address,
      instructions: [reclaimIx],
      signers: [h.payer],
      lifetime: h.lifetime(),
    });
    expect(h.svm.sendTransaction(direct)).not.toBeInstanceOf(FailedTransactionMetadata);
    expect(inspect(direct).signers).toEqual([h.payer.address]);
    expect(h.state(payment)).toMatchObject({ payer: stored.payer, held: 0n, refundable: 0n });
    expect(h.tokens(await h.payerAta())).toBe(payer0 + 100n);
    expect(h.ledger.submissions.length).toBe(submitted);
    reset();
  });
});

describe("HTTP surface", () => {
  test("only POST /verify and POST /settle exist; malformed JSON is rejected", async () => {
    for (const path of ["/capture", "/void", "/refund", "/reclaim", "/authorize", "/supported"]) {
      expect((await fetch(h.url + path, { method: "POST", body: "{}" })).status).toBe(404);
    }
    expect((await fetch(h.url + "/settle")).status).toBe(404);
    const bad = await fetch(h.url + "/settle", { method: "POST", headers: { "content-type": "application/json" }, body: "{" });
    expect(bad.status).toBe(400);
    expect(await bad.json()).toMatchObject({ success: false, errorReason: Reason.invalidPayload, transaction: "" });
    const badVerify = await fetch(h.url + "/verify", { method: "POST", headers: { "content-type": "application/json" }, body: "[" });
    expect(badVerify.status).toBe(400);
    expect(await badVerify.json()).toMatchObject({ isValid: false, invalidReason: Reason.invalidPayload });
  });
});
