// Acceptance 1 and 3: one valid /verify + /settle path per operation over real HTTP, asserting
// the exact executed instruction, signer role, amount, and the returned operation result.
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { authorizePayload } from "../src/transactions.js";
import { Tag } from "../src/program.js";
import { BINARY_SHA256, createHarness, DC, DR, type Harness, inspect, M, NETWORK } from "./fixture.js";

let h: Harness;
beforeAll(async () => {
  h = await createHarness();
  console.log(`SBF binary sha256: ${BINARY_SHA256}`);
});
afterAll(() => h.close());

/** Verifies read-only, then settles, and returns the settle response plus the landed transaction. */
async function verifyThenSettle(body: unknown, payment?: string) {
  const before = await h.snapshot(payment as never);
  const submitted = h.ledger.submissions.length;
  const v = await h.post("/verify", body);
  expect(v.status).toBe(200);
  expect(v.json).toMatchObject({ isValid: true, payer: h.payer.address });
  // /verify is read-only: no submission and no account change.
  expect(h.ledger.submissions.length).toBe(submitted);
  expect(await h.snapshot(payment as never)).toBe(before);

  const s = await h.post("/settle", body);
  expect(s.status).toBe(200);
  expect(h.ledger.submissions.length).toBe(submitted + 1);
  const landed = h.ledger.submissions.at(-1)!;
  expect(landed.status).toBe("succeeded");
  expect(s.json).toMatchObject({ success: true, transaction: landed.signature, network: NETWORK, payer: h.payer.address });
  expect(s.json.errorReason).toBeUndefined();
  // The verify preview and the settle result describe the same exact operation.
  expect(s.json.extensions["auth-capture"]).toEqual(v.json.extra["auth-capture"]);
  return { result: s.json.extensions["auth-capture"], amount: s.json.amount, landed: inspect(landed.transaction) };
}

describe("authorize, capture, capture+void, refund, void through /verify and /settle", () => {
  test("authorize settles the payer-signed deposit of exactly M with the sponsor as fee payer and rent funder", async () => {
    const salt = h.newSalt();
    const payment = await h.paymentFor(salt);
    const payerBefore = h.tokens(await h.payerAta());
    const body = h.body(authorizePayload(await h.signedAuthorize({ salt })));

    const { result, amount, landed } = await verifyThenSettle(body, payment);

    expect(landed.data[0]).toBe(Tag.authorize);
    expect(landed.signers).toEqual([h.facilitatorKey.address, h.payer.address]);
    expect(landed.accounts[0]).toBe(h.payer.address);
    expect(landed.accounts[1]).toBe(h.server.address);
    expect(landed.accounts[6]).toBe(h.facilitatorKey.address);
    expect(amount).toBe("100");
    expect(result).toEqual({ operation: "authorize", payment, amount: "100", held: "100", refundable: "0" });
    expect(h.state(payment)).toMatchObject({
      payer: h.payer.address,
      server: h.server.address,
      mint: h.mint,
      maximum: M,
      captureDeadline: DC,
      refundDeadline: DR,
      held: 100n,
      refundable: 0n,
    });
    expect(h.tokens(await h.vault(payment))).toBe(100n);
    expect(h.tokens(await h.payerAta())).toBe(payerBefore - 100n);
  });

  test("capture, capture+void, and repeated refunds map to the server-signed program instructions", async () => {
    const payment = await h.authorized();
    const serverAta = await h.serverAta();
    const payerAta = await h.payerAta();
    const server0 = h.tokens(serverAta);
    const payer0 = h.tokens(payerAta);

    // capture(a=30, releaseRemainder=false, expected (100,0))
    const cap = await verifyThenSettle(h.body(await h.capture(payment, 30n, false, 100n, 0n)), payment);
    expect(cap.landed.data[0]).toBe(Tag.capture);
    expect(cap.landed.data[9]).toBe(0);
    expect(cap.landed.signers).toEqual([h.facilitatorKey.address, h.server.address]);
    expect(cap.landed.accounts[0]).toBe(h.server.address);
    expect(cap.landed.accounts[4]).toBe(serverAta);
    expect(cap.amount).toBe("30");
    expect(cap.result).toEqual({ operation: "capture", payment, amount: "30", releaseRemainder: false, held: "70", refundable: "30" });
    expect(h.state(payment)).toMatchObject({ maximum: M, held: 70n, refundable: 30n });
    expect(h.tokens(serverAta)).toBe(server0 + 30n);

    // capture(a=20, releaseRemainder=true, expected (70,30)): pays 20 and releases 50 atomically.
    const cv = await verifyThenSettle(h.body(await h.capture(payment, 20n, true, 70n, 30n)), payment);
    expect(cv.landed.data[0]).toBe(Tag.capture);
    expect(cv.landed.data[9]).toBe(1);
    expect(cv.landed.accounts[5]).toBe(payerAta);
    expect(cv.amount).toBe("20");
    expect(cv.result).toEqual({
      operation: "capture",
      payment,
      amount: "20",
      releaseRemainder: true,
      released: "50",
      held: "0",
      refundable: "50",
    });
    expect(h.state(payment)).toMatchObject({ maximum: M, held: 0n, refundable: 50n });
    expect(h.tokens(serverAta)).toBe(server0 + 50n);
    expect(h.tokens(payerAta)).toBe(payer0 + 50n);
    expect(h.tokens(await h.vault(payment))).toBe(0n);

    // refund(r=15, expected (0,50)) then refund(r=10, expected (0,35)): server-funded, repeatable.
    const r1 = await verifyThenSettle(h.body(await h.refund(payment, 15n, 0n, 50n)), payment);
    expect(r1.landed.data[0]).toBe(Tag.refund);
    expect(r1.landed.signers).toEqual([h.facilitatorKey.address, h.server.address]);
    // Refund source is the stored server's ATA and destination the stored payer's ATA.
    expect(r1.landed.accounts[3]).toBe(serverAta);
    expect(r1.landed.accounts[4]).toBe(payerAta);
    expect(r1.result).toEqual({ operation: "refund", payment, amount: "15", held: "0", refundable: "35" });
    const r2 = await verifyThenSettle(h.body(await h.refund(payment, 10n, 0n, 35n)), payment);
    expect(r2.result).toEqual({ operation: "refund", payment, amount: "10", held: "0", refundable: "25" });
    expect(h.state(payment)).toMatchObject({ maximum: M, held: 0n, refundable: 25n });
    expect(h.tokens(serverAta)).toBe(server0 + 25n);
    expect(h.tokens(payerAta)).toBe(payer0 + 75n);
  });

  test("void releases the entire hold as a distinct operation, not a capture", async () => {
    const payment = await h.authorized();
    const payer0 = h.tokens(await h.payerAta());
    const server0 = h.tokens(await h.serverAta());

    const v = await verifyThenSettle(h.body(await h.voidOp(payment, 100n, 0n)), payment);

    expect(v.landed.data[0]).toBe(Tag.void);
    expect(v.landed.data.length).toBe(17);
    expect(v.landed.signers).toEqual([h.facilitatorKey.address, h.server.address]);
    expect(v.amount).toBeUndefined(); // a void settles nothing to the server; see README Results
    expect(v.result).toEqual({ operation: "void", payment, amount: "100", held: "0", refundable: "0" });
    expect(h.state(payment)).toMatchObject({ maximum: M, held: 0n, refundable: 0n });
    expect(h.tokens(await h.payerAta())).toBe(payer0 + 100n);
    expect(h.tokens(await h.serverAta())).toBe(server0);
  });

  test("full capture with releaseRemainder releases nothing and leaves no hold", async () => {
    const payment = await h.authorized();
    const server0 = h.tokens(await h.serverAta());
    const payer0 = h.tokens(await h.payerAta());

    const c = await verifyThenSettle(h.body(await h.capture(payment, 100n, true, 100n, 0n)), payment);

    expect(c.landed.data[9]).toBe(1);
    expect(c.result).toEqual({
      operation: "capture",
      payment,
      amount: "100",
      releaseRemainder: true,
      released: "0",
      held: "0",
      refundable: "100",
    });
    expect(h.tokens(await h.serverAta())).toBe(server0 + 100n);
    expect(h.tokens(await h.payerAta())).toBe(payer0);
  });

  test("an omitted paymentFlow resolves to the escrow default", async () => {
    const salt = h.newSalt();
    const req = h.requirements({}, { paymentFlow: undefined });
    delete req.extra!.paymentFlow;
    const r = await h.post("/settle", h.body(authorizePayload(await h.signedAuthorize({ salt })), req));
    expect(r.json).toMatchObject({ success: true });
    expect(h.state(await h.paymentFor(salt)).held).toBe(M);
  });
});
