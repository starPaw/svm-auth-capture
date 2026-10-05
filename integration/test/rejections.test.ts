// Acceptance 2 and 3: unsupported profiles, mismatched terms, altered or mis-signed
// transactions, wrong amounts/pairs, and expired operations fail closed at /verify and at
// /settle before any submission, leaving every touched account byte-identical.
import { type Address, generateKeyPairSigner, type Transaction } from "@solana/kit";
import { getTransferSolInstruction } from "@solana-program/system";
import { getTransferInstruction } from "@solana-program/token";
import { getSetComputeUnitLimitInstruction, getSetComputeUnitPriceInstruction } from "./compute-budget.js";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import {
  ata,
  captureAccounts,
  captureData,
  LOCAL_PROGRAM_ID,
  refundAccounts,
  refundData,
  toInstruction,
} from "../src/program.js";
import {
  authorizePayload,
  buildTransaction,
  capturePayload,
  captureInstruction,
  refundPayload,
  voidPayload,
} from "../src/transactions.js";
import { Reason } from "../src/types.js";
import { createHarness, DC, DR, type Harness, NETWORK, NOW } from "./fixture.js";

let h: Harness;
beforeAll(async () => {
  h = await createHarness();
});
afterAll(() => h.close());

async function rejected(body: unknown, reason: string, payment?: Address) {
  const before = await h.snapshot(payment);
  const submitted = h.ledger.submissions.length;
  const v = await h.post("/verify", body);
  expect(v.json).toMatchObject({ isValid: false, invalidReason: reason });
  const s = await h.post("/settle", body);
  expect(s.json).toMatchObject({ success: false, errorReason: reason, transaction: "", network: NETWORK });
  expect(h.ledger.submissions.length).toBe(submitted);
  expect(await h.snapshot(payment)).toBe(before);
}

/** Message bytes from `altered`, signatures from `signed`: a signature that covers other bytes. */
const transplant = (signed: Transaction, altered: Transaction): Transaction => ({
  messageBytes: altered.messageBytes,
  signatures: { ...altered.signatures, ...signed.signatures },
});

describe("profile and requirements", () => {
  test("unsupported scheme, payment flow, network, program, version, sponsor, and accepted drift", async () => {
    const salt = h.newSalt();
    const payload = authorizePayload(await h.signedAuthorize({ salt }));
    const payment = await h.paymentFor(salt);
    await rejected(h.body(payload, h.requirements({ scheme: "exact" })), Reason.unsupportedScheme, payment);
    await rejected(h.body(payload, h.requirements({}, { paymentFlow: "authorization" })), Reason.paymentFlow, payment);
    await rejected(h.body(payload, h.requirements({}, { paymentFlow: "upfront" })), Reason.paymentFlow, payment);
    await rejected(
      h.body(payload, h.requirements({ network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1" })),
      Reason.networkMismatch,
      payment,
    );
    await rejected(h.body(payload, h.requirements({ network: "not-caip2" })), Reason.invalidNetwork, payment);
    await rejected(h.body(payload, h.requirements({}, { programId: h.outsider.address })), Reason.programMismatch, payment);
    await rejected(h.body(payload, h.requirements({}, { feePayer: h.outsider.address })), Reason.feePayerMismatch, payment);
    await rejected({ ...h.body(payload), x402Version: 1 }, Reason.x402Version, payment);
    const drift = h.body(payload);
    drift.paymentPayload.accepted = h.requirements({}, { captureDeadline: Number(DC) + 1 });
    await rejected(drift, Reason.acceptedMismatch, payment);
    await rejected(h.body(payload, h.requirements({}, { captureDeadline: Number(DR) + 1 })), Reason.deadlineOrdering, payment);
  });

  test("unsupported economic-profile fields are rejected, not ignored, in requirements and accepted", async () => {
    const salt = h.newSalt();
    const payload = authorizePayload(await h.signedAuthorize({ salt }));
    const payment = await h.paymentFor(salt);
    for (const extra of [
      { assetTransferMethod: "permit2" },
      { assetTransferMethod: "eip3009" },
      { operatorType: "policy" },
      { operatorType: "delegated" },
      { minFeeBps: 100, maxFeeBps: 100 },
      { minFeeBps: 0, maxFeeBps: 0 },
      { feeRecipient: h.outsider.address },
      { captureMode: "deferred" },
    ]) {
      await rejected(h.body(payload, h.requirements({}, extra)), Reason.unsupportedExtra, payment);
    }
    // Requirements clean, accepted selecting a different transfer method.
    const drift = h.body(payload);
    drift.paymentPayload.accepted = h.requirements({}, { assetTransferMethod: "permit2" });
    await rejected(drift, Reason.acceptedMismatch, payment);
    // The same profile written differently (string deadline, implicit escrow flow) is equal.
    const normalized = h.body(payload);
    const { paymentFlow: _, ...implicit } = h.requirements({}, { captureDeadline: DC.toString() }).extra!;
    normalized.paymentPayload.accepted = { ...h.requirements(), extra: implicit };
    expect((await h.post("/verify", normalized)).json).toMatchObject({ isValid: true });
  });

  test("wrapped SOL and Token-2022 assets are unsupported", async () => {
    const native = "So11111111111111111111111111111111111111112" as Address;
    const salt = h.newSalt();
    await rejected(
      h.body(authorizePayload(await h.signedAuthorize({ salt, mint: native })), h.requirements({ asset: native })),
      Reason.unsupportedAsset,
    );
    // A mint-shaped account owned by Token-2022 (adversarial fixture state).
    const token2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb" as Address;
    const fake = (await generateKeyPairSigner()).address;
    const classic = h.svm.getAccount(h.mint);
    if (!classic.exists) throw new Error("mint missing");
    h.svm.setAccount({ ...classic, address: fake, programAddress: token2022 });
    await rejected(
      h.body(authorizePayload(await h.signedAuthorize({ salt, mint: fake })), h.requirements({ asset: fake })),
      Reason.unsupportedAsset,
    );
  });
});

describe("authorize terms and transaction", () => {
  test("requirements must equal the payer-signed payTo, asset, M, Dc, and Dr", async () => {
    const salt = h.newSalt();
    const payment = await h.paymentFor(salt);
    const payload = authorizePayload(await h.signedAuthorize({ salt }));
    const otherMint = (await generateKeyPairSigner()).address;
    await rejected(h.body(payload, h.requirements({ payTo: h.outsider.address })), Reason.termsMismatch, payment);
    await rejected(h.body(payload, h.requirements({ asset: otherMint })), Reason.termsMismatch, payment);
    await rejected(h.body(payload, h.requirements({ amount: "99" })), Reason.termsMismatch, payment);
    await rejected(h.body(payload, h.requirements({ amount: "101" })), Reason.termsMismatch, payment);
    await rejected(h.body(payload, h.requirements({}, { captureDeadline: Number(DC) - 1 })), Reason.termsMismatch, payment);
    await rejected(h.body(payload, h.requirements({}, { refundDeadline: Number(DR) + 1 })), Reason.termsMismatch, payment);
  });

  test("altered message, missing payer signature, and foreign fee payer are rejected", async () => {
    const salt = h.newSalt();
    const payment = await h.paymentFor(salt);
    const signed = await h.signedAuthorize({ salt });
    const altered = await h.signedAuthorize({ salt, maximum: 99n, signers: [] });
    await rejected(h.body(authorizePayload(transplant(signed, altered)), h.requirements({ amount: "99" })), Reason.signature, payment);
    await rejected(h.body(authorizePayload(await h.signedAuthorize({ salt, signers: [] }))), Reason.signature, payment);
    await rejected(
      h.body(authorizePayload(await h.signedAuthorize({ salt, feePayer: h.payer.address }))),
      Reason.feePayerMismatch,
      payment,
    );
  });

  test("only bounded compute-budget instructions may accompany authorize", async () => {
    const salt = h.newSalt();
    const payment = await h.paymentFor(salt);
    const sponsorDrain = getTransferSolInstruction({
      source: h.facilitatorKey,
      destination: h.outsider.address,
      amount: 1_000_000n,
    });
    await rejected(h.body(authorizePayload(await h.signedAuthorize({ salt, extra: [sponsorDrain] }))), Reason.instructions, payment);
    const payerSpend = getTransferInstruction({
      source: await h.payerAta(),
      destination: await ata(h.outsider.address, h.mint),
      authority: h.payer,
      amount: 1n,
    });
    await rejected(h.body(authorizePayload(await h.signedAuthorize({ salt, extra: [payerSpend] }))), Reason.instructions, payment);
    await rejected(
      h.body(authorizePayload(await h.signedAuthorize({ salt, extra: [getSetComputeUnitLimitInstruction(1_400_000)] }))),
      Reason.instructions,
      payment,
    );
    await rejected(
      h.body(authorizePayload(await h.signedAuthorize({ salt, extra: [getSetComputeUnitPriceInstruction(1_000_000n)] }))),
      Reason.instructions,
      payment,
    );
    const bounded = [getSetComputeUnitLimitInstruction(200_000), getSetComputeUnitPriceInstruction(1n)];
    const ok = await h.post("/settle", h.body(authorizePayload(await h.signedAuthorize({ salt, extra: bounded }))));
    expect(ok.json).toMatchObject({ success: true, amount: "100" });
  });

  test("a used identity, an expired capture deadline, and an unfunded payer fail before submission", async () => {
    const salt = h.newSalt();
    const payment = await h.paymentFor(salt);
    const payload = authorizePayload(await h.signedAuthorize({ salt }));
    expect((await h.post("/settle", h.body(payload))).json).toMatchObject({ success: true });
    // Resending the identical authorization never collects again.
    await rejected(h.body(payload), Reason.paymentExists, payment);

    const fresh = h.newSalt();
    h.setTime(DC);
    await rejected(h.body(authorizePayload(await h.signedAuthorize({ salt: fresh }))), Reason.captureExpired, await h.paymentFor(fresh));
    h.setTime(NOW);
    await rejected(
      h.body(authorizePayload(await h.signedAuthorize({ salt: fresh, maximum: 1_000_000n })), h.requirements({ amount: "1000000" })),
      Reason.insufficientFunds,
      await h.paymentFor(fresh),
    );
  });
});

describe("lifecycle terms, consent, amounts, and deadlines", () => {
  test("requirements must equal stored terms; a smaller operation amount never replaces M", async () => {
    const payment = await h.authorized();
    const payload = await h.capture(payment, 30n, false, 100n, 0n);
    // The operation amount offered as the requirements amount is rejected: amount is always M.
    await rejected(h.body(payload, h.requirements({ amount: "30" })), Reason.termsMismatch, payment);
    await rejected(h.body(payload, h.requirements({ payTo: h.outsider.address })), Reason.termsMismatch, payment);
    await rejected(h.body(payload, h.requirements({ asset: h.outsider.address })), Reason.termsMismatch, payment);
    await rejected(h.body(payload, h.requirements({}, { captureDeadline: Number(DC) + 1 })), Reason.termsMismatch, payment);
    await rejected(h.body(payload, h.requirements({}, { refundDeadline: Number(DR) - 1 })), Reason.termsMismatch, payment);

    expect((await h.post("/settle", h.body(payload))).json).toMatchObject({ success: true, amount: "30" });
    expect(h.state(payment)).toMatchObject({ maximum: 100n, held: 70n, refundable: 30n });
    // Later operations still verify against the original M.
    const next = h.body(await h.capture(payment, 10n, false, 70n, 30n));
    expect((await h.post("/verify", next)).json).toMatchObject({ isValid: true });
    await rejected(h.body(next.paymentPayload.payload, h.requirements({ amount: "70" })), Reason.termsMismatch, payment);
  });

  test("altered, unsigned, payer-, outsider-, and sponsor-signed server operations are rejected", async () => {
    const payment = await h.authorized();
    const signed = await h.signedCapture(payment, 30n, false, 100n, 0n);
    const altered = await h.signedCapture(payment, 90n, false, 100n, 0n, []);
    await rejected(h.body(capturePayload(payment, transplant(signed, altered), 90n, false, 100n, 0n)), Reason.signature, payment);
    await rejected(h.body(capturePayload(payment, altered, 90n, false, 100n, 0n)), Reason.signature, payment);

    const stored = await h.stored(payment);
    for (const imposter of [h.payer, h.outsider]) {
      // The imposter occupies the server role and signs; stored server consent is absent.
      const ix = await captureInstruction({ ...stored, server: imposter.address }, 30n, false, 100n, 0n);
      const tx = await buildTransaction({ feePayer: h.facilitatorKey.address, instructions: [ix], signers: [imposter], lifetime: h.lifetime() });
      await rejected(h.body(capturePayload(payment, tx, 30n, false, 100n, 0n)), Reason.signature, payment);
    }
    // The sponsor's signature alone authorizes nothing: it cannot be the server signer.
    const sponsorIx = await captureInstruction({ ...stored, server: h.facilitatorKey.address }, 30n, false, 100n, 0n);
    const sponsorTx = await buildTransaction({
      feePayer: h.facilitatorKey.address,
      instructions: [sponsorIx],
      signers: [h.facilitatorKey],
      lifetime: h.lifetime(),
    });
    await rejected(h.body(capturePayload(payment, sponsorTx, 30n, false, 100n, 0n)), Reason.signature, payment);
    // A server-signed operation whose fee payer is not the facilitator sponsor.
    const foreign = await buildTransaction({
      feePayer: h.outsider.address,
      instructions: [await captureInstruction(stored, 30n, false, 100n, 0n)],
      signers: [h.server],
      lifetime: h.lifetime(),
    });
    await rejected(h.body(capturePayload(payment, foreign, 30n, false, 100n, 0n)), Reason.feePayerMismatch, payment);
  });

  test("wrong operation amounts and expected pairs are rejected", async () => {
    const payment = await h.authorized();
    const tx = await h.signedCapture(payment, 30n, false, 100n, 0n);
    await rejected(h.body(capturePayload(payment, tx, 31n, false, 100n, 0n)), Reason.payloadMismatch, payment);
    await rejected(h.body(capturePayload(payment, tx, 30n, false, 99n, 0n)), Reason.payloadMismatch, payment);
    await rejected(h.body(await h.capture(payment, 101n, false, 100n, 0n)), Reason.amount, payment);
    await rejected(h.body(await h.capture(payment, 0n, false, 100n, 0n)), Reason.amount, payment);
    await rejected(h.body(await h.capture(payment, 30n, false, 99n, 0n)), Reason.unexpectedState, payment);
    await rejected(h.body(await h.capture(payment, 30n, false, 100n, 1n)), Reason.unexpectedState, payment);
    await rejected(h.body(await h.voidOp(payment, 100n, 5n)), Reason.unexpectedState, payment);

    expect((await h.post("/settle", h.body(await h.capture(payment, 40n, false, 100n, 0n)))).json).toMatchObject({ success: true });
    await rejected(h.body(await h.refund(payment, 41n, 60n, 40n)), Reason.amount, payment);
    await rejected(h.body(await h.refund(payment, 0n, 60n, 40n)), Reason.amount, payment);
    // A consumed consent (old pair) cannot be applied again.
    await rejected(h.body(await h.capture(payment, 40n, false, 100n, 0n)), Reason.unexpectedState, payment);
  });

  test("capture at Dc and refund at Dr are rejected before submission", async () => {
    const payment = await h.authorized();
    expect((await h.post("/settle", h.body(await h.capture(payment, 40n, false, 100n, 0n)))).json).toMatchObject({ success: true });
    const capture = h.body(await h.capture(payment, 10n, false, 60n, 40n));
    const refund = h.body(await h.refund(payment, 10n, 60n, 40n));
    h.setTime(DC - 1n);
    expect((await h.post("/verify", capture)).json).toMatchObject({ isValid: true });
    h.setTime(DC);
    await rejected(capture, Reason.captureExpired, payment);
    expect((await h.post("/verify", refund)).json).toMatchObject({ isValid: true });
    h.setTime(DR);
    await rejected(refund, Reason.refundExpired, payment);
    h.setTime(NOW);
  });

  test("capture+void carries the signed release flag; void and capture are not interchangeable", async () => {
    const payment = await h.authorized();
    const release = await h.signedCapture(payment, 30n, true, 100n, 0n);
    const keep = await h.signedCapture(payment, 30n, false, 100n, 0n);
    await rejected(h.body(capturePayload(payment, release, 30n, false, 100n, 0n)), Reason.payloadMismatch, payment);
    await rejected(h.body(capturePayload(payment, keep, 30n, true, 100n, 0n)), Reason.payloadMismatch, payment);
    const voidTx = await h.signedVoid(payment, 100n, 0n);
    await rejected(h.body({ ...capturePayload(payment, voidTx, 30n, false, 100n, 0n) }), Reason.instructionData, payment);
    await rejected(h.body(voidPayload(payment, keep, 100n, 0n)), Reason.instructionData, payment);
    const { releaseRemainder: _omit, ...implicit } = capturePayload(payment, keep, 30n, false, 100n, 0n);
    await rejected(h.body(implicit), Reason.invalidPayload, payment);
    await rejected(h.body({ ...voidPayload(payment, voidTx, 100n, 0n), amount: "100" }), Reason.invalidPayload, payment);
    await rejected(h.body({ ...voidPayload(payment, voidTx, 100n, 0n), type: "charge" }), Reason.payloadType, payment);
  });

  test("capture and refund must use the stored server and payer token accounts", async () => {
    const payment = await h.authorized();
    expect((await h.post("/settle", h.body(await h.capture(payment, 40n, false, 100n, 0n)))).json).toMatchObject({ success: true });
    const stored = await h.stored(payment);
    const outsiderAta = await ata(h.outsider.address, h.mint);
    const serverAta = await h.serverAta();
    const payerAta = await h.payerAta();
    const vault = await h.vault(payment);
    const send = (accounts: ReturnType<typeof refundAccounts>, data: Uint8Array) =>
      buildTransaction({
        feePayer: h.facilitatorKey.address,
        instructions: [toInstruction(LOCAL_PROGRAM_ID, accounts, data)],
        signers: [h.server],
        lifetime: h.lifetime(),
      });
    const base = { server: stored.server, payment, mint: stored.mint };
    const toOutsider = await send(refundAccounts({ ...base, serverAta, payerAta: outsiderAta }), refundData(10n, 60n, 40n));
    await rejected(h.body(refundPayload(payment, toOutsider, 10n, 60n, 40n)), Reason.accounts, payment);
    const fromOutsider = await send(refundAccounts({ ...base, serverAta: outsiderAta, payerAta }), refundData(10n, 60n, 40n));
    await rejected(h.body(refundPayload(payment, fromOutsider, 10n, 60n, 40n)), Reason.accounts, payment);
    const redirected = await send(
      captureAccounts({ ...base, vault, serverAta: outsiderAta, payerAta }),
      captureData(10n, false, 60n, 40n),
    );
    await rejected(h.body(capturePayload(payment, redirected, 10n, false, 60n, 40n)), Reason.accounts, payment);
  });

  test("insufficient server liquidity fails refund settlement without facilitator funding", async () => {
    const payment = await h.authorized();
    expect((await h.post("/settle", h.body(await h.capture(payment, 40n, false, 100n, 0n)))).json).toMatchObject({ success: true });
    const serverAta = await h.serverAta();
    const balance = h.tokens(serverAta);
    const parking = await ata(h.outsider.address, h.mint);
    const { getCreateAssociatedTokenIdempotentInstruction } = await import("@solana-program/token");
    h.ok(
      await h.direct(
        [
          getCreateAssociatedTokenIdempotentInstruction({ payer: h.setup, owner: h.outsider.address, mint: h.mint, ata: parking }),
          getTransferInstruction({ source: serverAta, destination: parking, authority: h.server, amount: balance - 5n }),
        ],
        [h.server],
      ),
    );
    await rejected(h.body(await h.refund(payment, 10n, 60n, 40n)), Reason.serverInsufficientFunds, payment);
    expect(h.state(payment)).toMatchObject({ held: 60n, refundable: 40n });
  });

  test("unknown payment and unknown operation type are rejected", async () => {
    const ghost = await h.paymentFor(h.newSalt());
    const tx = await h.signedVoid(ghost, 100n, 0n);
    await rejected(h.body(voidPayload(ghost, tx, 100n, 0n)), Reason.paymentNotFound);
    await rejected(h.body({ type: "settle", payment: ghost, transaction: "AA==" }), Reason.payloadType);
  });
});
