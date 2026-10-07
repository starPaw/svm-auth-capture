// SAC-006 criteria 2 and 4 on Devnet, through `Facilitator.settle`/`verify` on the real
// `RpcLedger` (the code path `devnet-server.ts` runs, minus HTTP, so one driver can chain several
// operations on one payment and wait on the cluster Clock). Every rejection is bracketed by
// finalized snapshots proving the guarded state did not change; any deviation exits non-zero.
//   node --experimental-strip-types evidence/chains.ts      (env: see run-all.sh)
import { getSignatureFromTransaction, type Address } from "@solana/kit";
import { Facilitator } from "../src/facilitator.ts";
import { ata, reclaimAccounts, refundData, Tag, toInstruction, TOKEN_PROGRAM_ADDRESS } from "../src/program.ts";
import { submitReclaim } from "../src/reclaim.ts";
import { redactRpcUrl, RpcLedger } from "../src/rpc-ledger.ts";
import {
  authorizeInstruction,
  authorizePayload,
  buildTransaction,
  captureInstruction,
  capturePayload,
  encodeTransaction,
  refundInstruction,
  refundPayload,
  voidInstruction,
  voidPayload,
} from "../src/transactions.ts";
import type { PaymentRequirements, SettleResponse } from "../src/types.ts";
import { check, context, emit, finalizedSlot, slotOf, snapshot, unchanged, waitForClock } from "./lib.ts";

type Terms = { maximum: bigint; dc: bigint; dr: bigint };

async function main(): Promise<void> {
  const c = await context();
  const { record, ledger, sponsor, payer, server, mint } = c;
  const facilitator = new Facilitator({ network: record.network.caip2, programId: record.programId, feePayer: sponsor, ledger });
  const lifetime = () => ledger.latestBlockhash();
  // Every later account read must follow all transaction/expiry evidence already observed.
  let evidenceSlot = 0n;
  const advanceSlot = (slot: bigint) => { if (slot > evidenceSlot) evidenceSlot = slot; };
  const state = (label: string, payment?: Address, minSlot = 0n) =>
    snapshot(c, label, payment, minSlot > evidenceSlot ? minSlot : evidenceSlot);

  const requirements = (t: Terms): PaymentRequirements => ({
    scheme: "auth-capture",
    network: record.network.caip2,
    amount: t.maximum.toString(),
    asset: mint,
    payTo: server.address,
    maxTimeoutSeconds: 120,
    extra: { paymentFlow: "escrow", captureDeadline: t.dc.toString(), refundDeadline: t.dr.toString(), programId: record.programId, feePayer: sponsor.address },
  });
  const body = (req: PaymentRequirements, payload: Record<string, unknown>) => ({ x402Version: 2, paymentPayload: { x402Version: 2, accepted: req, payload }, paymentRequirements: req });
  const stored = (payment: Address) => ({ programId: record.programId, payment, payer: payer.address, server: server.address, mint });
  const signedByServer = async (ix: Parameters<typeof buildTransaction>[0]["instructions"][number]) =>
    buildTransaction({ feePayer: sponsor.address, instructions: [ix], signers: [server], lifetime: await lifetime() });

  async function succeeded(label: string, res: SettleResponse): Promise<SettleResponse> {
    check(res.success, `${label} settled`, { errorReason: res.errorReason });
    advanceSlot(await finalizedSlot(c, res.transaction));
    emit(label, { signature: res.transaction, slot: await slotOf(c, res.transaction), result: res.extensions?.["auth-capture"] });
    return res;
  }

  /** A rejection must name `reason`, broadcast nothing, and leave the guarded state unchanged. */
  async function rejected(label: string, payment: Address | undefined, reason: string, attempt: () => Promise<SettleResponse>): Promise<void> {
    const before = await state(`${label}: before`, payment);
    const res = await attempt();
    emit(`REJECTION ${label}`, { errorReason: res.errorReason, transaction: res.transaction });
    check(!res.success && res.errorReason === reason && res.transaction === "", `${label} rejected with ${reason}, nothing broadcast`, { got: res.errorReason });
    const after = await state(`${label}: after`, payment, BigInt(before.payment?.slot ?? "0"));
    check(unchanged(before, after), `${label} left balances and (H,F) unchanged`);
  }

  async function authorize(maximum: bigint, dc: bigint, dr: bigint): Promise<Address> {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const ix = await authorizeInstruction({ programId: record.programId, payer: payer.address, server: server.address, mint, funder: sponsor.address, salt, maximum, captureDeadline: dc, refundDeadline: dr });
    const tx = await buildTransaction({ feePayer: sponsor.address, instructions: [ix], signers: [payer], lifetime: await lifetime() });
    const res = await succeeded("authorize", await facilitator.settle(body(requirements({ maximum, dc, dr }), authorizePayload(tx))));
    return (res.extensions?.["auth-capture"] as { payment: Address }).payment;
  }
  const capture = async (p: Address, t: Terms, amount: bigint, release: boolean, h: bigint, f: bigint) => {
    const tx = await signedByServer(await captureInstruction(stored(p), amount, release, h, f));
    return facilitator.settle(body(requirements(t), capturePayload(p, tx, amount, release, h, f)));
  };
  const voidHold = async (p: Address, t: Terms, h: bigint, f: bigint) => {
    const tx = await signedByServer(await voidInstruction(stored(p), h, f));
    return facilitator.settle(body(requirements(t), voidPayload(p, tx, h, f)));
  };
  const refund = async (p: Address, t: Terms, amount: bigint, h: bigint, f: bigint, req = requirements(t)) => {
    const tx = await signedByServer(await refundInstruction(stored(p), amount, h, f));
    return facilitator.settle(body(req, refundPayload(p, tx, amount, h, f)));
  };
  /**
   * Classic SPL Token `Transfer` (tag 3), used only to move server liquidity for the
   * refund-liquidity case; it is setup, not the behavior under test. An unresolved attempt is
   * never blindly resent: the driver waits until its blockhash can no longer land, reads the
   * finalized destination balance, and sends a new transfer only if the first did not execute.
   */
  const tokenTransfer = async (from: typeof payer, to: Address, amount: bigint) => {
    const data = new Uint8Array(9);
    data[0] = 3;
    new DataView(data.buffer).setBigUint64(1, amount, true);
    const ix = toInstruction(
      TOKEN_PROGRAM_ADDRESS,
      [
        { address: await ata(from.address, mint), signer: false, writable: true },
        { address: await ata(to, mint), signer: false, writable: true },
        { address: from.address, signer: true, writable: false },
      ],
      data,
    );
    const target = BigInt((await state(`transfer ${amount}: before`)).serverAta) + (to === server.address ? amount : -amount);
    for (let attempt = 1; attempt <= 3; attempt += 1) {
      const life = await lifetime();
      const tx = await buildTransaction({ feePayer: sponsor.address, instructions: [ix], signers: [sponsor, from], lifetime: life });
      const result = await ledger.submit(tx);
      emit("setup token transfer", { amount, attempt, result });
      if (result.kind === "submitted" && result.outcome?.status === "succeeded") {
        advanceSlot(await finalizedSlot(c, getSignatureFromTransaction(tx)));
        return;
      }
      for (;;) {
        const expiry = await ledger.isBlockhashValid(life.blockhash);
        if (expiry.kind === "ok" && !expiry.valid) {
          advanceSlot(expiry.slot);
          break;
        }
        await new Promise((r) => setTimeout(r, 5_000));
      }
      if (BigInt((await state(`transfer ${amount}: after unresolved attempt ${attempt}`)).serverAta) === target) return;
    }
    check(false, `token transfer of ${amount} executed`);
  };

  const now0 = await ledger.now();
  emit("start", { clock: now0 });

  // ---- Chain A: authorize -> partial capture -> capture-and-void -> later refund (criterion 2)
  emit("CHAIN A", { steps: "authorize M=100 -> capture 30 -> capture 20 + release -> refund 15" });
  const tA: Terms = { maximum: 100n, dc: now0 + 480n, dr: now0 + 900n };
  await state("A before");
  const pA = await authorize(tA.maximum, tA.dc, tA.dr);
  let s = await state("A after authorize", pA);
  check(s.payment?.held === "100" && s.payment.refundable === "0", "A (H,F)=(100,0)");
  await succeeded("A partial capture 30", await capture(pA, tA, 30n, false, 100n, 0n));
  s = await state("A after partial capture", pA);
  check(s.payment?.held === "70" && s.payment.refundable === "30", "A (H,F)=(70,30)");

  await rejected("stale (H,F)", pA, "invalid_auth_capture_svm_unexpected_payment_state", () => capture(pA, tA, 20n, true, 100n, 0n));

  await succeeded("A capture-and-void 20", await capture(pA, tA, 20n, true, 70n, 30n));
  s = await state("A after capture-and-void", pA);
  check(s.payment?.held === "0" && s.payment.refundable === "50", "A (H,F)=(0,50)");

  await rejected("terms mismatch (Dc differs from the stored payment)", pA, "invalid_auth_capture_svm_terms_mismatch", () =>
    refund(pA, tA, 5n, 0n, 50n, requirements({ ...tA, dc: tA.dc - 10n })),
  );

  await succeeded("A later refund 15", await refund(pA, tA, 15n, 0n, 50n));
  s = await state("A after refund", pA);
  check(s.payment?.held === "0" && s.payment.refundable === "35", "A (H,F)=(0,35)");

  await rejected("unusable destination (payer token account replaced by the mint)", pA, "invalid_auth_capture_svm_accounts", async () => {
    const accounts = [
      { address: server.address, signer: true, writable: false },
      { address: pA, signer: false, writable: true },
      { address: mint, signer: false, writable: false },
      { address: await ata(server.address, mint), signer: false, writable: true },
      { address: mint, signer: false, writable: true },
      { address: TOKEN_PROGRAM_ADDRESS, signer: false, writable: false },
    ];
    const tx = await signedByServer(toInstruction(record.programId, accounts, refundData(5n, 0n, 35n)));
    return facilitator.settle(body(requirements(tA), refundPayload(pA, tx, 5n, 0n, 35n)));
  });

  // Insufficient server liquidity: leave the server ATA below a refund that F allows, then restore.
  {
    const before = await state("liquidity: server balance", pA);
    const drain = BigInt(before.serverAta) - 5n;
    check(drain > 0n, "server ATA holds more than 5 to drain", { serverAta: before.serverAta });
    await tokenTransfer(server, payer.address, drain);
    await rejected("insufficient refund liquidity (server ATA 5 < refund 20 <= F 35)", pA, "invalid_auth_capture_svm_server_insufficient_funds", () => refund(pA, tA, 20n, 0n, 35n));
    await tokenTransfer(payer, server.address, drain);
    const restored = await state("liquidity: restored", pA);
    check(restored.serverAta === before.serverAta && restored.payment?.refundable === "35", "server liquidity restored; F still 35");
  }

  // ---- Chain B: direct lifecycle void; handler failure is exercised by handler-failure.ts
  emit("CHAIN B", { steps: "authorize M=50 -> void" });
  const nowB = await ledger.now();
  const tB: Terms = { maximum: 50n, dc: nowB + 180n, dr: nowB + 360n };
  const bBefore = await state("B before");
  const pB = await authorize(tB.maximum, tB.dc, tB.dr);
  await state("B after authorize", pB);
  await succeeded("B direct lifecycle void", await voidHold(pB, tB, 50n, 0n));
  s = await state("B after void", pB);
  check(s.payment?.held === "0" && s.payment.refundable === "0" && s.payerAta === bBefore.payerAta, "B hold fully released to the payer");

  // ---- Chain D: capture at/after Dc is refused (criterion 4)
  emit("CHAIN D", { steps: "authorize M=10 -> wait Dc -> capture refused" });
  const nowD = await ledger.now();
  const tD: Terms = { maximum: 10n, dc: nowD + 45n, dr: nowD + 600n };
  const pD = await authorize(tD.maximum, tD.dc, tD.dr);
  await waitForClock(c, tD.dc, "D capture deadline");
  await rejected("capture at/after Dc", pD, "invalid_auth_capture_svm_capture_deadline_expired", () => capture(pD, tD, 5n, false, 10n, 0n));

  // ---- Chain E: refund at/after Dr is refused (criterion 4)
  emit("CHAIN E", { steps: "authorize M=10 -> capture 5 -> wait Dr -> refund refused" });
  const nowE = await ledger.now();
  const tE: Terms = { maximum: 10n, dc: nowE + 60n, dr: nowE + 75n };
  const pE = await authorize(tE.maximum, tE.dc, tE.dr);
  await succeeded("E capture 5 before Dc", await capture(pE, tE, 5n, false, 10n, 0n));
  await waitForClock(c, tE.dr, "E refund deadline");
  await rejected("refund at/after Dr", pE, "invalid_auth_capture_svm_refund_deadline_expired", () => refund(pE, tE, 1n, 5n, 5n));

  // ---- Payer reclaim is never relayed (criterion 2): /verify refuses it; the payer submits it.
  emit("RECLAIM NOT RELAYED", { payment: pD });
  {
    const accounts = reclaimAccounts({ payer: payer.address, payment: pD, mint, vault: await ata(pD, mint), payerAta: await ata(payer.address, mint) });
    const relayTx = await buildTransaction({ feePayer: sponsor.address, instructions: [toInstruction(record.programId, accounts, Uint8Array.of(Tag.reclaim))], signers: [payer], lifetime: await lifetime() });
    const v = await facilitator.verify(body(requirements(tD), { type: "reclaim", transaction: encodeTransaction(relayTx) }));
    check(!v.isValid && v.invalidReason === "invalid_auth_capture_svm_reclaim_not_relayed", "/verify refuses a relayed reclaim");
  }

  // ---- Wrong genesis and wrong program (criterion 4)
  {
    const wrong = new RpcLedger({ network: record.network.caip2, genesisHash: "11111111111111111111111111111111111111111", rpcUrl: c.rpcUrl });
    const error = await wrong.verifyGenesis().then(() => undefined, (e: Error) => e.message);
    emit("REJECTION wrong genesis", { error });
    check(error !== undefined && error.includes("genesis mismatch") && !error.includes(c.rpcUrl) && error.includes(redactRpcUrl(c.rpcUrl)), "wrong genesis refused, RPC credentials redacted");
    const req = requirements({ maximum: 10n, dc: now0 + 60n, dr: now0 + 120n });
    (req.extra as Record<string, unknown>).programId = sponsor.address;
    const v = await facilitator.verify(body(req, { transaction: "" }));
    emit("REJECTION wrong program", { invalidReason: v.invalidReason });
    check(!v.isValid && v.invalidReason === "invalid_auth_capture_svm_program_mismatch", "wrong program refused");
  }

  // ---- Payer-direct reclaim of the remaining holds (D: uncaptured; E: after a partial capture).
  for (const [label, p] of [["D", pD], ["E", pE]] as const) {
    const before = await state(`${label} before payer reclaim`, p);
    const { signature, result } = await submitReclaim({ ledger, programId: record.programId, payer, payment: p, lifetime: await lifetime() });
    emit(`${label} payer reclaim`, { signature, slot: await slotOf(c, signature), result });
    check(result.kind === "submitted" && result.outcome?.status === "succeeded", `${label} reclaim finalized`);
    advanceSlot(await finalizedSlot(c, signature));
    const after = await state(`${label} after payer reclaim`, p, BigInt(before.payment!.slot));
    check(
      after.payment?.held === "0" &&
        after.payment.refundable === before.payment?.refundable &&
        BigInt(after.payerAta) === BigInt(before.payerAta) + BigInt(before.payment!.held!) &&
        after.serverAta === before.serverAta,
      `${label}: payer recovered exactly H=${before.payment?.held}; F and the server untouched`,
    );
  }
  emit("chains: all checks passed");
}

main().catch((error) => {
  console.error(error instanceof Error ? (error.stack ?? error.message) : String(error));
  process.exitCode = 1;
});
