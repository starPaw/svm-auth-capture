// SAC-006 criterion 3 on Devnet: controlled fault injection around the real `RpcLedger`, at the
// resource boundary, over the x402 v2 HTTP transport. `FaultyLedger` lets an armed call genuinely
// broadcast and poll to finalized, then degrades only the result handed to the facilitator:
// `lost` strips the outcome; `weak` relabels it `confirmed`. Lines tagged [FAULT INJECTED] are
// injected; everything else is NATURAL. Any deviation exits non-zero.
//   node --experimental-strip-types evidence/fault-injection.ts      (env: see run-all.sh)
import type { OriginReader } from "../src/lifetime-provenance.ts";
import { mkdirSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { serve, type ServerType } from "@hono/node-server";
import { type Address, getTransactionDecoder, type Transaction } from "@solana/kit";
import { authorizePaymentPayload, type ClientPolicy, selectOffer, signAuthorize } from "../src/client.ts";
import { Facilitator } from "../src/facilitator.ts";
import { createGatewayApp } from "../src/gateway.ts";
import { decodeHeader, encodeHeader, PAYMENT_REQUIRED_HEADER, PAYMENT_RESPONSE_HEADER, PAYMENT_SIGNATURE_HEADER, parsePaymentRequired } from "../src/http-transport.ts";
import type { Ledger, LedgerAccount, SimulationOutcome, SubmitResult } from "../src/ledger.ts";
import { fingerprint, OperationStore } from "../src/operation-store.ts";
import { submitReclaim } from "../src/reclaim.ts";
import { reconcileEntry } from "../src/reconciliation.ts";
import { createResourceApp, type HandlerResult } from "../src/resource-server.ts";
import { SponsorshipGuard } from "../src/sponsorship.ts";
import { FileSubmissionJournal } from "../src/submission-journal.ts";
import { check, context, emit, finalizedSlot, slotOf, snapshot, waitForClock } from "./lib.ts";

type Fault = "lost" | "weak";

export class FaultyLedger implements Ledger {
  readonly network: string;
  private readonly real: Ledger;
  private armed?: { fault: Fault; skip: number };
  private originalFaultResult?: SubmitResult;

  constructor(real: Ledger) {
    this.real = real;
    this.network = real.network;
  }
  /** Degrades the result of the submit() call after `skip` natural ones; one-shot. */
  arm(fault: Fault, skip = 0): void {
    this.armed = { fault, skip };
    this.originalFaultResult = undefined;
  }
  disarm(): void {
    this.armed = undefined;
  }
  now(): Promise<bigint> {
    return this.real.now();
  }
  getAccount(address: Address): Promise<LedgerAccount | null> {
    return this.real.getAccount(address);
  }
  verifyBlockhashOrigin(...args: Parameters<OriginReader["verifyBlockhashOrigin"]>) {
    if ("verifyBlockhashOrigin" in this.real) return (this.real as Ledger & OriginReader).verifyBlockhashOrigin(...args);
    return Promise.resolve({ state: "unverified" as const, reason: "lookup-unavailable" as const });
  }
  simulate(transaction: Transaction): Promise<SimulationOutcome> {
    return this.real.simulate(transaction);
  }
  async submit(transaction: Transaction): Promise<SubmitResult> {
    const armed = this.armed;
    if (!armed) return this.real.submit(transaction);
    if (armed.skip > 0) {
      armed.skip -= 1;
      return this.real.submit(transaction);
    }
    this.armed = undefined;
    const real = await this.real.submit(transaction);
    // A controlled downgrade requires proved natural finality. Never relabel unknown/failure
    // as confirmed success or continue this campaign past an ambiguous original submission.
    this.originalFaultResult = real;
    this.requireFinalizedOriginal();
    if (armed.fault === "lost") {
      emit("[FAULT INJECTED] result stripped", { realResult: real, returned: { kind: "submitted" } });
      return { kind: "submitted" };
    }
    emit("[FAULT INJECTED] commitment weakened", { realResult: real, returned: "confirmed" });
    return { kind: "submitted", outcome: { status: "succeeded", commitment: "confirmed" as "finalized" } };
  }
  /** The facilitator catches submit errors; the driver must independently stop at its boundary. */
  requireFinalizedOriginal(): void {
    const real = this.originalFaultResult;
    check(real?.kind === "submitted" && real.outcome?.status === "succeeded" && real.outcome.commitment === "finalized", "fault injection requires a real finalized success; otherwise stop for original-signature reconciliation", { realResult: real });
  }
}

async function startApp(app: { fetch: (req: Request) => Response | Promise<Response> }) {
  const s: ServerType = await new Promise((resolve) => {
    const srv = serve({ fetch: app.fetch, port: 0, hostname: "127.0.0.1" }, () => resolve(srv));
  });
  const addr = s.address();
  const url = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}`;
  return { url, close: () => new Promise<void>((resolve) => s.close(() => resolve())) };
}

async function main(): Promise<void> {
  const c = await context();
  const { record, ledger: real, sponsor, payer, server, mint } = c;
  const AMOUNT = 10n;
  const outDir = process.env.SAC006_EVIDENCE_DIR ?? mkdtempSync(join(tmpdir(), "sac006-fault-"));
  const faulty = new FaultyLedger(real);
  const journalDir = join(outDir, "fault-facilitator-journal");
  const journal = new FileSubmissionJournal(journalDir);
  const bearer = crypto.randomUUID();
  const facilitator = new Facilitator({ network: record.network.caip2, programId: record.programId, feePayer: sponsor, ledger: faulty, journal, observationKey: bearer });
  const sponsorship = new SponsorshipGuard({ ledger: real, feePayer: sponsor.address, maxAttempts: 1000, minLamportsBalance: 1n });
  const gateway = await startApp(createGatewayApp(facilitator, { bearerToken: bearer, sponsorship, allowlist: { merchant: server.address, mint } }));

  let handlerCalls = 0;
  const storeDir = (name: string) => {
    const dir = join(outDir, "fault-operation-stores", name);
    mkdirSync(dir, { recursive: true });
    return dir;
  };
  const resourceApp = (store: OperationStore) =>
    createResourceApp({
      facilitatorUrl: gateway.url,
      bearerToken: bearer,
      network: record.network.caip2,
      programId: record.programId,
      feePayer: sponsor.address,
      server,
      asset: mint,
      amount: AMOUNT,
      captureDeadlineSeconds: 60,
      refundDeadlineSeconds: 600,
      store,
      getLatestBlockhash: () => real.latestBlockhash(),
      now: () => real.now(),
      handler: async (): Promise<HandlerResult> => {
        handlerCalls += 1;
        return { ok: true, amount: AMOUNT, releaseRemainder: true };
      },
      // Above this facilitator's worst case with the driver's settlement window.
      facilitatorTimeoutMs: 300_000,
    });
  const policy: ClientPolicy = { network: record.network.caip2, programId: record.programId, payTo: server.address, asset: mint, maxAmount: AMOUNT, maxCaptureWindowSeconds: 300, feePayer: sponsor.address };

  async function signedHeader(url: string): Promise<{ header: string; salt: Uint8Array; captureDeadline: bigint }> {
    const challenge = await fetch(`${url}/resource`);
    const paymentRequired = parsePaymentRequired(decodeHeader(challenge.headers.get(PAYMENT_REQUIRED_HEADER)!));
    const offer = selectOffer(paymentRequired, policy, await real.now());
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const tx = await signAuthorize(payer, offer, policy, salt, await real.latestBlockhash());
    return { header: encodeHeader(authorizePaymentPayload(paymentRequired, offer.requirements, tx)), salt, captureDeadline: offer.captureDeadline };
  }
  const send = (url: string, header: string) => fetch(`${url}/resource`, { headers: { [PAYMENT_SIGNATURE_HEADER]: header } });
  const receiptOf = (res: Response) => {
    const h = res.headers.get(PAYMENT_RESPONSE_HEADER);
    return h ? (decodeHeader(h) as { success: boolean; errorReason?: string; transaction: string }) : undefined;
  };
  const holds: { payment: Address; captureDeadline: bigint }[] = [];

  emit("STEP 1", { scenario: "lost RPC result on authorize" });
  {
    const store = new OperationStore(storeDir("1-lost-authorize"));
    const app = await startApp(resourceApp(store));
    const { header, salt, captureDeadline } = await signedHeader(app.url);
    const calls = handlerCalls;
    faulty.arm("lost");
    const res = await send(app.url, header);
    faulty.requireFinalizedOriginal();
    const receipt = receiptOf(res);
    emit("response", { status: res.status, paymentResponse: receipt });
    check(res.status === 402 && receipt?.errorReason === "settlement_pending", "402 with a settlement_pending PAYMENT-RESPONSE");
    check(handlerCalls === calls, "handler never started");
    const rec = store.read(fingerprint(payer.address, "/resource", salt))!;
    check(rec.status === "authorize-pending" && rec.authorize!.signature === receipt!.transaction && rec.authorize!.signature !== "", "authorize-pending with the pending receipt's signature journaled");
    check(journal.read(rec.authorize!.signature)?.attempts.at(-1)?.outcome?.result === "unresolved", "facilitator journal prepared before broadcast; attempt recorded unresolved");
    const report = await reconcileEntry(store, real, record.programId, rec.fingerprint);
    emit("NATURAL reconcile", { conclusion: report.conclusion, submissions: report.submissions, payment: report.payment });
    check(report.submissions[0]?.verdict === "landed-succeeded" && report.payment?.kind === "ok" && report.payment.exists, "the authorize really finalized; the hold exists");
    holds.push({ payment: rec.authorize!.payment as Address, captureDeadline });

    emit("STEP 2", { scenario: "NATURAL re-send of the journaled co-signed authorize bytes" });
    const entry = journal.read(rec.authorize!.signature)!;
    const again = await real.submit(getTransactionDecoder().decode(Buffer.from(entry.transactionBase64, "base64")));
    emit("NATURAL RpcLedger.submit(identical bytes)", { result: again });
    check(again.kind === "submitted", "a refusal of already-landed bytes is never classified not-submitted");
    await app.close();
  }

  emit("STEP 3", { scenario: "weaker commitment on authorize" });
  {
    const store = new OperationStore(storeDir("3-weak-authorize"));
    const app = await startApp(resourceApp(store));
    const { header, salt, captureDeadline } = await signedHeader(app.url);
    const calls = handlerCalls;
    faulty.arm("weak");
    const res = await send(app.url, header);
    faulty.requireFinalizedOriginal();
    emit("response", { status: res.status, paymentResponse: receiptOf(res) });
    check(res.status === 402 && receiptOf(res)?.errorReason === "settlement_pending", "confirmed-only is reported settlement_pending");
    check(handlerCalls === calls, "handler never started");
    const rec = store.read(fingerprint(payer.address, "/resource", salt))!;
    check(rec.status === "authorize-pending", "authorize-pending");
    holds.push({ payment: rec.authorize!.payment as Address, captureDeadline });
    await app.close();
  }

  emit("STEP 4", { scenario: "concurrent identical requests" });
  {
    const store = new OperationStore(storeDir("4-concurrent"));
    const app = await startApp(resourceApp(store));
    const { header } = await signedHeader(app.url);
    const calls = handlerCalls;
    const statuses = (await Promise.all([send(app.url, header), send(app.url, header), send(app.url, header)])).map((r) => r.status).sort();
    emit("NATURAL statuses", { statuses });
    check(statuses.join(",") === "200,409,409", "exactly one 200, the rest 409");
    check(handlerCalls === calls + 1, "handler ran exactly once");
    await app.close();
  }

  emit("STEP 5", { scenario: "restart on the same store directory" });
  {
    const dir = storeDir("5-restart");
    const a = await startApp(resourceApp(new OperationStore(dir)));
    const { header } = await signedHeader(a.url);
    const calls = handlerCalls;
    const first = await send(a.url, header);
    await a.close();
    const b = await startApp(resourceApp(new OperationStore(dir)));
    const replay = await send(b.url, header);
    emit("NATURAL statuses", { first: first.status, replayAfterRestart: replay.status });
    check(first.status === 200 && replay.status === 409, "first 200, replay after restart 409");
    check(handlerCalls === calls + 1, "handler ran exactly once across the restart");
    check(new OperationStore(dir).unresolved().length === 0, "nothing unresolved to resume");
    await b.close();
  }

  emit("STEP 6", { scenario: "lost RPC result on the terminal capture" });
  {
    const store = new OperationStore(storeDir("6-lost-capture"));
    const app = await startApp(resourceApp(store));
    // Any naturally unresolved authorization stops this scenario. Never create fresh consent
    // to get past an unknown outcome; retain its original journal for manual reconciliation.
    const signed = await signedHeader(app.url);
    const salt = signed.salt;
    faulty.arm("lost", 1);
    const res = await send(app.url, signed.header);
    faulty.requireFinalizedOriginal();
    check(res.status !== 402, "authorize finalized naturally before injecting the capture fault; otherwise stop");
    const calls = handlerCalls;
    const receipt = receiptOf(res!);
    const body = (await res!.json()) as { ok?: boolean };
    emit("response", { status: res!.status, paymentResponse: receipt, body });
    check(res!.status === 500 && receipt?.success === false && receipt.errorReason === "settlement_pending" && body.ok === undefined, "500 with a pending PAYMENT-RESPONSE and no resource body");
    check(handlerCalls === calls, "no further handler run after the response");
    const rec = store.read(fingerprint(payer.address, "/resource", salt))!;
    check(rec.handlerResult?.ok === true, "the handler ran once, before the terminal settle");
    check(rec.status === "terminal-pending" && rec.terminal!.signature === receipt!.transaction, "terminal-pending with the capture signature journaled");
    check(store.unresolved().some((r) => r.fingerprint === rec.fingerprint), "listed by unresolved()");
    const report = await reconcileEntry(store, real, record.programId, rec.fingerprint);
    emit("NATURAL reconcile", { conclusion: report.conclusion, submissions: report.submissions, payment: report.payment });
    check(report.submissions.map((s) => s.verdict).join(",") === "landed-succeeded,landed-succeeded", "both original transactions finalized");
    check(report.payment?.kind === "ok" && report.payment.exists && report.payment.held === "0", "payment at a finalized slot >= the capture shows H=0");

    const stored = await snapshot(c, "step 6 payment", rec.terminal!.payment as Address, await finalizedSlot(c, rec.terminal!.signature));
    const req = {
      scheme: "auth-capture",
      network: record.network.caip2,
      amount: AMOUNT.toString(),
      asset: mint,
      payTo: server.address,
      maxTimeoutSeconds: 60,
      extra: { paymentFlow: "escrow", captureDeadline: Number(stored.payment!.captureDeadline), refundDeadline: Number(stored.payment!.refundDeadline), programId: record.programId, feePayer: sponsor.address },
    };
    const t = rec.terminal!;
    const retried = (await (
      await fetch(`${gateway.url}/settle`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${bearer}` },
        body: JSON.stringify({
          x402Version: 2,
          paymentRequirements: req,
          paymentPayload: { x402Version: 2, accepted: req, payload: { type: "capture", payment: t.payment, transaction: t.transactionBase64, amount: AMOUNT.toString(), releaseRemainder: true, expectedHeld: t.expectedHeld, expectedRefundable: t.expectedRefundable } },
        }),
      })
    ).json()) as { success: boolean; errorReason?: string };
    emit("NATURAL naive retry of the journaled capture bytes", { result: retried });
    check(!retried.success && retried.errorReason === "settlement_pending", "durable reservation refused another broadcast; never a second payment");
    const after = await snapshot(c, "step 6 payment after retry", t.payment as Address, BigInt(stored.payment!.slot));
    check(after.payment?.held === stored.payment?.held && after.payment?.refundable === stored.payment?.refundable, "retry left (H,F) unchanged");
    await app.close();
  }
  await gateway.close();

  emit("CLEANUP", { scenario: "payer-direct reclaim of the holds left by steps 1 and 3" });
  for (const { payment, captureDeadline } of holds) {
    await waitForClock(c, captureDeadline, `Dc of ${payment}`);
    const before = await snapshot(c, "before reclaim", payment);
    check(before.payment?.exists === true && BigInt(before.payment.held ?? "0") > 0n, "the proven authorization hold must exist before cleanup; missing state is incomplete evidence");
    const { signature, result } = await submitReclaim({ ledger: real, programId: record.programId, payer, payment, lifetime: await real.latestBlockhash(), journal });
    emit("payer reclaim", { payment, signature, slot: await slotOf(c, signature), result });
    const after = await snapshot(c, "after reclaim", payment, await finalizedSlot(c, signature));
    check(after.payment?.held === "0" && BigInt(after.payerAta) === BigInt(before.payerAta) + BigInt(before.payment!.held!), "payer recovered exactly the hold");
  }
  emit("fault injection: all checks passed");
}

if (process.argv[1]?.endsWith("fault-injection.ts")) main().catch((error) => {
  console.error(error instanceof Error ? (error.stack ?? error.message) : String(error));
  // The failed campaign owns its ephemeral HTTP listeners; exit instead of leaving them live.
  process.exit(1);
});
