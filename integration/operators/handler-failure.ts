// Real HTTP handler failure -> server-signed void, using the accepted Devnet deployment.
// No fault is injected into the ledger: only the protected handler deliberately throws.
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { serve } from "@hono/node-server";
import type { AddressInfo } from "node:net";
import type { Address } from "@solana/kit";
import { payForResource } from "../src/client.ts";
import { Facilitator } from "../src/facilitator.ts";
import { createGatewayApp } from "../src/gateway.ts";
import { OperationStore } from "../src/operation-store.ts";
import { reconcileEntry } from "../src/reconciliation.ts";
import { createResourceApp } from "../src/resource-server.ts";
import { SponsorshipGuard } from "../src/sponsorship.ts";
import { FileSubmissionJournal } from "../src/submission-journal.ts";
import { check, context, emit, finalizedSlot, snapshot } from "./lib.ts";

export async function runHandlerFailure(c: Awaited<ReturnType<typeof context>>, outDir: string): Promise<void> {
  const { ledger, record, sponsor, payer, server, mint } = c;
  const journal = new FileSubmissionJournal(join(outDir, "handler-failure-facilitator-journal"));
  const store = new OperationStore(join(outDir, "handler-failure-operation-store"));
  const bearerToken = crypto.randomUUID();
  const facilitator = new Facilitator({ network: record.network.caip2, programId: record.programId, feePayer: sponsor, ledger, journal, observationKey: bearerToken });
  const gateway = createGatewayApp(facilitator, {
    bearerToken,
    sponsorship: new SponsorshipGuard({ ledger, feePayer: sponsor.address, maxAttempts: 2, minLamportsBalance: 10_000_000n }),
    allowlist: { merchant: server.address, mint },
  });
  const gatewayListener = await new Promise<ReturnType<typeof serve>>((resolve) => {
    const s = serve({ fetch: gateway.fetch, hostname: "127.0.0.1", port: 0 }, () => resolve(s));
  });
  try {
    let handlerCalls = 0;
    const resource = createResourceApp({
      facilitatorUrl: `http://127.0.0.1:${(gatewayListener.address() as AddressInfo).port}`,
      bearerToken,
      network: record.network.caip2,
      programId: record.programId,
      feePayer: sponsor.address,
      server,
      asset: mint,
      amount: 10n,
      captureDeadlineSeconds: 600,
      refundDeadlineSeconds: 600,
      store,
      getLatestBlockhash: () => ledger.latestBlockhash(),
      now: () => ledger.now(),
      facilitatorTimeoutMs: 300_000,
      handler: async () => {
        handlerCalls += 1;
        throw new Error("intentional evidence handler failure");
      },
    });
    const listener = await new Promise<ReturnType<typeof serve>>((resolve) => {
      const s = serve({ fetch: resource.fetch, hostname: "127.0.0.1", port: 0 }, () => resolve(s));
    });
    try {
      const before = await snapshot(c, "handler failure: before");
      const response = await payForResource({
        resourceUrl: `http://127.0.0.1:${(listener.address() as AddressInfo).port}/resource`,
        policy: { network: record.network.caip2, programId: record.programId, payTo: server.address, asset: mint, feePayer: sponsor.address, maxAmount: 10n, maxCaptureWindowSeconds: 600 },
        payer,
        now: () => ledger.now(),
        latestBlockhash: () => ledger.latestBlockhash(),
      });
      emit("handler failure response", { status: response.status, body: response.body, paymentResponse: response.paymentResponse, handlerCalls });
      check(response.status === 500 && handlerCalls === 1, "the real resource handler threw exactly once; no successful resource response");
      const entries = store.list();
      check(entries.length === 1, "one authorization and one resource execution recorded");
      const entry = entries[0]!;
      check(entry.status === "completed" && entry.handlerResult?.ok === false && entry.terminal?.op === "void" && entry.terminalReceipt?.success === true, "handler failure settled a void, never a capture");
      const report = await reconcileEntry(store, ledger, record.programId, entry.fingerprint);
      emit("handler failure reconciliation", { submissions: report.submissions, payment: report.payment, conclusion: report.conclusion });
      check(report.conclusion === "definitive" && report.submissions.map((s) => s.verdict).join(",") === "landed-succeeded,landed-succeeded", "authorize and void both finalized successfully");
      const after = await snapshot(c, "handler failure: after void", entry.terminal!.payment as Address, await finalizedSlot(c, entry.terminal!.signature));
      check(after.payment?.held === "0" && after.payment.refundable === "0" && after.payerAta === before.payerAta && after.serverAta === before.serverAta, "void returned the entire hold; merchant received no tokens");
      writeFileSync(join(outDir, "handler-failure-report.json"), JSON.stringify({ before, after, response, report }, (_k, v) => typeof v === "bigint" ? v.toString() : v, 2));
    } finally {
      await new Promise<void>((resolve, reject) => listener.close((error) => error ? reject(error) : resolve()));
    }
  } finally {
    await new Promise<void>((resolve, reject) => gatewayListener.close((error) => error ? reject(error) : resolve()));
  }
}

if (process.argv[1]?.endsWith("handler-failure.ts")) {
  const c = await context();
  await runHandlerFailure(c, process.env.SAC006_EVIDENCE_DIR ?? mkdtempSync(join(tmpdir(), "sac006-handler-failure-")));
}
