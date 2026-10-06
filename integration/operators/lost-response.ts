// SAC-006 criteria 2/3 on Devnet: a resource app whose HTTP client really reaches the running
// facilitator (`npm run devnet`) — which co-signs, journals, broadcasts, and finalizes the
// authorize — and then drops the answer ([FAULT INJECTED]). Expected: 402, the handler never runs,
// and the record stays `authorize-pending` with no signature. Writes the record identity to
// `$SAC006_EVIDENCE_DIR/lost-response.result.json` for `run-all.sh`, which then reconciles it and
// reclaims the hold with both services stopped.
//   node --experimental-strip-types evidence/lost-response.ts      (env: see run-all.sh)
import type { AddressInfo } from "node:net";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { serve } from "@hono/node-server";
import type { Address } from "@solana/kit";
import { payForResource } from "../src/client.ts";
import { OperationStore } from "../src/operation-store.ts";
import { createResourceApp } from "../src/resource-server.ts";
import { check, context, emit, env } from "./lib.ts";

const c = await context();
const store = new OperationStore(env("SAC006_STORE_DIR"));
let handlerCalls = 0;
const lossy: typeof fetch = async (input, init) => {
  const res = await fetch(input, init);
  const body = await res.text();
  emit("[FAULT INJECTED] facilitator answer dropped", { httpStatus: res.status, droppedAnswer: JSON.parse(body) });
  throw new Error("socket hang up (injected)");
};
const app = createResourceApp({
  facilitatorUrl: env("SAC006_FACILITATOR_URL"),
  bearerToken: env("SAC006_BEARER_TOKEN"),
  network: c.record.network.caip2,
  programId: c.record.programId,
  feePayer: c.sponsor.address,
  server: c.server,
  asset: c.mint,
  amount: BigInt(env("SAC006_AUTHORIZE_AMOUNT")),
  captureDeadlineSeconds: 60,
  refundDeadlineSeconds: 600,
  store,
  getLatestBlockhash: () => c.ledger.latestBlockhash(),
  now: () => c.ledger.now(),
  handler: async () => {
    handlerCalls += 1;
    return { ok: true, amount: 1n, releaseRemainder: true };
  },
  fetchImpl: lossy,
});
const server = await new Promise<ReturnType<typeof serve>>((resolve) => {
  const s = serve({ fetch: app.fetch, port: 0, hostname: "127.0.0.1" }, () => resolve(s));
});
const result = await payForResource({
  resourceUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}/resource`,
  policy: {
    network: c.record.network.caip2,
    programId: c.record.programId,
    payTo: c.server.address,
    asset: c.mint,
    maxAmount: BigInt(env("SAC006_AUTHORIZE_AMOUNT")),
    maxCaptureWindowSeconds: 300,
    feePayer: c.sponsor.address,
  },
  payer: c.payer,
  now: () => c.ledger.now(),
  latestBlockhash: () => c.ledger.latestBlockhash(),
});
server.close();
emit("client", { status: result.status, paymentResponse: result.paymentResponse, handlerCalls });
check(result.status === 402 && handlerCalls === 0, "402 and the handler never ran");
const record = store.unresolved().find((r) => r.note?.includes("injected"));
check(record?.status === "authorize-pending" && record.authorize?.signature === "", "record authorize-pending with no signature (the receipt was lost)");
const identity = { fingerprint: record!.fingerprint, payment: record!.authorize!.payment as Address, captureDeadline: result.offer.captureDeadline.toString() };
emit("lost-response record", identity);
writeFileSync(join(env("SAC006_EVIDENCE_DIR"), "lost-response.result.json"), JSON.stringify(identity, null, 2));
