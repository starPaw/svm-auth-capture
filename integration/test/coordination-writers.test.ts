// Ordinary writers execute accepted SBF under a complete disposable domain. No live network.
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { fork, type ChildProcess } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { serve, type ServerType } from "@hono/node-server";
import type { AddressInfo } from "node:net";
import { getMintToInstruction } from "@solana-program/token";
import { getBase64Encoder, getTransactionDecoder, partiallySignTransaction, type Address } from "@solana/kit";
import { enrollRecoveryDomain, type DomainPaths, type RecoveryDomain } from "../src/coordination.ts";
import { DOMAIN_ROLES } from "../src/coordination-schema.ts";
import { Facilitator } from "../src/facilitator.ts";
import { createApp } from "../src/app.ts";
import { createRestaurantApp, RestaurantOrders, DEMO_BUDGET, type RestaurantConfig } from "../src/restaurant.ts";
import { OperationStore } from "../src/operation-store.ts";
import { FileSubmissionJournal } from "../src/submission-journal.ts";
import { createResourceApp } from "../src/resource-server.ts";
import { demoSponsorComputeBounds } from "../src/demo-compute.ts";
import { decodeHeader, encodeHeader, type PaymentRequired } from "../src/http-transport.ts";
import { encodeTransaction } from "../src/transactions.ts";
import { submitReclaim } from "../src/reclaim.ts";
import { createHarness, NOW, type Harness } from "./fixture.ts";
let h: Harness, root: string, paths: DomainPaths, domain: RecoveryDomain, c: RestaurantConfig, relay: FileSubmissionJournal, server: ServerType;
const children: ChildProcess[] = [], origin = "http://coordinated.test", merchantToken = "synthetic-coordinated-merchant-00000001";
beforeEach(async () => {
  h = await createHarness(); h.ok(await h.direct([getMintToInstruction({ mint: h.mint, token: await h.payerAta(), mintAuthority: h.setup, amount: 1_000_000_000n })]));
  root = mkdtempSync(join(realpathSync(tmpdir()), "coordinated-writers-"));
  paths = Object.fromEntries(DOMAIN_ROLES.map(role => { const p = join(root,role); mkdirSync(p,{ mode:0o700 }); return [role,p]; })) as DomainPaths;
  domain = enrollRecoveryDomain(paths); relay = new FileSubmissionJournal(paths.facilitator, { coordination: domain });
  const facilitator = new Facilitator({ network: h.ledger.network, programId: h.facilitator.programId, feePayer: h.facilitatorKey, ledger: h.ledger, journal: relay, ...demoSponsorComputeBounds() });
  server = await new Promise<ServerType>(r => { const s = serve({ fetch: createApp(facilitator).fetch, port: 0, hostname: "127.0.0.1" }, () => r(s)); });
  const ledger = Object.assign(h.ledger, {
    getSignatureStatus: async (sig: string) => { const s = h.ledger.submissions.find(s => s.signature === sig); return s ? { kind: "found" as const, commitment: "finalized" as const, slot: 1n, err: s.status === "succeeded" ? null : "failed" } : { kind: "not-found" as const }; },
    getAccountAtLeast: async (a: Address) => ({ kind: "ok" as const, slot: 1n, account: await h.ledger.getAccount(a) }),
  });
  c = { merchantToken, facilitatorUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, bearerToken: "synthetic", network: h.ledger.network, programId: h.facilitator.programId, feePayer: h.facilitatorKey.address, server: h.server, asset: h.mint, amount: DEMO_BUDGET, captureDeadlineSeconds: 150, refundDeadlineSeconds: 30, store: new OperationStore(paths.operations,domain), orders: new RestaurantOrders(paths.orders,domain), reclaimJournal: new FileSubmissionJournal(paths.reclaim,{ coordination: domain }), ledger, origin, now: () => h.ledger.now(), getLatestBlockhash: async () => h.lifetime(), handler: async () => ({ ok: true, amount: 40n, releaseRemainder: true }) };
});
afterEach(async () => { for (const child of children.splice(0)) child.kill("SIGKILL"); if (server) await new Promise<void>(r => server.close(() => r())); await h.close(); rmSync(root,{ recursive:true, force:true }); });
const sign = async (unsigned: string) => encodeTransaction(await partiallySignTransaction([h.payer.keyPair], getTransactionDecoder().decode(getBase64Encoder().encode(unsigned))));
async function order() {
  const app = createRestaurantApp(c);
  const r = await app.request(`${origin}/api/orders`, { method:"POST", headers:{ origin, "content-type":"application/json" }, body:JSON.stringify({ payer:h.payer.address }) });
  expect(r.status).toBe(402); const body = await r.json() as any, cookie = r.headers.get("set-cookie")!.split(";")[0]!;
  const required = decodeHeader(r.headers.get("PAYMENT-REQUIRED")!) as PaymentRequired;
  return { app, body, cookie, required };
}
async function exclusiveRefused() {
  const child = fork(resolve("test/fixtures/coordination-worker.ts"), [JSON.stringify(paths), "exclusive", "80"], { execArgv:["--experimental-strip-types"], stdio:["ignore","ignore","ignore","ipc"] }); children.push(child);
  const messages: unknown[] = [];
  await new Promise<void>((r,j) => { const timeout = setTimeout(() => j(new Error("exclusive waiter did not refuse")),4000); child.on("message", m => { messages.push(m); if (m === "refused") { clearTimeout(timeout); r(); } if (m === "entered") { clearTimeout(timeout); child.send("release"); j(new Error("exclusive entered before durable writer result")); } }); });
  expect(messages).not.toContain("entered");
}
test("restaurant → HTTP facilitator, action result, reclaim GET draft and browser payer journal retain the shared domain", async () => {
  h.ledger.beforeRead = () => { c.orders.assertAccess(); relay.assertAccess(); };
  const { app, body, cookie, required } = await order();
  h.ledger.beforeSubmit = async () => { relay.assertAccess(); await exclusiveRefused(); };
  const auth = await app.request(`${origin}/resource?order=${body.order}`, { method:"POST", headers:{ origin, cookie, "PAYMENT-SIGNATURE":encodeHeader({ x402Version:2, resource:required.resource, accepted:required.accepts[0], payload:{ transaction:await sign(body.unsigned) } }) } });
  expect(auth.status).toBe(200);
  const action = await app.request(`${origin}/api/orders/${body.order}/actions/beer`, { method:"POST", headers:{ origin, authorization:`Bearer ${merchantToken}` } }); expect(action.status).toBe(200);
  h.setTime(NOW+150n);
  const draft = await app.request(`${origin}/api/orders/${body.order}/reclaim`,{ headers:{ cookie } }); expect(draft.status).toBe(200);
  const unsigned = (await draft.json() as any).unsigned;
  const reclaim = await app.request(`${origin}/api/orders/${body.order}/reclaim`,{ method:"POST", headers:{ origin,cookie,"content-type":"application/json" },body:JSON.stringify({ transaction:await sign(unsigned) }) }); expect(reclaim.status).toBe(200);
  await domain.run("shared",async () => {
    expect(relay.list()).toHaveLength(2); expect(relay.list().every(e => e.attempts.at(-1)?.outcome?.result === "finalized-succeeded")).toBe(true);
    expect(c.orders.read(body.order).events).toHaveLength(3); expect(c.orders.busy(body.order)).toBe(false);
    expect((c.reclaimJournal as FileSubmissionJournal).list()[0]?.attempts.at(-1)?.outcome?.result).toBe("finalized-succeeded");
  });
});
test("direct payer proof/prepare/result and resource callbacks enroll without changing ordinary interfaces", async () => {
  const payment = await h.authorized(); h.setTime(NOW+100n);
  h.ledger.beforeRead = () => { relay.assertAccess(); };
  h.ledger.beforeSubmit = async () => { c.reclaimJournal.assertAccess?.(); await exclusiveRefused(); };
  const result = await submitReclaim({ ledger:h.ledger, programId:h.facilitator.programId, payer:h.payer, payment,lifetime:h.lifetime(),journal:c.reclaimJournal });
  expect(result.result).toMatchObject({ kind:"submitted", outcome:{ status:"succeeded" } });
  await domain.run("shared",async () => { expect(c.reclaimJournal.read(result.signature)?.attempts.at(-1)?.outcome?.result).toBe("finalized-succeeded"); });
  h.ledger.beforeSubmit = undefined; h.setTime(NOW);
  const config = { ...c, amount:100n, captureDeadlineSeconds:100, handler:vi.fn(async () => { c.store.assertAccess(); relay.assertAccess(); await exclusiveRefused(); return { ok:true as const, amount:40n,releaseRemainder:true }; }) };
  const app = createResourceApp(config);
  const challenge = await app.request(`${origin}/resource`), required = decodeHeader(challenge.headers.get("PAYMENT-REQUIRED")!) as PaymentRequired;
  const tx = await h.signedAuthorize({ salt:h.newSalt(), dc:BigInt(required.accepts[0]!.extra!.captureDeadline as number), dr:BigInt(required.accepts[0]!.extra!.refundDeadline as number) });
  const r = await app.request(`${origin}/resource`,{ headers:{ "PAYMENT-SIGNATURE":encodeHeader({ x402Version:2, resource:required.resource,accepted:required.accepts[0],payload:{ transaction:encodeTransaction(tx) } }) } });
  expect(r.status).toBe(200); expect(config.handler).toHaveBeenCalledTimes(1);
  await domain.run("shared",async () => { expect(c.store.list()[0]?.status).toBe("completed"); });
});
test("unconfigured/legacy journal refuses before payer effect-capable reads or signing", async () => {
  const journal = new FileSubmissionJournal(paths.reclaim), read = vi.spyOn(h.ledger,"getAccount"), simulate = vi.spyOn(h.ledger,"simulate"), submit = vi.spyOn(h.ledger,"submit");
  await expect(submitReclaim({ ledger:h.ledger,programId:h.facilitator.programId,payer:h.payer,payment:h.payer.address,lifetime:h.lifetime(),journal })).rejects.toThrow();
  for (const trap of [read,simulate,submit]) expect(trap).not.toHaveBeenCalled();
});
