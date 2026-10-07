// Local HTTP → real facilitator → accepted SBF. No Devnet submissions or mocked payment engine.
import { mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getBase64Encoder, getTransactionDecoder, partiallySignTransaction, type Address } from "@solana/kit";
import { getMintToInstruction } from "@solana-program/token";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { demoSponsorComputeBounds } from "../src/demo-compute.js";
import { createRestaurantApp, DEMO_BUDGET, DEMO_UNIT, RestaurantOrders, type RestaurantConfig } from "../src/restaurant.js";
import { createPresentationApp } from "../src/restaurant-server.js";
import { OperationStore } from "../src/operation-store.js";
import { FileSubmissionJournal } from "../src/submission-journal.js";
import { encodeTransaction } from "../src/transactions.js";
import { decodeHeader, encodeHeader, type PaymentRequired } from "../src/http-transport.js";
import { createHarness, type Harness, NOW, inspect } from "./fixture.js";
import type { Hono } from "hono";
let h: Harness, c: RestaurantConfig, app: Hono, dir: string;
const merchantToken = "local-merchant-test-credential-0123456789";
const origin = "http://restaurant.test";
type Session = { id: string; cookie: string; required: PaymentRequired; unsigned: string };
beforeEach(async () => {
  h = await createHarness(demoSponsorComputeBounds());
  h.ok(await h.direct([getMintToInstruction({ mint: h.mint, token: await h.payerAta(), mintAuthority: h.setup, amount: 1_000_000_000n })]));
  dir = mkdtempSync(join(tmpdir(), "capture402-restaurant-"));
  const ledger = Object.assign(h.ledger, {
    getSignatureStatus: async (signature: string) => {
      const s = h.ledger.submissions.find(s => s.signature === signature);
      return s && s.status !== "unknown" ? { kind: "found" as const, commitment: "finalized" as const, slot: 1n, err: s.status === "failed" ? "failed" : null } : { kind: "not-found" as const };
    },
    getAccountAtLeast: async (address: Address) => ({ kind: "ok" as const, slot: 1n, account: await h.ledger.getAccount(address) }),
  });
  c = { merchantToken, facilitatorUrl: h.url, bearerToken: "local-only-test", network: h.ledger.network, programId: h.facilitator.programId, feePayer: h.facilitatorKey.address, server: h.server, asset: h.mint, amount: DEMO_BUDGET, captureDeadlineSeconds: 150, refundDeadlineSeconds: 30, store: new OperationStore(join(dir, "legacy")), orders: new RestaurantOrders(join(dir, "orders")), reclaimJournal: new FileSubmissionJournal(join(dir, "reclaim")), ledger, origin, now: () => h.ledger.now(), getLatestBlockhash: async () => h.lifetime(), handler: async () => { throw new Error("unused legacy one-shot handler"); } };
  app = createRestaurantApp(c);
});
afterEach(async () => { await h.close(); });
async function offer(scenario = "normal"): Promise<Session> {
  const r = await app.request(`${origin}/resource?payer=${h.payer.address}&scenario=${scenario}`);
  expect(r.status).toBe(402);
  const required = decodeHeader(r.headers.get("PAYMENT-REQUIRED")!) as PaymentRequired;
  expect(required.accepts[0]!.amount).toBe("100000000");
  const b = await r.json() as any;
  return { id: b.order, unsigned: b.unsigned, required, cookie: r.headers.get("set-cookie")!.split(";")[0]! };
}
async function sign(unsigned: string, signer = h.payer) {
  return encodeTransaction(await partiallySignTransaction([signer.keyPair], getTransactionDecoder().decode(getBase64Encoder().encode(unsigned))));
}
async function authorize(s: Session) {
  return app.request(`${origin}/resource?order=${s.id}`, { method: "POST", headers: { cookie: s.cookie, origin, "PAYMENT-SIGNATURE": encodeHeader({ x402Version: 2, resource: s.required.resource, accepted: s.required.accepts[0], payload: { transaction: await sign(s.unsigned) } }) } });
}
const view = async (s: Session) => (await (await app.request(`${origin}/api/orders/${s.id}`, { headers: { cookie: s.cookie } })).json()) as any;
const action = (s: Session, a: string) => app.request(`${origin}/api/orders/${s.id}/actions/${a}`, { method: "POST", headers: { authorization: `Bearer ${merchantToken}`, origin } });
async function expectAction(s: Session, a: string) {
  const r = await action(s, a); const body = await r.json() as any;
  expect(body, JSON.stringify(body)).toMatchObject({ receipt: { success: true } }); expect(r.status).toBe(200);
  expect(decodeHeader(r.headers.get("PAYMENT-RESPONSE")!)).toMatchObject({ success: true, transaction: body.receipt.transaction });
}
describe("merchant application authority", () => {
  test.each(["beer", "salmon", "finish", "void", "refund"])("payer session cannot request %s or reach merchant signing", async a => {
    const s = await offer("refund"); await authorize(s);
    // A refundable balance makes refund meaningful; all refusals must occur before eligibility.
    await expectAction(s, "beer");
    const disk = readFileSync(c.orders.path(s.id), "utf8");
    const files = readdirSync(join(dir, "orders")).sort();
    const submitted = h.ledger.submissions.length, simulated = h.ledger.simulated.length;
    const sign = vi.fn(c.server.signTransactions);
    app = createRestaurantApp({ ...c, server: { ...c.server, signTransactions: sign } });
    for (const token of [undefined, "incorrect", merchantToken.slice(0, -1) + "X", c.bearerToken, s.cookie.split("=")[1]]) {
      const headers: Record<string, string> = { cookie: s.cookie, origin, "content-type": "application/json" };
      if (token) headers.authorization = `Bearer ${token}`;
      const r = await app.request(`${origin}/api/orders/${s.id}/actions/${a}`, {
        method: "POST", headers, body: JSON.stringify({ role: "merchant", merchant: true }),
      });
      expect(r.status).toBe(401);
    }
    expect(sign).not.toHaveBeenCalled();
    expect(h.ledger.submissions).toHaveLength(submitted);
    expect(h.ledger.simulated).toHaveLength(simulated);
    expect(readFileSync(c.orders.path(s.id), "utf8")).toBe(disk);
    expect(readdirSync(join(dir, "orders")).sort()).toEqual(files);
    expect(c.orders.busy(s.id)).toBe(false);
  });
  test("missing configuration fails closed, including across restart", async () => {
    const s = await offer(); await authorize(s);
    for (const a of ["beer", "salmon", "finish", "void", "refund"]) {
      app = createRestaurantApp({ ...c, merchantToken: undefined, orders: new RestaurantOrders(join(dir, "orders")) });
      expect((await action(s, a)).status).toBe(503);
      expect(c.orders.attempted(s.id, a as any)).toBe(false);
    }
    expect(h.ledger.submissions).toHaveLength(1);
    expect(c.orders.busy(s.id)).toBe(false);
  });
  test("merchant authentication precedes order lookup and survives restart", async () => {
    expect((await app.request(`${origin}/api/orders/missing/actions/beer`, { method: "POST", headers: { origin } })).status).toBe(401);
    const s = await offer(); await authorize(s);
    app = createRestaurantApp({ ...c, orders: new RestaurantOrders(join(dir, "orders")) });
    await expectAction(s, "beer"); // Merchant request intentionally carries no payer cookie.
    const wrongOrigin = await app.request(`${origin}/api/orders/${s.id}/actions/void`, {
      method: "POST", headers: { authorization: `Bearer ${merchantToken}`, origin: "https://foreign.example" },
    });
    expect(wrongOrigin.status).toBe(403);
    expect(h.ledger.submissions).toHaveLength(2);
    for (const path of [`/api/orders/${s.id}`, `/api/orders/${s.id}/reclaim`]) {
      expect((await app.request(origin + path, { headers: { authorization: `Bearer ${merchantToken}` } })).status).toBe(409);
    }
  });
  test("empty, short and reused facilitator credentials are rejected", () => {
    for (const token of ["", "short", "x".repeat(31), " " + merchantToken, merchantToken + "\n"]) {
      expect(() => createRestaurantApp({ ...c, merchantToken: token })).toThrow("merchant token");
    }
    expect(() => createRestaurantApp({ ...c, bearerToken: merchantToken })).toThrow("merchant token");
  });
});
describe("restaurant budget lifecycle", () => {
  test("402 → signed authorize → menu handler → 40 → 25 → void remaining 35 with exact token deltas and finalized signatures", async () => {
    const before = h.tokens(await h.payerAta()); const s = await offer();
    const r = await authorize(s); expect(r.status).toBe(200); expect(decodeHeader(r.headers.get("PAYMENT-RESPONSE")!)).toMatchObject({ success: true });
    let v = await view(s); const p = v.payment as Address;
    expect(h.state(p)).toMatchObject({ held: 100n * DEMO_UNIT, refundable: 0n });
    await expectAction(s, "beer"); expect(h.state(p)).toMatchObject({ held: 60n * DEMO_UNIT, refundable: 40n * DEMO_UNIT });
    await expectAction(s, "salmon"); expect(h.state(p)).toMatchObject({ held: 35n * DEMO_UNIT, refundable: 65n * DEMO_UNIT });
    await expectAction(s, "finish"); expect(h.state(p)).toMatchObject({ held: 0n, refundable: 65n * DEMO_UNIT });
    v = await view(s); expect(v).toMatchObject({ status: "closed", authorized: 100, captured: 65, remaining: 0, refunded: 0, released: 35 });
    expect(h.tokens(await h.payerAta())).toBe(before - 65n * DEMO_UNIT); expect(h.tokens(await h.serverAta())).toBe(65n * DEMO_UNIT);
    expect(v.events.map((e: any) => [e.action,e.status,e.chainStatus.commitment])).toEqual(["authorize","beer","salmon","finish"].map(a => [a,"finalized","finalized"]));
    expect(h.ledger.submissions).toHaveLength(4); expect(inspect(h.ledger.submissions[3]!.transaction).data[0]).toBe(3); // existing void opcode
    const restored = createRestaurantApp({ ...c, orders: new RestaurantOrders(join(dir, "orders")) });
    expect((await restored.request(`${origin}/api/orders/${s.id}`, { headers: { cookie: s.cookie } })).status).toBe(200);
    expect((await action(s, "beer")).status).toBe(409); expect(h.ledger.submissions).toHaveLength(4);
    const publicWire = JSON.stringify(v); expect(publicWire).not.toContain("transactionBase64"); expect(publicWire).not.toContain("capabilityHash"); expect(publicWire).not.toContain(merchantToken);
  });
  test("expired never-submitted draft can be replaced by an explicit fresh offer without touching old evidence or submitting", async () => {
    const first = await offer(); const original = readFileSync(c.orders.path(first.id),"utf8");
    h.setTime(NOW + 300n);
    const r = await app.request(`${origin}/resource?payer=${h.payer.address}&scenario=normal`,{headers:{cookie:first.cookie}});
    expect(r.status).toBe(402); const next = await r.json() as any;
    expect(next.order).not.toBe(first.id);expect(next.unsigned).not.toBe(first.unsigned);
    expect(next.required.accepts[0].extra.captureDeadline).toBe(Number(NOW+450n));
    expect(readFileSync(c.orders.path(first.id),"utf8")).toBe(original);
    expect(h.ledger.submissions).toHaveLength(0);
  });
  test("refund 40 uses merchant authority and finish releases 60; payer recovers all tokens", async () => {
    const before = h.tokens(await h.payerAta()); const s = await offer("refund"); expect((await authorize(s)).status).toBe(200);
    await expectAction(s,"beer"); await expectAction(s,"refund");
    expect(h.state((await view(s)).payment)).toMatchObject({ held: 60n * DEMO_UNIT, refundable: 0n });
    await expectAction(s,"finish"); expect(await view(s)).toMatchObject({ captured: 40, refunded: 40, released: 60, remaining: 0 });
    expect(h.tokens(await h.payerAta())).toBe(before); expect(h.tokens(await h.serverAta())).toBe(0n);
    expect(inspect(h.ledger.submissions[2]!.transaction).signers).toContain(h.server.address);
  });
  test("cancelled order void releases 100 and cannot capture", async () => {
    const before = h.tokens(await h.payerAta()); const s = await offer("cancelled"); await authorize(s);
    expect((await action(s,"beer")).status).toBe(409); await expectAction(s,"void");
    expect(await view(s)).toMatchObject({ captured: 0, released: 100, remaining: 0 }); expect(h.tokens(await h.payerAta())).toBe(before);
    expect(h.ledger.submissions).toHaveLength(2);
  });
  test("unavailable merchant: deadline enforced; payer alone signs direct reclaim without facilitator", async () => {
    const before = h.tokens(await h.payerAta()); const s = await offer("unavailable"); await authorize(s);
    expect((await action(s,"beer")).status).toBe(409);
    const prepare = () => app.request(`${origin}/api/orders/${s.id}/reclaim`, { headers: { cookie: s.cookie } });
    expect((await prepare()).status).toBe(409); h.setTime(NOW + 150n);
    c.getLatestBlockhash = async () => ({ ...h.lifetime(), blockhashSlot: 1n });
    const r = await prepare(); expect(r.status).toBe(200); const { unsigned } = await r.json() as any;
    c.facilitatorUrl = "http://127.0.0.1:1";
    const result = await app.request(`${origin}/api/orders/${s.id}/reclaim`, { method:"POST", headers: { cookie:s.cookie, origin, "content-type":"application/json" }, body: JSON.stringify({ transaction: await sign(unsigned) }) });
    expect(result.status).toBe(200); expect(await view(s)).toMatchObject({ released:100,remaining:0 });
    expect(inspect(h.ledger.submissions[1]!.transaction).signers).toEqual([h.payer.address]); expect(h.tokens(await h.payerAta())).toBe(before);
    expect(readdirSync(join(dir,"reclaim")).some(f => f.endsWith(".json"))).toBe(true);
    const submitted = h.ledger.submissions[1]!;
    expect(c.reclaimJournal.read(submitted.signature)).toMatchObject({
      transactionBase64: encodeTransaction(submitted.transaction), blockhashSlot: "1",
      lastValidBlockHeight: h.lifetime().lastValidBlockHeight.toString(),
      blockhash: h.lifetime().blockhash,
    });
  });
  test("payer signature, capability and origin enforced before broadcast", async () => {
    const s = await offer();
    expect((await app.request(`${origin}/api/orders/${s.id}`)).status).toBe(409);
    expect((await app.request(`${origin}/api/orders/${s.id}/actions/beer`, { method:"POST", headers:{ cookie:s.cookie,origin:"https://foreign.example" } })).status).toBe(403);
    const forged = await app.request(`${origin}/resource?order=${s.id}`, { method:"POST", headers:{ cookie:s.cookie,origin,"PAYMENT-SIGNATURE":encodeHeader({ x402Version:2,resource:s.required.resource,accepted:s.required.accepts[0],payload:{transaction:s.unsigned} }) } });
    expect(forged.status).not.toBe(200); expect(h.ledger.submissions).toHaveLength(0); expect(c.orders.busy(s.id)).toBe(false);
    expect((await authorize(s)).status).toBe(200);
  });
  test("wrong menu order does not burn consent; concurrent duplicate captures execute once", async () => {
    const s = await offer(); await authorize(s);
    expect((await action(s,"salmon")).status).toBe(409); expect(c.orders.attempted(s.id,"salmon")).toBe(false);
    const results = await Promise.all([action(s,"beer"),action(s,"beer")]); expect(results.map(r=>r.status).sort()).toEqual([200,409]);
    expect(h.ledger.submissions).toHaveLength(2); await expectAction(s,"salmon");
  });
  test("lost finalized response freezes all new consent and retains original transaction bytes across restart", async () => {
    const s = await offer(); await authorize(s); h.ledger.failSubmit = "after-landing";
    expect((await action(s,"beer")).status).toBe(409); expect(await view(s)).toMatchObject({ status:"pending",remaining:60 });
    const record = JSON.parse(readFileSync(c.orders.path(s.id),"utf8")); expect(record.events[1].transactionBase64.length).toBeGreaterThan(0);
    app = createRestaurantApp({ ...c, orders: new RestaurantOrders(join(dir,"orders")) });
    expect((await action(s,"salmon")).status).toBe(409); expect((await action(s,"void")).status).toBe(409); expect(h.ledger.submissions).toHaveLength(2);
  });
  test("provider diagnostics and large request bodies never expose private configuration", async () => {
    const s = await offer(); await authorize(s); h.ledger.failSubmit = "after-landing";
    await action(s,"beer");
    const original = c.ledger.getSignatureStatus;
    c.ledger.getSignatureStatus = async signature => signature === h.ledger.submissions[1]!.signature ? { kind:"unavailable",detail:"https://private-provider.invalid/SECRET_RPC_PATH?api-key=PRIVATE" } : original(signature);
    const v = await view(s); expect(JSON.stringify(v)).not.toContain("SECRET_RPC_PATH");
    c.ledger.getSignatureStatus = async () => { throw new Error("https://private-provider.invalid/SECRET_RPC_PATH"); };
    const r = await app.request(`${origin}/api/orders/${s.id}`,{headers:{cookie:s.cookie}});
    expect(r.status).toBe(409); expect(await r.text()).not.toContain("SECRET_RPC_PATH");
    const oversized = await app.request(`${origin}/api/orders/${s.id}/reclaim`,{method:"POST",headers:{cookie:s.cookie,origin},body:"x".repeat(32769)});
    expect(oversized.status).toBe(413); expect(h.ledger.submissions).toHaveLength(2);
  });
  test("unprovisioned presentation is available, honest and excludes private configuration", async () => {
    const ui = createPresentationApp({ programId:h.facilitator.programId,network:h.ledger.network,configured:false });
    for (const route of ["/","/customer","/merchant","/assets/app.js","/assets/wallet.js","/assets/style.css","/assets/solflare.js","/assets/solflare.js.LEGAL.txt"]) expect((await ui.request(route)).status).toBe(200);
    const info = await (await ui.request("/api/config")).json(); expect(info).toMatchObject({ configured:false,budget:100,cluster:"devnet",walletChain:"solana:devnet",timing:{captureSeconds:150,refundSecondsAfterCapture:30} });
    expect(JSON.stringify(info)).not.toContain(c.bearerToken); expect((await ui.request("/resource")).status).toBe(503);
    expect(h.ledger.submissions).toHaveLength(0);
  });
});
