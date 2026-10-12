// Local HTTP → real facilitator → accepted SBF. No Devnet submissions or mocked payment engine.
import { mkdtempSync, readdirSync, readFileSync, writeFileSync,renameSync,existsSync,chmodSync,statSync,unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from 'node:crypto';
import { EXPIRED_A_POLICY } from '../src/authorize-abandon.ts';
import { getBase64Encoder, getTransactionDecoder, partiallySignTransaction, getSignatureFromTransaction, getCompiledTransactionMessageDecoder, getBase64EncodedWireTransaction, type Address } from "@solana/kit";
import { getMintToInstruction, getTransferInstruction } from "@solana-program/token";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { demoSponsorComputeBounds } from "../src/demo-compute.js";
import { createRestaurantApp, DEMO_BUDGET, DEMO_UNIT, RestaurantOrders, type RestaurantConfig } from "../src/restaurant.js";
import { createPresentationApp } from "../src/restaurant-server.js";
import { OperationStore } from "../src/operation-store.js";
import { FileSubmissionJournal } from "../src/submission-journal.js";
import { messageHash } from '../src/submission-journal.ts';
import { PENDING_A_ISOLATION,prepareUnknownAuthorizeIsolation,persistUnknownAuthorizeIsolation,authorizeIsolationEvidence,type IsolationPolicy } from '../src/unknown-authorize-isolation.ts';
import { createDurableFile } from "../src/durable-file.js";
import { encodeTransaction, reclaimInstruction, refundInstruction } from "../src/transactions.js";
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
    offerBlockhashValid: async (hash:string) => hash === h.lifetime().blockhash,
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
  const r = await app.request(`${origin}/api/orders`, { method: "POST", headers: { origin, "content-type": "application/json" }, body: JSON.stringify({ payer: h.payer.address, scenario }) });
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
describe('selected UNKNOWN authorize effect isolation',()=>{
  async function fixture(landed=false) {
    c.network='solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1';
    Reflect.set(c.ledger,'network',c.network);Reflect.set(h.facilitator,'network',c.network);
    c.getLatestBlockhash=async()=>({...h.lifetime(),contextSlot:1n,blockhashSlot:1n,commitment:'finalized' as const,network:c.network,genesisHash:'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG'});
    const journalDir=join(dir,'facilitator-journal'),journal=new FileSubmissionJournal(journalDir);
    Reflect.set(h.facilitator,'journal',journal);
    vi.spyOn(c.ledger,'submit').mockImplementation(async tx=>{
      if(landed)h.ok(h.svm.sendTransaction(tx));
      h.ledger.submissions.push({signature:getSignatureFromTransaction(tx),status:'unknown',transaction:tx});
      return{kind:'submitted'};
    });
    const s=await offer(),path=c.orders.path(s.id);
    const consent=JSON.stringify({unsignedSha256:createHash('sha256').update(s.unsigned).digest('hex')});
    expect((await app.request(`${origin}/api/orders/${s.id}/wallet-consent`,{method:'POST',headers:{cookie:s.cookie,origin,'content-type':'application/json'},body:consent})).status).toBe(200);
    expect((await authorize(s)).status).toBe(402);
    const order=c.orders.read(s.id),signature=order.events[0]!.transaction,journalPath=join(journalDir,`${signature}.json`),entry=JSON.parse(readFileSync(journalPath,'utf8'));
    const sha=(p:string)=>createHash('sha256').update(readFileSync(p)).digest('hex');
    const policy:IsolationPolicy={...PENDING_A_ISOLATION,order:s.id,payment:order.payment,payer:order.payer,signature,
      orderSha256:sha(path),consentSha256:sha(`${path}.wallet-consent.lock`),busySha256:sha(`${path}.busy`),actionSha256:sha(`${path}.authorize.lock`),
      journalSha256:sha(journalPath),messageHash:entry.messageHash,signedWireSha256:createHash('sha256').update(Buffer.from(entry.transactionBase64,'base64')).digest('hex')};
    h.setTime(NOW+190n);h.svm.expireBlockhash();
    c.ledger.getFinalizedBlockhashStatus=async()=>({kind:'ok',valid:false,slot:5n});
    c.ledger.getAccountAtLeast=async address=>({kind:'ok',slot:6n,account:await h.ledger.getAccount(address)});
    c.ledger.getClockAtLeast=async()=>({kind:'ok',commitment:'finalized',slot:7n,unixTimestamp:NOW+190n});
    const reader={getSignatureStatus:(signature:string)=>c.ledger.getSignatureStatus(signature),
      getAccountAtLeast:(address:Address,slot:bigint)=>c.ledger.getAccountAtLeast(address,slot),
      getFinalizedBlockhashStatus:(hash:string,slot:bigint)=>c.ledger.getFinalizedBlockhashStatus!(hash,slot),
      getClockAtLeast:(slot:bigint)=>c.ledger.getClockAtLeast!(slot,Date.now()+1000),
      findSignaturesByMessage:async()=>({kind:'ok' as const,signatures:[],truncated:false}),isBlockhashValid:async()=>({kind:'ok' as const,valid:false,slot:5n})};
    const args={policy,ordersDir:c.orders.dir,journalDirs:[journalDir,c.reclaimJournal instanceof FileSubmissionJournal?c.reclaimJournal.dir:''],programId:c.programId,server:c.server.address,mint:c.asset,funder:c.feePayer,network:c.network,reader};
    return{s,path,policy,journalPath,args,original:readFileSync(path),consent:readFileSync(`${path}.wallet-consent.lock`),busy:statSync(`${path}.busy`),prepare:()=>prepareUnknownAuthorizeIsolation(args)};
  }
  test('one new offer preserves UNKNOWN originals, reservations and exclusive successor; old operations stay locked',async()=>{
    const f=await fixture(),record=await f.prepare();
    expect(record).toMatchObject({originalOutcome:'unknown',reserveDisposition:'retained',proof:{kind:'expired-no-successful-authorize-effect'}});
    const archiveSha256=persistUnknownAuthorizeIsolation(f.policy,f.path,record);
    c.authorizeIsolationPolicy={...f.policy,archiveSha256};app=createRestaurantApp(c);
    const v=await view(f.s);expect(v).toMatchObject({status:'pending',authorizeIsolation:{originalOutcome:'unknown',reserveRetained:true}});
    expect(v.actions.beer).toBe(false);expect(c.orders.busy(f.s.id)).toBe(true);
    const prepare=()=>app.request(`${origin}/api/orders`,{method:'POST',headers:{cookie:f.s.cookie,origin,'content-type':'application/json'},body:JSON.stringify({payer:h.payer.address})});
    const results=await Promise.all([prepare(),prepare()]);expect(results.map(r=>r.status).sort()).toEqual([402,409]);
    expect(readFileSync(f.path)).toEqual(f.original);expect(readFileSync(`${f.path}.wallet-consent.lock`)).toEqual(f.consent);
    expect(statSync(`${f.path}.busy`).ino).toBe(f.busy.ino);expect(JSON.parse(readFileSync(f.journalPath,'utf8')).attempts).toHaveLength(1);
    expect(h.ledger.submissions).toHaveLength(1);expect(await h.ledger.getAccount(f.policy.payment as never)).toBeNull();
    expect((await authorize(f.s)).status).toBe(409);expect((await prepare()).status).toBe(409);
  });
  test.each(['active','unavailable','stale-account','weak-status','known-success','landed','changed-consent','duplicate-action','invalid-signature','inode-drift'])(
    'UNKNOWN isolation refuses %s without modifying originals or making a submission',async fault=>{
    const f=await fixture(fault==='landed');
    if(fault==='active')f.args.reader.getFinalizedBlockhashStatus=async()=>({kind:'ok',valid:true,slot:5n});
    if(fault==='unavailable')f.args.reader.getFinalizedBlockhashStatus=async()=>({kind:'unavailable',detail:'synthetic unavailable'}) as never;
    if(fault==='stale-account')f.args.reader.getAccountAtLeast=async address=>({kind:'ok',slot:4n,account:await h.ledger.getAccount(address)});
    if(['weak-status','known-success'].includes(fault))f.args.reader.getSignatureStatus=async()=>({kind:'found',commitment:fault==='weak-status'?'confirmed':'finalized',slot:1n,err:null}) as never;
    if(fault==='changed-consent')writeFileSync(`${f.path}.wallet-consent.lock`,'{}');
    if(fault==='duplicate-action'){const order=c.orders.read(f.s.id);order.events.push({...order.events[0]!,action:'beer'});c.orders.write(order);f.policy.orderSha256=createHash('sha256').update(readFileSync(f.path)).digest('hex');}
    if(fault==='invalid-signature'){const j=JSON.parse(readFileSync(f.journalPath,'utf8')),bytes=Buffer.from(j.transactionBase64,'base64');bytes[1]=(bytes[1]??0)^1;j.transactionBase64=bytes.toString('base64');writeFileSync(f.journalPath,JSON.stringify(j));f.policy.journalSha256=createHash('sha256').update(readFileSync(f.journalPath)).digest('hex');f.policy.signedWireSha256=createHash('sha256').update(bytes).digest('hex');}
    if(fault==='inode-drift')f.args.reader.getClockAtLeast=async()=>{const raw=readFileSync(f.path);writeFileSync(`${f.path}.swap`,raw);renameSync(`${f.path}.swap`,f.path);return{kind:'ok',commitment:'finalized',slot:7n,unixTimestamp:NOW+190n};};
    await expect(f.prepare()).rejects.toThrow();expect(existsSync(`${f.path}.authorize-isolation.lock`)).toBe(false);expect(h.ledger.submissions).toHaveLength(1);expect(c.orders.busy(f.s.id)).toBe(true);
  });
  test.each(['cloned-record','changed-proof','changed-original','changed-journal','replaced-journal'])('isolation writer rejects %s without a producer capability/custody match',async fault=>{
    const f=await fixture();let record=await f.prepare();
    if(fault==='cloned-record')record=JSON.parse(JSON.stringify(record));
    if(fault==='changed-proof')record.proof.clockSlot='999';
    if(fault==='changed-original')writeFileSync(`${f.path}.busy`,'beer');
    if(fault==='changed-journal')writeFileSync(f.journalPath,'{}');
    if(fault==='replaced-journal'){writeFileSync(`${f.journalPath}.swap`,readFileSync(f.journalPath),{mode:0o600});renameSync(`${f.journalPath}.swap`,f.journalPath);}
    expect(()=>persistUnknownAuthorizeIsolation(f.policy,f.path,record)).toThrow();expect(existsSync(`${f.path}.authorize-isolation.lock`)).toBe(false);
  });
  test('partial archive, archive digest drift and active original hash forbid a new order',async()=>{
    const f=await fixture(),record=await f.prepare(),archiveSha256=persistUnknownAuthorizeIsolation(f.policy,f.path,record);
    c.authorizeIsolationPolicy={...f.policy,archiveSha256};app=createRestaurantApp(c);
    chmodSync(`${f.path}.authorize-isolation.lock`,0o600);expect(()=>authorizeIsolationEvidence(c.authorizeIsolationPolicy,c.orders.read(f.s.id),f.path)).toThrow();
    chmodSync(`${f.path}.authorize-isolation.lock`,0o400);c.authorizeIsolationPolicy.archiveSha256='0'.repeat(64);expect(()=>authorizeIsolationEvidence(c.authorizeIsolationPolicy,c.orders.read(f.s.id),f.path)).toThrow();
    c.authorizeIsolationPolicy.archiveSha256=archiveSha256;
    f.args.reader.getFinalizedBlockhashStatus=async()=>({kind:'ok',valid:true,slot:5n});c.ledger.getFinalizedBlockhashStatus=f.args.reader.getFinalizedBlockhashStatus;
    expect((await app.request(`${origin}/api/orders`,{method:'POST',headers:{cookie:f.s.cookie,origin,'content-type':'application/json'},body:JSON.stringify({payer:h.payer.address})})).status).toBe(409);
  });
  test.each(['','.wallet-consent.lock','.busy','.authorize.lock'])('missing original custody file %s cannot be mistaken for an absent previous session',async suffix=>{
    const f=await fixture(),record=await f.prepare(),archiveSha256=persistUnknownAuthorizeIsolation(f.policy,f.path,record);
    c.authorizeIsolationPolicy={...f.policy,archiveSha256};app=createRestaurantApp(c);
    unlinkSync(`${f.path}${suffix}`); // Adversarial fixture only.
    expect((await app.request(`${origin}/api/orders`,{method:'POST',headers:{cookie:f.s.cookie,origin,'content-type':'application/json'},body:JSON.stringify({payer:h.payer.address})})).status).toBe(409);
    expect(existsSync(`${f.path}.authorize-successor.lock`)).toBe(false);expect(h.ledger.submissions).toHaveLength(1);
  });
});
test('one original signature observation is shared within a response, never across HTTP requests',async()=>{
  const s=await offer();expect((await authorize(s)).status).toBe(200);
  const lookup=vi.spyOn(c.ledger,'getSignatureStatus');
  await view(s);expect(lookup).toHaveBeenCalledTimes(1);lookup.mockClear();
  await view(s);expect(lookup).toHaveBeenCalledTimes(1);lookup.mockClear();
  expect((await app.request(`${origin}/api/orders/${s.id}/actions/beer`,{headers:{authorization:`Bearer ${merchantToken}`}})).status).toBe(200);
  expect(lookup).toHaveBeenCalledTimes(1);lookup.mockResolvedValue({kind:'not-found'});
  expect((await app.request(`${origin}/api/orders/${s.id}`,{headers:{cookie:s.cookie}})).status).toBe(409);
});
describe("read-only discovery and same-origin order preparation", () => {
  test.each(["", "?payer=invalid&scenario=invalid", "?payer=public-wallet&scenario=normal"])("GET /resource%s only discovers x402 requirements", async query => {
    const reads = vi.spyOn(c.orders, "read"), writes = vi.spyOn(c.orders, "create");
    const latest = vi.spyOn(c, "getLatestBlockhash"), simulate = vi.spyOn(c.ledger, "simulate");
    const response = await app.request(`${origin}/resource${query}`, { headers: { "sec-fetch-site": "cross-site" } });
    expect(response.status).toBe(402);
    const required = decodeHeader(response.headers.get("PAYMENT-REQUIRED")!);
    expect(required).toMatchObject({ x402Version: 2, accepts: [{ amount: "100000000" }] });
    expect(await response.json()).toEqual(required);
    expect(response.headers.get("set-cookie")).toBeNull();
    for (const call of [reads, writes, latest, simulate]) expect(call).not.toHaveBeenCalled();
    expect(readdirSync(c.orders.dir)).toEqual([]);
    expect(h.ledger.submissions).toHaveLength(0);
  });
  test.each([undefined, "null", "https://attacker.invalid", `${origin}/`, `${origin}.attacker.invalid`, `${origin}:80`, `${origin}, https://attacker.invalid`])("order preparation rejects Origin %s before side effects", async suppliedOrigin => {
    const headers: Record<string,string> = { "content-type": "application/json" };
    if (suppliedOrigin !== undefined) headers.origin = suppliedOrigin;
    const now = vi.spyOn(c, "now"), latest = vi.spyOn(c, "getLatestBlockhash"), simulate = vi.spyOn(c.ledger, "simulate");
    const response = await app.request(`${origin}/api/orders`, { method: "POST", headers, body: JSON.stringify({ payer: h.payer.address }) });
    expect(response.status).toBe(403); expect(response.headers.get("set-cookie")).toBeNull();
    for (const call of [now, latest, simulate]) expect(call).not.toHaveBeenCalled();
    expect(readdirSync(c.orders.dir)).toEqual([]); expect(h.ledger.submissions).toHaveLength(0);
  });
  test.each([
    [undefined, '{}', 415], ["text/plain", '{}', 415], ["application/x-www-form-urlencoded", 'payer=wallet', 415],
    ["application/json", '{', 400], ["application/json", 'null', 400], ["application/json", '[]', 400],
    ["application/json", '{}', 400], ["application/json", '{"payer":1}', 400],
    ["application/json", '{"payer":"invalid"}', 400],
    ["application/json", "invalid-scenario", 400], ["application/json", "extra-key", 400],
    ["application/json", "oversize", 413],
  ])("malformed preparation (%s, %s) does not issue a session", async (contentType, input, status) => {
    const headers: Record<string,string> = { origin };
    if (contentType) headers["content-type"] = contentType as string;
    const body = input === "invalid-scenario" ? JSON.stringify({ payer: h.payer.address, scenario: null }) : input === "extra-key" ? JSON.stringify({ payer: h.payer.address, order: "overwrite" }) : input === "oversize" ? "x".repeat(32_769) : input as string;
    const now = vi.spyOn(c, "now"), latest = vi.spyOn(c, "getLatestBlockhash"), simulate = vi.spyOn(c.ledger, "simulate");
    const response = await app.request(`${origin}/api/orders`, { method: "POST", headers, body });
    expect(response.status).toBe(status); expect(response.headers.get("set-cookie")).toBeNull();
    for (const call of [now, latest, simulate]) expect(call).not.toHaveBeenCalled();
    expect(readdirSync(c.orders.dir)).toEqual([]); expect(h.ledger.submissions).toHaveLength(0);
  });
  test("explicit cross-site metadata is rejected even with a claimed valid Origin", async () => {
    const response = await app.request(`${origin}/api/orders`, { method: "POST", headers: { origin, "sec-fetch-site": "cross-site", "content-type": "application/json" }, body: JSON.stringify({ payer: h.payer.address }) });
    expect(response.status).toBe(403); expect(response.headers.get("set-cookie")).toBeNull();
    expect(readdirSync(c.orders.dir)).toEqual([]); expect(h.ledger.simulated).toHaveLength(0);
  });
  test("same-origin JSON preparation issues one wallet-specific draft without broadcasting", async () => {
    const response = await app.request(`${origin}/api/orders`, { method: "POST", headers: { origin, "content-type": "application/json; charset=utf-8", "sec-fetch-site": "same-origin" }, body: JSON.stringify({ payer: h.payer.address }) });
    expect(response.status).toBe(402); const body = await response.json() as any;
    expect(body.required).toEqual(decodeHeader(response.headers.get("PAYMENT-REQUIRED")!));
    const cookie = response.headers.get("set-cookie")!;
    expect(cookie).toContain("HttpOnly"); expect(cookie).toContain("SameSite=Strict");
    expect(c.orders.read(body.order)).toMatchObject({ payer: h.payer.address, scenario: "normal", status: "draft", unsigned: body.unsigned });
    expect(readdirSync(c.orders.dir)).toHaveLength(1); expect(h.ledger.submissions).toHaveLength(0);
  });
  test("original P2-1 cross-site navigation cannot overwrite a funded session or obstruct viewing and payer-direct reclaim", async () => {
    c.origin = "https://restaurant.test"; app = createRestaurantApp(c);
    const prepare = await app.request(`${c.origin}/api/orders`, { method: "POST", headers: { origin: c.origin, "content-type": "application/json" }, body: JSON.stringify({ payer: h.payer.address, scenario: "unavailable" }) });
    const body = await prepare.json() as any;
    const existing: Session = { id: body.order, unsigned: body.unsigned, required: body.required, cookie: prepare.headers.get("set-cookie")!.split(";")[0]! };
    expect(prepare.headers.get("set-cookie")).toContain("Secure");
    expect((await app.request(`${c.origin}/resource?order=${existing.id}`, { method: "POST", headers: { origin: c.origin, cookie: existing.cookie, "PAYMENT-SIGNATURE": encodeHeader({ x402Version: 2, resource: existing.required.resource, accepted: existing.required.accepts[0], payload: { transaction: await sign(existing.unsigned) } }) } })).status).toBe(200);
    const disk = readFileSync(c.orders.path(existing.id), "utf8"), files = readdirSync(c.orders.dir).sort(), simulated = h.ledger.simulated.length;
    // SameSite=Strict omits the existing cookie on this original cross-site navigation.
    const navigation = await app.request(`${c.origin}/resource?payer=${h.payer.address}`, { headers: { "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document", referer: "https://attacker.invalid/" } });
    expect(navigation.status).toBe(402); expect(navigation.headers.get("set-cookie")).toBeNull();
    expect(await navigation.json()).not.toHaveProperty("order");
    expect(readdirSync(c.orders.dir).sort()).toEqual(files); expect(readFileSync(c.orders.path(existing.id), "utf8")).toBe(disk);
    expect(h.ledger.simulated).toHaveLength(simulated); expect(h.ledger.submissions).toHaveLength(1);
    expect(await view(existing)).toMatchObject({ remaining: 100, status: "active" });
    h.setTime(NOW + 150n);
    const reclaim = await app.request(`${c.origin}/api/orders/${existing.id}/reclaim`, { headers: { cookie: existing.cookie } });
    expect(reclaim.status).toBe(200); const { unsigned } = await reclaim.json() as any;
    c.facilitatorUrl = "http://127.0.0.1:1";
    expect((await app.request(`${c.origin}/api/orders/${existing.id}/reclaim`, { method: "POST", headers: { origin: c.origin, cookie: existing.cookie, "content-type": "application/json" }, body: JSON.stringify({ transaction: await sign(unsigned) }) })).status).toBe(200);
    expect(await view(existing)).toMatchObject({ remaining: 0, released: 100 });
    expect(inspect(h.ledger.submissions[1]!.transaction).signers).toEqual([h.payer.address]);
  });
  test.each(["active", "pending", "busy"])("a new order cannot replace an existing %s reservation across restart", async state => {
    const existing = await offer("unavailable");
    if (state === "pending") h.ledger.failSubmit = "after-landing";
    if (state === "busy") c.orders.reserve(existing.id, "authorize");
    else await authorize(existing);
    const files = readdirSync(c.orders.dir).sort(), disk = readFileSync(c.orders.path(existing.id), "utf8"), submitted = h.ledger.submissions.length;
    app = createRestaurantApp({ ...c, orders: new RestaurantOrders(c.orders.dir) });
    const response = await app.request(`${origin}/api/orders`, { method: "POST", headers: { origin, cookie: existing.cookie, "content-type": "application/json" }, body: JSON.stringify({ payer: h.payer.address }) });
    expect(response.status).toBe(409); expect(response.headers.get("set-cookie")).toBeNull();
    expect(readdirSync(c.orders.dir).sort()).toEqual(files); expect(readFileSync(c.orders.path(existing.id), "utf8")).toBe(disk);
    expect(h.ledger.submissions).toHaveLength(submitted);
  });
});
describe("merchant application authority", () => {
  test.each(["beer", "salmon", "finish", "void", "refund"])("payer session cannot request %s or reach merchant signing", async a => {
    const s = await offer("refund"); await authorize(s);
    // A refundable balance makes refund meaningful; all refusals must occur before eligibility.
    await expectAction(s, "beer");
    const disk = readFileSync(c.orders.path(s.id), "utf8");
    const files = readdirSync(join(dir, "orders")).sort();
    const submitted = h.ledger.submissions.length, simulated = h.ledger.simulated.length;
    const sign = vi.fn(c.server.signTransactions);
    for (const restarted of [false, true]) {
      const orders = restarted ? new RestaurantOrders(join(dir, "orders")) : c.orders;
      const read = vi.spyOn(orders, "read"), reserve = vi.spyOn(orders, "reserve");
      const backend = createRestaurantApp({ ...c, orders, server: { ...c.server, signTransactions: sign } });
      app = createPresentationApp({ programId: c.programId, network: c.network, configured: true }, backend);
      for (const token of [undefined, "incorrect", merchantToken.slice(0, -1) + "X", c.bearerToken, s.cookie.split("=")[1]]) {
        const headers: Record<string, string> = { cookie: s.cookie, origin, "content-type": "application/json" };
        if (token) headers.authorization = `Bearer ${token}`;
        const r = await app.request(`${origin}/api/orders/${s.id}/actions/${a}`, {
          method: "POST", headers, body: JSON.stringify({ role: "merchant", merchant: true }),
        });
        expect(r.status).toBe(401);
      }
      expect(read).not.toHaveBeenCalled();
      expect(reserve).not.toHaveBeenCalled();
      read.mockRestore(); reserve.mockRestore();
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
    const disk = readFileSync(c.orders.path(s.id), "utf8");
    const files = readdirSync(join(dir, "orders")).sort();
    const simulated = h.ledger.simulated.length;
    const sign = vi.fn(c.server.signTransactions);
    for (const a of ["beer", "salmon", "finish", "void", "refund"]) {
      app = createRestaurantApp({ ...c, merchantToken: undefined, orders: new RestaurantOrders(join(dir, "orders")), server: { ...c.server, signTransactions: sign } });
      expect((await action(s, a)).status).toBe(503);
      expect(c.orders.attempted(s.id, a as any)).toBe(false);
    }
    expect(sign).not.toHaveBeenCalled();
    expect(h.ledger.simulated).toHaveLength(simulated);
    expect(h.ledger.submissions).toHaveLength(1);
    expect(readFileSync(c.orders.path(s.id), "utf8")).toBe(disk);
    expect(readdirSync(join(dir, "orders")).sort()).toEqual(files);
    expect(c.orders.busy(s.id)).toBe(false);
  });
  test("mounted presentation and payer session never disclose merchant or facilitator credentials", async () => {
    app = createPresentationApp({ programId: c.programId, network: c.network, configured: true, sponsor: c.feePayer, merchant: c.server.address, mint: c.asset }, app);
    const s = await offer();
    const publicResponses = [JSON.stringify(s)];
    for (const route of ["/api/config", "/", "/customer", "/merchant", "/assets/app.js", "/assets/wallet.js", `/api/orders/${s.id}`]) {
      const r = await app.request(origin + route, { headers: { cookie: s.cookie } });
      expect(r.status).toBe(200);
      publicResponses.push(await r.text());
    }
    for (const body of publicResponses) {
      expect(body).not.toContain(merchantToken);
      expect(body).not.toContain(c.bearerToken);
    }
    expect(h.ledger.submissions).toHaveLength(0);
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
  test('runtime Clock requires finalized context at least the original transaction slot before merchant dispatch',async()=>{
    const s=await offer();await authorize(s);
    const clock=vi.fn(async(min:bigint)=>({kind:'ok' as const,commitment:'finalized' as const,slot:min,unixTimestamp:NOW}));
    c.ledger.getClockAtLeast=clock;expect((await view(s)).actions.beer).toBe(true);expect(clock.mock.calls[0]![0]).toBe(1n);
    c.ledger.getClockAtLeast=async()=>({kind:'ok',commitment:'finalized',slot:0n,unixTimestamp:NOW+300n});
    const response=await action(s,'beer');expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({receipt:{success:false,errorReason:'settlement_not_submitted',transaction:''}});
    expect(h.ledger.submissions).toHaveLength(1);expect(c.orders.attempted(s.id,'beer')).toBe(false);
  });
  test('atomic browser action executes existing capture release flag once and independent token deltas agree',async()=>{
    const before=h.tokens(await h.payerAta()),s=await offer('atomic');expect((await authorize(s)).status).toBe(200);
    expect((await view(s)).actions).toMatchObject({atomic:true,beer:false,salmon:false,void:false});
    await expectAction(s,'atomic');const v=await view(s);
    expect(h.state(v.payment)).toMatchObject({held:0n,refundable:40n*DEMO_UNIT});
    expect(v).toMatchObject({captured:40,released:60,remaining:0});
    expect(h.tokens(await h.payerAta())).toBe(before-40n*DEMO_UNIT);expect(h.tokens(await h.serverAta())).toBe(40n*DEMO_UNIT);
    expect(h.ledger.submissions).toHaveLength(2);
    expect(inspect(h.ledger.submissions[1]!.transaction).data[9]).toBe(1);
    expect((await action(s,'atomic')).status).toBe(409);expect(h.ledger.submissions).toHaveLength(2);
  });
  test('partial capture followed by actual deadline payer reclaim preserves F40 and returns only H60',async()=>{
    const before=h.tokens(await h.payerAta()),s=await offer('partial-reclaim');await authorize(s);await expectAction(s,'beer');
    expect(await view(s)).toMatchObject({remaining:60,refundableBaseUnits:'40000000',actions:{salmon:false,void:false,reclaim:false}});
    h.setTime(NOW+150n);const r=await app.request(`${origin}/api/orders/${s.id}/reclaim`,{headers:{cookie:s.cookie}});expect(r.status).toBe(200);
    const {unsigned}=await r.json() as any;
    const result=await app.request(`${origin}/api/orders/${s.id}/reclaim`,{method:'POST',headers:{cookie:s.cookie,origin,'content-type':'application/json'},body:JSON.stringify({transaction:await sign(unsigned)})});
    expect(result.status).toBe(200);expect(h.state((await view(s)).payment)).toMatchObject({held:0n,refundable:40n*DEMO_UNIT});
    expect(h.tokens(await h.payerAta())).toBe(before-40n*DEMO_UNIT);expect(h.tokens(await h.serverAta())).toBe(40n*DEMO_UNIT);
  });
  test('source-bound legacy recovery rejects stale provenance, retains original and survives separate reclaim preparation',async()=>{
    const s=await offer();await authorize(s);h.setTime(NOW+150n);
    const original=readFileSync(c.orders.path(s.id));const stored=c.orders.read(s.id);
    c.b3Recovery={schema:1,order:s.id,payment:stored.payment,payer:stored.payer,sourceSha:'4e570a1adc14e1c5477d4a6270df02884cd58b88',orderSha256:createHash('sha256').update(original).digest('hex'),authorizeSignature:stored.events[0]!.transaction,originalEvidenceSha256:'b'.repeat(64),classification:'source-bound-pre-dispatch-refusal',action:'beer'};
    app=createRestaurantApp(c);expect((await view(s)).b3Recovery).toMatchObject({order:s.id,continued:false});
    for(const patch of [{order:'0'.repeat(32)},{payer:h.server.address},{payment:h.mint},{sourceSha:'a'.repeat(40)},{orderSha256:'a'.repeat(64)},{authorizeSignature:'wrong'},{classification:'balance-only'}]) {
      const candidate=createRestaurantApp({...c,b3Recovery:{...c.b3Recovery,...patch} as any});
      expect((await (await candidate.request(`${origin}/api/orders/${s.id}`,{headers:{cookie:s.cookie}})).json() as any).b3Recovery).toBeUndefined();
    }
    expect(readFileSync(c.orders.path(s.id))).toEqual(original);
    const prep=await app.request(`${origin}/api/orders/${s.id}/reclaim`,{headers:{cookie:s.cookie}});expect(prep.status).toBe(200);
    expect((await view(s)).b3Recovery).toMatchObject({continued:false});
    const {unsigned}=await prep.json() as any;
    const result=await app.request(`${origin}/api/orders/${s.id}/reclaim`,{method:'POST',headers:{cookie:s.cookie,origin,'content-type':'application/json'},body:JSON.stringify({transaction:await sign(unsigned)})});
    expect(result.status).toBe(200);expect((await view(s)).b3Recovery).toMatchObject({continued:true});
    expect(c.orders.read(s.id).events[0]).toEqual(stored.events[0]);expect(c.orders.attempted(s.id,'beer')).toBe(false);
  });
  test('freshness must bind exact original wire; wallet consent durably blocks expired draft replacement',async()=>{
    const s=await offer();c.ledger.offerBlockhashValid=async()=>true;
    const preflight=()=>app.request(`${origin}/api/orders/${s.id}/signing-preflight?operation=authorize`,{headers:{cookie:s.cookie}});
    expect((await preflight()).status).toBe(200);
    const reserve=(unsignedSha256:string)=>app.request(`${origin}/api/orders/${s.id}/wallet-consent`,{method:'POST',headers:{cookie:s.cookie,origin,'content-type':'application/json'},body:JSON.stringify({unsignedSha256})});
    expect((await reserve('a'.repeat(64))).status).toBe(409);expect((await reserve(createHash('sha256').update(s.unsigned).digest('hex'))).status).toBe(200);
    c.ledger.offerBlockhashValid=async()=>false;expect((await preflight()).status).toBe(409);h.setTime(NOW+300n);
    const r=await app.request(`${origin}/api/orders`,{method:'POST',headers:{cookie:s.cookie,origin,'content-type':'application/json'},body:JSON.stringify({payer:h.payer.address})});
    expect(r.status).toBe(409);expect(h.ledger.submissions).toHaveLength(0);
  });
  async function expiredAuthorizeDraft() {
    c.getLatestBlockhash=async()=>({...h.lifetime(),blockhashSlot:1n,commitment:'finalized' as const,network:c.network,genesisHash:'local-genesis'});
    const s=await offer();
    const consent=await app.request(`${origin}/api/orders/${s.id}/wallet-consent`,{method:'POST',headers:{cookie:s.cookie,origin,'content-type':'application/json'},body:JSON.stringify({unsignedSha256:createHash('sha256').update(s.unsigned).digest('hex')})});expect(consent.status).toBe(200);
    const path=c.orders.path(s.id),stored=c.orders.read(s.id);
    // First-party lifetime provenance fixture, not a live origin claim.
    stored.authorizeLifetime={version:1,messageHash:(await import('../src/submission-journal.ts')).messageHash(getTransactionDecoder().decode(getBase64Encoder().encode(s.unsigned)).messageBytes),blockhash:h.lifetime().blockhash,lastValidBlockHeight:h.lifetime().lastValidBlockHeight.toString(),contextSlot:'1',commitment:'finalized',network:c.network,genesisHash:'local-genesis'};c.orders.write(stored);
    const original=readFileSync(path,'utf8'),consentBytes=readFileSync(`${path}.wallet-consent.lock`,'utf8');
    c.authorizeAbandonPolicy={...EXPIRED_A_POLICY,order:s.id,payment:stored.payment,payer:stored.payer,orderSha256:createHash('sha256').update(original).digest('hex'),consentSha256:createHash('sha256').update(consentBytes).digest('hex')};
    h.setTime(NOW+190n);h.svm.expireBlockhash();
    c.ledger.getFinalizedBlockhashStatus=async()=>({kind:'ok',valid:false,slot:5n});
    c.ledger.getAccountAtLeast=async address=>({kind:'ok',slot:6n,account:await h.ledger.getAccount(address)});
    c.ledger.getClockAtLeast=async()=>({kind:'ok',commitment:'finalized',slot:7n,unixTimestamp:NOW+190n});
    app=createRestaurantApp(c);
    return {s,path,original,consentBytes,abandon:()=>app.request(`${origin}/api/orders/${s.id}/abandon-authorize`,{method:'POST',headers:{cookie:s.cookie,origin}})};
  }
  test('explicit selected unfunded abandonment retains original bytes, survives restart and permits only a separate new offer',async()=>{
    const a=await expiredAuthorizeDraft();
    const r=await a.abandon();expect(r.status).toBe(200);expect(await r.json()).toMatchObject({abandoned:true,proof:{kind:'expired-unfunded-authorize',originSlot:'1',expirySlot:'5',paymentSlot:'6',clockSlot:'7'}});
    expect(readFileSync(a.path,'utf8')).toBe(a.original);expect(readFileSync(`${a.path}.wallet-consent.lock`,'utf8')).toBe(a.consentBytes);
    const archive=readFileSync(`${a.path}.authorize-abandon.lock`,'utf8');expect(JSON.parse(archive)).toMatchObject({originalOrder:a.original,originalConsent:a.consentBytes});
    app=createRestaurantApp({...c,orders:new RestaurantOrders(c.orders.dir)});
    const v=await view(a.s);expect(v).toMatchObject({status:'abandoned',authorizeAbandoned:{kind:'expired-unfunded-authorize'}});expect(v.unsigned).toBeUndefined();
    expect((await a.abandon()).status).toBe(409);
    expect((await app.request(`${origin}/api/orders/${a.s.id}/signing-preflight?operation=authorize`,{headers:{cookie:a.s.cookie}})).status).toBe(409);
    const next=await app.request(`${origin}/api/orders`,{method:'POST',headers:{cookie:a.s.cookie,origin,'content-type':'application/json'},body:JSON.stringify({payer:h.payer.address,scenario:'normal'})});expect(next.status).toBe(402);
    const body=await next.json() as any;expect(body.order).not.toBe(a.s.id);expect(body.required.accepts[0].extra.captureDeadline).toBe(Number(NOW+340n));
    expect(readFileSync(a.path,'utf8')).toBe(a.original);expect(readFileSync(`${a.path}.authorize-abandon.lock`,'utf8')).toBe(archive);expect(h.ledger.submissions).toHaveLength(0);
  });
  test.each(['no-policy','wrong-order','wrong-identity','order-drift','consent-drift','valid-hash','unavailable','stale-expiry','stale-payment','stale-clock','before-deadline','existing-PDA','pending','event','dispatch-lock','operation-journal','submission-journal','partial-archive','signed-wire','wrong-wire','missing-origin'])('authorize abandonment refuses %s without modifying originals or sending',async failure=>{
    const a=await expiredAuthorizeDraft();
    if(failure==='no-policy')delete c.authorizeAbandonPolicy;
    if(failure==='wrong-order')c.authorizeAbandonPolicy!.order='0'.repeat(32);
    if(failure==='wrong-identity')c.authorizeAbandonPolicy!.payer=h.server.address;
    if(failure==='valid-hash')c.ledger.getFinalizedBlockhashStatus=async()=>({kind:'ok',valid:true,slot:5n});
    if(failure==='unavailable')c.ledger.getFinalizedBlockhashStatus=async()=>({kind:'unavailable',detail:'fixture'});
    if(failure==='stale-expiry')c.ledger.getFinalizedBlockhashStatus=async()=>({kind:'ok',valid:false,slot:1n});
    if(failure==='stale-payment')c.ledger.getAccountAtLeast=async address=>({kind:'ok',slot:4n,account:await h.ledger.getAccount(address)});
    if(failure==='stale-clock')c.ledger.getClockAtLeast=async()=>({kind:'ok',commitment:'finalized',slot:4n,unixTimestamp:NOW+190n});
    if(failure==='before-deadline')c.ledger.getClockAtLeast=async()=>({kind:'ok',commitment:'finalized',slot:7n,unixTimestamp:NOW+170n});
    if(failure==='existing-PDA')c.ledger.getAccountAtLeast=async()=>({kind:'ok',slot:6n,account:{owner:c.programId,lamports:1n,executable:false,data:new Uint8Array()}});
    if(failure==='operation-journal')vi.spyOn(c.store,'list').mockReturnValue([{authorize:{payment:c.orders.read(a.s.id).payment}} as any]);
    if(failure==='submission-journal')vi.spyOn(c.reclaimJournal,'findByMessageHash').mockReturnValue([{} as any]);
    const order=c.orders.read(a.s.id);
    if(failure==='signed-wire')order.unsigned=await sign(order.unsigned);
    if(failure==='wrong-wire')order.unsigned=encodeTransaction(await h.signedAuthorize({salt:h.newSalt(),signers:[]}));
    if(failure==='missing-origin')order.authorizeLifetime!.contextSlot=null;
    if(failure==='pending')order.status='pending';
    if(failure==='event')order.events.push({action:'authorize',status:'prepared',transaction:'original'} as any);
    if(failure==='order-drift')order.required.accepts[0]!.extra!.captureDeadline=1;
    c.orders.write(order);
    if(['signed-wire','wrong-wire','missing-origin'].includes(failure)) {
      c.authorizeAbandonPolicy!.orderSha256=createHash('sha256').update(readFileSync(a.path)).digest('hex');
      (await import('node:fs')).writeFileSync(`${a.path}.wallet-consent.lock`,JSON.stringify({order:order.id,unsignedSha256:createHash('sha256').update(order.unsigned).digest('hex')}));
      c.authorizeAbandonPolicy!.consentSha256=createHash('sha256').update(readFileSync(`${a.path}.wallet-consent.lock`)).digest('hex');
    }
    if(failure==='consent-drift')(await import('node:fs')).writeFileSync(`${a.path}.wallet-consent.lock`,'{}');
    if(failure==='dispatch-lock')createDurableFile(`${a.path}.authorize.lock`,'original');
    if(failure==='partial-archive')createDurableFile(`${a.path}.authorize-abandon.lock`,'{');
    const before=readFileSync(a.path),consent=readFileSync(`${a.path}.wallet-consent.lock`);
    expect((await a.abandon()).status).toBe(409);expect(readFileSync(a.path)).toEqual(before);expect(readFileSync(`${a.path}.wallet-consent.lock`)).toEqual(consent);expect(h.ledger.submissions).toHaveLength(0);
  });
  test('partial abandonment archive and busy reservation remain blocked across restart',async()=>{
    const a=await expiredAuthorizeDraft();createDurableFile(`${a.path}.authorize-abandon.lock`,'{"schema":1}');
    app=createRestaurantApp({...c,orders:new RestaurantOrders(c.orders.dir)});
    expect((await app.request(`${origin}/api/orders/${a.s.id}`,{headers:{cookie:a.s.cookie}})).status).toBe(409);
    expect((await app.request(`${origin}/api/orders`,{method:'POST',headers:{cookie:a.s.cookie,origin,'content-type':'application/json'},body:JSON.stringify({payer:h.payer.address})})).status).toBe(409);
    expect((await a.abandon()).status).toBe(409);expect(h.ledger.submissions).toHaveLength(0);
  });
  test('concurrent successor offers reserve exactly one; partial intent blocks after restart',async()=>{
    const a=await expiredAuthorizeDraft();expect((await a.abandon()).status).toBe(200);
    const next=()=>app.request(`${origin}/api/orders`,{method:'POST',headers:{cookie:a.s.cookie,origin,'content-type':'application/json'},body:JSON.stringify({payer:h.payer.address,scenario:'normal'})});
    const results=await Promise.all([next(),next()]);expect(results.map(r=>r.status).sort()).toEqual([402,409]);
    const intent=JSON.parse(readFileSync(`${a.path}.authorize-successor.lock`,'utf8'));
    expect(intent.previousOrder).toBe(a.s.id);expect(c.orders.read(intent.nextOrder).status).toBe('draft');
    app=createRestaurantApp({...c,orders:new RestaurantOrders(c.orders.dir)});expect((await next()).status).toBe(409);expect((await view(a.s)).status).toBe('pending');expect(h.ledger.submissions).toHaveLength(0);
  });
  test('partial successor reservation blocks new offer without fabricating a completed successor',async()=>{
    const a=await expiredAuthorizeDraft();await a.abandon();createDurableFile(`${a.path}.authorize-successor.lock`,'{');
    app=createRestaurantApp({...c,orders:new RestaurantOrders(c.orders.dir)});
    expect((await view(a.s)).status).toBe('pending');
    expect((await app.request(`${origin}/api/orders`,{method:'POST',headers:{cookie:a.s.cookie,origin,'content-type':'application/json'},body:JSON.stringify({payer:h.payer.address})})).status).toBe(409);expect(h.ledger.submissions).toHaveLength(0);
  });
  test('retained busy abandonment reservation cannot be reused after restart',async()=>{
    const a=await expiredAuthorizeDraft();c.orders.reserve(a.s.id,'authorize');
    app=createRestaurantApp({...c,orders:new RestaurantOrders(c.orders.dir)});
    expect((await a.abandon()).status).toBe(409);expect(c.orders.busy(a.s.id)).toBe(true);expect((await view(a.s)).authorizeAbandonEligible).toBe(false);expect(h.ledger.submissions).toHaveLength(0);
  });
  test('abandonment serializes against concurrent abandonment and fresh consent',async()=>{
    const a=await expiredAuthorizeDraft();let entered!:()=>void,release!:(v:any)=>void;const started=new Promise<void>(r=>entered=r),waiting=new Promise<any>(r=>release=r);
    c.ledger.getFinalizedBlockhashStatus=async()=>{entered();return waiting;};const first=a.abandon();await started;
    expect((await a.abandon()).status).toBe(409);
    expect((await app.request(`${origin}/api/orders/${a.s.id}/wallet-consent`,{method:'POST',headers:{cookie:a.s.cookie,origin,'content-type':'application/json'},body:JSON.stringify({unsignedSha256:createHash('sha256').update(a.s.unsigned).digest('hex')})})).status).toBe(409);
    release({kind:'ok',valid:false,slot:5n});expect((await first).status).toBe(200);expect(h.ledger.submissions).toHaveLength(0);
  });
  test('reclaim wallet consent durably preserves its original draft without permitting replacement signing',async()=>{
    const s=await offer();await authorize(s);h.setTime(NOW+150n);
    const prepare=()=>app.request(`${origin}/api/orders/${s.id}/reclaim`,{headers:{cookie:s.cookie}});
    const r=await prepare();expect(r.status).toBe(200);const {unsigned}=await r.json() as any;
    const consent=await app.request(`${origin}/api/orders/${s.id}/wallet-consent?operation=reclaim`,{method:'POST',headers:{cookie:s.cookie,origin,'content-type':'application/json'},body:JSON.stringify({unsignedSha256:createHash('sha256').update(unsigned).digest('hex')})});
    expect(consent.status).toBe(200);app=createRestaurantApp({...c,orders:new RestaurantOrders(c.orders.dir)});
    expect((await prepare()).status).toBe(409);expect(c.orders.read(s.id).reclaimUnsigned).toBe(unsigned);
    const result=await app.request(`${origin}/api/orders/${s.id}/reclaim`,{method:'POST',headers:{cookie:s.cookie,origin,'content-type':'application/json'},body:JSON.stringify({transaction:await sign(unsigned)})});
    expect(result.status).toBe(200);expect((await view(s)).remaining).toBe(0);expect(h.ledger.submissions).toHaveLength(2);
  });
  test('concurrent reclaim preparation cannot replace the draft while wallet-consent eligibility awaits Clock',async()=>{
    const s=await offer();await authorize(s);h.setTime(NOW+150n);
    const prepare=()=>app.request(`${origin}/api/orders/${s.id}/reclaim`,{headers:{cookie:s.cookie}});
    const {unsigned}=await (await prepare()).json() as any;
    let entered!:()=>void,release!:(v:bigint)=>void;
    const started=new Promise<void>(r=>entered=r),clock=new Promise<bigint>(r=>release=r);
    c.now=()=>{entered();return clock;};
    const consent=app.request(`${origin}/api/orders/${s.id}/wallet-consent?operation=reclaim`,{method:'POST',headers:{cookie:s.cookie,origin,'content-type':'application/json'},body:JSON.stringify({unsignedSha256:createHash('sha256').update(unsigned).digest('hex')})});
    await started;expect(c.orders.busy(s.id)).toBe(true);expect((await prepare()).status).toBe(409);
    expect(c.orders.read(s.id).reclaimUnsigned).toBe(unsigned);release(NOW+150n);
    expect((await consent).status).toBe(200);expect(c.orders.busy(s.id)).toBe(false);
  });

  async function expiredReclaimConsent() {
    const s=await offer();await authorize(s);h.setTime(NOW+150n);
    c.getLatestBlockhash=async()=>({...h.lifetime(),blockhashSlot:1n});
    const prep=await app.request(`${origin}/api/orders/${s.id}/reclaim`,{headers:{cookie:s.cookie}});
    expect(prep.status).toBe(200);const {unsigned}=await prep.json() as any;
    const consentPath=`${c.orders.path(s.id)}.reclaim-consent.lock`;
    const consent=await app.request(`${origin}/api/orders/${s.id}/wallet-consent?operation=reclaim`,{method:'POST',headers:{cookie:s.cookie,origin,'content-type':'application/json'},body:JSON.stringify({unsignedSha256:createHash('sha256').update(unsigned).digest('hex')})});
    expect(consent.status).toBe(200);const originalConsent=readFileSync(consentPath,'utf8');
    h.svm.expireBlockhash();
    c.ledger.getFinalizedBlockhashStatus=async()=>({kind:'ok',valid:false,slot:5n});
    c.ledger.getAccountAtLeast=async(address)=>({kind:'ok',slot:6n,account:await h.ledger.getAccount(address)});
    c.ledger.getClockAtLeast=async()=>({kind:'ok',commitment:'finalized',slot:7n,unixTimestamp:NOW+150n});
    return {s,unsigned,consentPath,originalConsent,renew:()=>app.request(`${origin}/api/orders/${s.id}/reclaim-renewal`,{method:'POST',headers:{cookie:s.cookie,origin}})};
  }
  test('one explicit finalized-expiry renewal archives old consent/wire across restart and reclaims with one new payer signature',async()=>{
    const a=await expiredReclaimConsent(),originalEvents=c.orders.read(a.s.id).events;
    const r=await a.renew();expect(r.status).toBe(200);const renewed=await r.json() as any;
    expect(renewed.proof).toMatchObject({kind:'expired-no-reclaim-effect',originSlot:'1',expirySlot:'5',paymentSlot:'6',held:'100000000'});
    expect(renewed.unsigned).not.toBe(a.unsigned);expect(readFileSync(a.consentPath,'utf8')).toBe(a.originalConsent);
    const archive=JSON.parse(readFileSync(`${c.orders.path(a.s.id)}.reclaim-renewal.lock`,'utf8'));expect(archive).toMatchObject({oldUnsigned:a.unsigned,oldConsent:a.originalConsent,newUnsigned:renewed.unsigned});
    expect(c.orders.read(a.s.id).events).toEqual(originalEvents);expect(h.ledger.submissions).toHaveLength(1);
    app=createRestaurantApp({...c,orders:new RestaurantOrders(c.orders.dir)});
    expect((await a.renew()).status).toBe(409);
    const same=await app.request(`${origin}/api/orders/${a.s.id}/reclaim`,{headers:{cookie:a.s.cookie}});expect(same.status).toBe(200);expect((await same.json() as any).unsigned).toBe(renewed.unsigned);
    const consent=await app.request(`${origin}/api/orders/${a.s.id}/wallet-consent?operation=reclaim`,{method:'POST',headers:{cookie:a.s.cookie,origin,'content-type':'application/json'},body:JSON.stringify({unsignedSha256:createHash('sha256').update(renewed.unsigned).digest('hex')})});expect(consent.status).toBe(200);
    expect((await app.request(`${origin}/api/orders/${a.s.id}/reclaim`,{headers:{cookie:a.s.cookie}})).status).toBe(409);
    const result=await app.request(`${origin}/api/orders/${a.s.id}/reclaim`,{method:'POST',headers:{cookie:a.s.cookie,origin,'content-type':'application/json'},body:JSON.stringify({transaction:await sign(renewed.unsigned)})});
    expect(result.status).toBe(200);expect(h.state(c.orders.read(a.s.id).payment).held).toBe(0n);expect((await view(a.s)).remaining).toBe(0);expect(h.ledger.submissions).toHaveLength(2);
    expect(readFileSync(a.consentPath,'utf8')).toBe(a.originalConsent);expect(c.orders.read(a.s.id).events[0]).toEqual(originalEvents[0]);
  });
  test.each(['valid','unavailable','stale-expiry','stale-payment','stale-clock','before-deadline','missing-origin','signed-wire','extra-instruction','pending','unknown-authorize','partial-archive','missing-account'])('renewal refuses %s without mutating the original draft/consent or sending',async failure=>{
    const a=await expiredReclaimConsent();
    if(failure==='valid')c.ledger.getFinalizedBlockhashStatus=async()=>({kind:'ok',valid:true,slot:5n});
    if(failure==='unavailable')c.ledger.getFinalizedBlockhashStatus=async()=>({kind:'unavailable',detail:'fixture'});
    if(failure==='stale-expiry')c.ledger.getFinalizedBlockhashStatus=async()=>({kind:'ok',valid:false,slot:1n});
    if(failure==='stale-payment')c.ledger.getAccountAtLeast=async(address)=>({kind:'ok',slot:4n,account:await h.ledger.getAccount(address)});
    if(failure==='stale-clock')c.ledger.getClockAtLeast=async()=>({kind:'ok',commitment:'finalized',slot:4n,unixTimestamp:NOW+150n});
    if(failure==='before-deadline')c.ledger.getClockAtLeast=async()=>({kind:'ok',commitment:'finalized',slot:7n,unixTimestamp:NOW+149n});
    if(failure==='missing-account')c.ledger.getAccountAtLeast=async()=>({kind:'ok',slot:6n,account:null});
    if(failure==='unknown-authorize')c.ledger.getSignatureStatus=async()=>({kind:'not-found'});
    const stored=c.orders.read(a.s.id);
    if(failure==='pending')stored.status='pending';
    if(failure==='missing-origin')delete stored.reclaimLifetime!.blockhashSlot;
    if(failure==='signed-wire' || failure==='extra-instruction') {
      if(failure==='signed-wire')stored.reclaimUnsigned=await sign(a.unsigned);
      else stored.reclaimUnsigned=encodeTransaction(await h.signedAuthorize({salt:h.newSalt(),signers:[]}));
      // Even custody-matching consent cannot authorize a different economic wire.
      const fs=await import('node:fs');fs.writeFileSync(a.consentPath,JSON.stringify({order:a.s.id,unsignedSha256:createHash('sha256').update(stored.reclaimUnsigned!).digest('hex')}));
    }
    c.orders.write(stored);
    if(failure==='partial-archive')createDurableFile(`${c.orders.path(a.s.id)}.reclaim-renewal.lock`,JSON.stringify({newUnsigned:'incomplete'}));
    const bytes=readFileSync(c.orders.path(a.s.id)),consent=readFileSync(a.consentPath);
    expect((await a.renew()).status).toBe(409);expect(readFileSync(c.orders.path(a.s.id))).toEqual(bytes);expect(readFileSync(a.consentPath)).toEqual(consent);expect(h.ledger.submissions).toHaveLength(1);
  });
  test('repeated expiry before consent appends immutable archives, survives restart and signs only the current generation',async()=>{
    const a=await expiredReclaimConsent(),path=c.orders.path(a.s.id),original=readFileSync(a.consentPath),events=c.orders.read(a.s.id).events;
    let draft=await (await a.renew()).json() as any;
    const first=readFileSync(`${path}.reclaim-renewal.lock`);
    for(let i=0;i<3;i++) {
      const previous=draft.unsigned;
      h.svm.expireBlockhash();
      draft=await (await a.renew()).json() as any;
      expect(draft.unsigned).toBeTypeOf('string');expect(draft.unsigned).not.toBe(previous);
      const file=`${path}.reclaim-renewal-${createHash('sha256').update(previous).digest('hex')}.lock`;
      const archive=JSON.parse(readFileSync(file,'utf8'));
      expect(archive).toMatchObject({oldUnsigned:previous,oldConsent:null,proof:{consentSha256:null},newUnsigned:draft.unsigned});
      expect(readFileSync(`${path}.reclaim-renewal.lock`)).toEqual(first);
      expect(readFileSync(a.consentPath)).toEqual(original);
      app=createRestaurantApp({...c,orders:new RestaurantOrders(c.orders.dir)});
      const same=await app.request(`${origin}/api/orders/${a.s.id}/reclaim`,{headers:{cookie:a.s.cookie}});
      expect((await same.json() as any).unsigned).toBe(draft.unsigned);
    }
    expect(c.orders.read(a.s.id).events).toEqual(events);expect(h.ledger.submissions).toHaveLength(1);
    const consent=await app.request(`${origin}/api/orders/${a.s.id}/wallet-consent?operation=reclaim`,{method:'POST',headers:{cookie:a.s.cookie,origin,'content-type':'application/json'},body:JSON.stringify({unsignedSha256:createHash('sha256').update(draft.unsigned).digest('hex')})});
    expect(consent.status).toBe(200);
    expect((await app.request(`${origin}/api/orders/${a.s.id}/signing-preflight?operation=reclaim`,{headers:{cookie:a.s.cookie}})).status).toBe(409);
    const dispatch=await app.request(`${origin}/api/orders/${a.s.id}/signing-preflight?operation=reclaim&phase=dispatch`,{headers:{cookie:a.s.cookie}});
    expect(dispatch.status).toBe(200);expect(await dispatch.json()).toMatchObject({phase:'dispatch',fresh:false,unsignedSha256:createHash('sha256').update(draft.unsigned).digest('hex')});
    const result=await app.request(`${origin}/api/orders/${a.s.id}/reclaim`,{method:'POST',headers:{cookie:a.s.cookie,origin,'content-type':'application/json'},body:JSON.stringify({transaction:await sign(draft.unsigned)})});
    expect(result.status).toBe(200);expect(h.state(c.orders.read(a.s.id).payment).held).toBe(0n);expect((await view(a.s)).remaining).toBe(0);
  });
  test.each(['used-consent','unknown','stale-expiry','stale-payment','stale-clock','identity','signed','dispatch','journal','partial-archive','busy-restart'])('repeat preparation refuses %s and retains all archives',async failure=>{
    const a=await expiredReclaimConsent(),path=c.orders.path(a.s.id);
    const draft=await (await a.renew()).json() as any;
    if(failure==='used-consent') {
      const r=await app.request(`${origin}/api/orders/${a.s.id}/wallet-consent?operation=reclaim`,{method:'POST',headers:{cookie:a.s.cookie,origin,'content-type':'application/json'},body:JSON.stringify({unsignedSha256:createHash('sha256').update(draft.unsigned).digest('hex')})});expect(r.status).toBe(200);
    }
    h.svm.expireBlockhash();
    if(failure==='stale-expiry')c.ledger.getFinalizedBlockhashStatus=async()=>({kind:'ok',valid:false,slot:1n});
    if(failure==='stale-payment')c.ledger.getAccountAtLeast=async(address)=>({kind:'ok',slot:4n,account:await h.ledger.getAccount(address)});
    if(failure==='stale-clock')c.ledger.getClockAtLeast=async()=>({kind:'ok',commitment:'finalized',slot:4n,unixTimestamp:NOW+150n});
    const order=c.orders.read(a.s.id);
    if(failure==='unknown')order.status='pending';
    if(failure==='identity')order.required.accepts[0]!.extra!.refundDeadline=1;
    if(failure==='signed')order.reclaimUnsigned=await sign(draft.unsigned);
    if(failure==='dispatch')createDurableFile(`${path}.reclaim.lock`,'retained-attempt');
    if(failure==='journal')vi.spyOn(c.reclaimJournal,'findByMessageHash').mockReturnValue([{} as any]);
    if(failure==='partial-archive')createDurableFile(`${path}.reclaim-renewal-${createHash('sha256').update(draft.unsigned).digest('hex')}.lock`,'{');
    if(failure==='busy-restart') {c.orders.reserve(a.s.id,'reclaim');app=createRestaurantApp({...c,orders:new RestaurantOrders(c.orders.dir)});}
    c.orders.write(order);
    const archive=readFileSync(`${path}.reclaim-renewal.lock`),before=readFileSync(path);
    expect((await a.renew()).status).toBe(409);expect(readFileSync(path)).toEqual(before);expect(readFileSync(`${path}.reclaim-renewal.lock`)).toEqual(archive);expect(h.ledger.submissions).toHaveLength(1);
  });
  test('archive-before-publication failure blocks every entry point across restart',async()=>{
    const a=await expiredReclaimConsent();await a.renew();h.svm.expireBlockhash();
    const before=readFileSync(c.orders.path(a.s.id));
    const write=vi.spyOn(c.orders,'write').mockImplementationOnce(()=>{throw Error('injected crash before atomic publication');});
    expect((await a.renew()).status).toBe(409);write.mockRestore();
    expect(readFileSync(c.orders.path(a.s.id))).toEqual(before);
    app=createRestaurantApp({...c,orders:new RestaurantOrders(c.orders.dir)});
    expect((await a.renew()).status).toBe(409);
    for(const suffix of ['', '/reclaim','/signing-preflight?operation=reclaim'])expect((await app.request(`${origin}/api/orders/${a.s.id}${suffix}`,{headers:{cookie:a.s.cookie}})).status).toBe(409);
    expect(h.ledger.submissions).toHaveLength(1);
  });
  test('repeat preparation serializes with consent and other preparers',async()=>{
    const a=await expiredReclaimConsent();const draft=await (await a.renew()).json() as any;h.svm.expireBlockhash();
    let entered!:()=>void,release!:(v:any)=>void;const started=new Promise<void>(r=>entered=r),waiting=new Promise<any>(r=>release=r);
    c.ledger.getFinalizedBlockhashStatus=async()=>{entered();return waiting;};
    const first=a.renew();await started;
    expect((await a.renew()).status).toBe(409);
    const consent=await app.request(`${origin}/api/orders/${a.s.id}/wallet-consent?operation=reclaim`,{method:'POST',headers:{cookie:a.s.cookie,origin,'content-type':'application/json'},body:JSON.stringify({unsignedSha256:createHash('sha256').update(draft.unsigned).digest('hex')})});expect(consent.status).toBe(409);
    release({kind:'ok',valid:false,slot:5n});expect((await first).status).toBe(200);expect(h.ledger.submissions).toHaveLength(1);
  });
  test('dispatch preflight requires exact durable consent and still rejects expired, pending or mismatched consent',async()=>{
    const a=await expiredReclaimConsent(),draft=await (await a.renew()).json() as any;
    const preflight=()=>app.request(`${origin}/api/orders/${a.s.id}/signing-preflight?operation=reclaim&phase=dispatch`,{headers:{cookie:a.s.cookie}});
    expect((await preflight()).status).toBe(409);
    const marker=`${c.orders.path(a.s.id)}.reclaim-consent-${createHash('sha256').update(draft.unsigned).digest('hex')}.lock`;
    createDurableFile(marker,JSON.stringify({order:a.s.id,unsignedSha256:'wrong'}));
    expect((await preflight()).status).toBe(409);
    const fs=await import('node:fs');fs.writeFileSync(marker,JSON.stringify({order:a.s.id,unsignedSha256:createHash('sha256').update(draft.unsigned).digest('hex')}));
    expect((await preflight()).status).toBe(200);
    const order=c.orders.read(a.s.id);order.status='pending';c.orders.write(order);expect((await preflight()).status).toBe(409);
    order.status='active';c.orders.write(order);h.svm.expireBlockhash();expect((await preflight()).status).toBe(409);
    expect(h.ledger.submissions).toHaveLength(1);
  });
  test('renewed signed wire without durable fresh consent cannot dispatch',async()=>{
    const a=await expiredReclaimConsent(),draft=await (await a.renew()).json() as any;
    const result=await app.request(`${origin}/api/orders/${a.s.id}/reclaim`,{method:'POST',headers:{cookie:a.s.cookie,origin,'content-type':'application/json'},body:JSON.stringify({transaction:await sign(draft.unsigned)})});
    expect(result.status).toBe(409);expect(h.ledger.submissions).toHaveLength(1);expect(c.orders.attempted(a.s.id,'reclaim')).toBe(false);
  });
  test('expired retained generation cannot get consent or signing preflight',async()=>{
    const a=await expiredReclaimConsent(),draft=await (await a.renew()).json() as any;h.svm.expireBlockhash();
    const consent=await app.request(`${origin}/api/orders/${a.s.id}/wallet-consent?operation=reclaim`,{method:'POST',headers:{cookie:a.s.cookie,origin,'content-type':'application/json'},body:JSON.stringify({unsignedSha256:createHash('sha256').update(draft.unsigned).digest('hex')})});expect(consent.status).toBe(409);
    expect((await app.request(`${origin}/api/orders/${a.s.id}/signing-preflight?operation=reclaim`,{headers:{cookie:a.s.cookie}})).status).toBe(409);
    expect((await view(a.s)).reclaimDraftState).toBe('expired-or-unavailable');
  });
  test('a dispatched original reclaim attempt cannot enter consent renewal',async()=>{
    const a=await expiredReclaimConsent();
    createDurableFile(`${c.orders.path(a.s.id)}.reclaim.lock`,'original-attempt');
    expect((await a.renew()).status).toBe(409);expect(h.ledger.submissions).toHaveLength(1);
  });
  test('positive finalized H is required: a successful direct reclaim cannot be renewed',async()=>{
    const a=await expiredReclaimConsent(),payment=c.orders.read(a.s.id).payment;
    h.ok(await h.direct([await reclaimInstruction({programId:c.programId,payment,payer:h.payer.address,server:h.server.address,mint:h.mint})],[h.payer]));
    expect(h.state(payment).held).toBe(0n);expect((await a.renew()).status).toBe(409);
  });
  test('renewal serializes against concurrent preparation and duplicate renewal while expiry evidence awaits',async()=>{
    const a=await expiredReclaimConsent();let release!:(v:any)=>void,entered!:()=>void;
    const started=new Promise<void>(r=>entered=r),waiting=new Promise<any>(r=>release=r);
    c.ledger.getFinalizedBlockhashStatus=async()=>{entered();return waiting;};
    const first=a.renew();await started;expect(c.orders.busy(a.s.id)).toBe(true);
    expect((await a.renew()).status).toBe(409);expect((await app.request(`${origin}/api/orders/${a.s.id}/reclaim`,{headers:{cookie:a.s.cookie}})).status).toBe(409);
    release({kind:'ok',valid:false,slot:5n});expect((await first).status).toBe(200);expect(c.orders.busy(a.s.id)).toBe(false);expect(h.ledger.submissions).toHaveLength(1);
  });
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
    const r = await app.request(`${origin}/api/orders`, { method: "POST", headers: { origin, cookie: first.cookie, "content-type": "application/json" }, body: JSON.stringify({ payer: h.payer.address, scenario: "normal" }) });
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
    c.merchantToken = undefined;
    app = createRestaurantApp(c);
    const before = h.tokens(await h.payerAta()); const s = await offer("unavailable"); await authorize(s);
    expect((await action(s,"beer")).status).toBe(503);
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
  test.each(["snapshot", "blockhash", "simulation"])("a %s refusal before merchant preparation returns definitive not-submitted without signing or changing originals", async phase => {
    const s = await offer(); await authorize(s);
    const original = readFileSync(c.orders.path(s.id), "utf8");
    const secret = "SYNTHETIC_PRIVATE_RPC_DETAIL";
    if (phase === "snapshot") vi.spyOn(c.ledger, "getAccountAtLeast").mockResolvedValueOnce({ kind: "unavailable", detail: secret });
    if (phase === "blockhash") vi.spyOn(c, "getLatestBlockhash").mockRejectedValueOnce(new Error(secret));
    if (phase === "simulation") vi.spyOn(c.ledger, "simulate").mockRejectedValueOnce(new Error(secret));
    const relay = vi.fn(); c.fetchImpl = relay;
    const response = await action(s, "beer");
    const body = await response.json() as any;
    expect(response.status).toBe(409);
    expect(body).toMatchObject({ receipt: { success: false, errorReason: "settlement_not_submitted", transaction: "", payer: h.payer.address } });
    expect(decodeHeader(response.headers.get("PAYMENT-RESPONSE")!)).toEqual(body.receipt);
    expect(JSON.stringify(body)).not.toContain(secret);
    expect(relay).not.toHaveBeenCalled(); expect(h.ledger.submissions).toHaveLength(1);
    expect(readFileSync(c.orders.path(s.id), "utf8")).toBe(original);
    expect(c.orders.busy(s.id)).toBe(false); expect(c.orders.attempted(s.id, "beer")).toBe(false);
    h.setTime(NOW + 150n);
    expect(await view(s)).toMatchObject({ status: "active", remaining: 100, actions: { reclaim: true } });
  });
  test("an unlock failure cannot produce a definitive not-submitted receipt or release the busy reservation", async () => {
    const s = await offer(); await authorize(s);
    vi.spyOn(c, "getLatestBlockhash").mockRejectedValueOnce(new Error("SYNTHETIC_PRIVATE_RPC_DETAIL"));
    vi.spyOn(c.orders, "unlock").mockImplementationOnce(() => { throw new Error("SYNTHETIC_PRIVATE_UNLOCK_DETAIL"); });
    const response = await action(s, "beer");
    expect(response.status).toBe(409); expect(await response.json()).not.toHaveProperty("receipt");
    expect(c.orders.busy(s.id)).toBe(true); expect(h.ledger.submissions).toHaveLength(1);
  });
  test("a partial preparation failure retains original bytes and reservations without a not-submitted receipt", async () => {
    const s = await offer(); await authorize(s);
    const prepare = c.orders.prepare.bind(c.orders);
    vi.spyOn(c.orders, "prepare").mockImplementationOnce((order, event) => {
      prepare(order, event); throw new Error("SYNTHETIC_PRIVATE_PREPARATION_DETAIL");
    });
    const relay = vi.fn(); c.fetchImpl = relay;
    const response = await action(s, "beer");
    expect(response.status).toBe(409); expect(await response.json()).not.toHaveProperty("receipt");
    const record = c.orders.read(s.id);
    expect(record.status).toBe("pending"); expect(record.events[1]!.transactionBase64.length).toBeGreaterThan(0);
    expect(c.orders.attempted(s.id, "beer")).toBe(true); expect(c.orders.busy(s.id)).toBe(true);
    expect(relay).not.toHaveBeenCalled(); expect(h.ledger.submissions).toHaveLength(1);
  });
  test("an action lock created before the order update also retains the busy reservation", async () => {
    const s = await offer(); await authorize(s);
    const original = readFileSync(c.orders.path(s.id), "utf8");
    vi.spyOn(c.orders, "prepare").mockImplementationOnce((order, event) => {
      createDurableFile(`${c.orders.path(order.id)}.${event.action}.lock`, JSON.stringify(event));
      throw new Error("SYNTHETIC_PRIVATE_PREPARATION_DETAIL");
    });
    const response = await action(s, "beer");
    expect(response.status).toBe(409); expect(await response.json()).not.toHaveProperty("receipt");
    expect(readFileSync(c.orders.path(s.id), "utf8")).toBe(original);
    expect(c.orders.attempted(s.id, "beer")).toBe(true); expect(c.orders.busy(s.id)).toBe(true);
    expect(h.ledger.submissions).toHaveLength(1);
  });
  test("lost finalized response freezes all new consent and retains original transaction bytes across restart", async () => {
    const s = await offer(); await authorize(s); h.ledger.failSubmit = "after-landing";
    const response = await action(s,"beer");
    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({ receipt: { errorReason: "settlement_pending", transaction: expect.any(String) } });
    expect(await view(s)).toMatchObject({ status:"pending",remaining:60 });
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


describe("issue #45 read-only operator preflight and fail-closed eligibility", () => {
  const spyMerchant = () => { const sign = vi.fn(c.server.signTransactions); c.server = { ...c.server, signTransactions: sign }; app = createRestaurantApp(c); return sign; };
  const preflight = (s: Session, token = merchantToken, a = "beer") => app.request(`${origin}/api/orders/${s.id}/actions/${a}`, { headers: { authorization: `Bearer ${token}` } });
  test.each(["", "incorrect", "local-only-test"])("invalid preflight bearer %s cannot reserve, simulate, sign or submit", async token => {
    const s = await offer(); await authorize(s);
    const reserve = vi.spyOn(c.orders, "reserve"), read = vi.spyOn(c.orders, "read"), simulate = vi.spyOn(c.ledger, "simulate"), sign = spyMerchant();
    const files = readdirSync(c.orders.dir).sort(), original = readFileSync(c.orders.path(s.id), "utf8");
    expect((await preflight(s, token)).status).toBe(401);
    for (const call of [reserve, read, simulate, sign]) expect(call).not.toHaveBeenCalled();
    expect(readdirSync(c.orders.dir).sort()).toEqual(files); expect(readFileSync(c.orders.path(s.id), "utf8")).toBe(original);
    expect(h.ledger.submissions).toHaveLength(1);
  });
  test("matching finalized funded PDA does not reconcile a draft or permit merchant signing; payer reclaim policy stays intact", async () => {
    const s = await offer();
    // Fund the exact offered PDA outside application orchestration, leaving its original
    // authorization draft and economic records untouched. This is a local LiteSVM fixture.
    const signed = await partiallySignTransaction([h.payer.keyPair, h.facilitatorKey.keyPair], getTransactionDecoder().decode(getBase64Encoder().encode(s.unsigned)));
    expect(await c.ledger.submit(signed)).toMatchObject({ kind: "submitted", outcome: { status: "succeeded", commitment: "finalized" } });
    const original = readFileSync(c.orders.path(s.id), "utf8"), files = readdirSync(c.orders.dir).sort();
    const payment = c.orders.read(s.id).payment, originalState = h.state(payment);
    expect(c.orders.read(s.id)).toMatchObject({ status: "draft", events: [] });
    expect(originalState).toMatchObject({ held: DEMO_BUDGET, refundable: 0n });
    const sign = spyMerchant(), simulate = vi.spyOn(c.ledger, "simulate"), write = vi.spyOn(c.orders, "write"), prepare = vi.spyOn(c.orders, "prepare");
    const v = await (await preflight(s)).json() as any;
    for (const a of ["beer", "salmon", "finish", "void", "refund"]) {
      expect(v.actions[a]).toBe(false); expect(v.actionReasons[a]).toContain("authorization is still draft");
      const response = await action(s, a); expect(response.status).toBe(409); expect(await response.text()).toContain("authorization is still draft");
      expect(c.orders.attempted(s.id, a as any)).toBe(false);
    }
    for (const call of [sign, simulate, write, prepare]) expect(call).not.toHaveBeenCalled();
    expect(h.ledger.submissions).toHaveLength(1); expect(h.state(payment)).toEqual(originalState);
    expect(readFileSync(c.orders.path(s.id), "utf8")).toBe(original); expect(readdirSync(c.orders.dir).sort()).toEqual(files);
    expect(c.orders.busy(s.id)).toBe(false);
    h.setTime(NOW + 150n);
    const expired = await (await preflight(s)).json() as any;
    expect(expired.actions.reclaim).toBe(true);
    for (const a of ["beer", "salmon", "finish", "void", "refund"]) expect(expired.actions[a]).toBe(false);
    expect(readFileSync(c.orders.path(s.id), "utf8")).toBe(original);
  });
  test("verified access is scoped to an original order and never signs, writes, or discloses unsigned wire", async () => {
    const s = await offer();
    const reserve = vi.spyOn(c.orders, "reserve"), write = vi.spyOn(c.orders, "write"), simulate = vi.spyOn(c.ledger, "simulate"), sign = spyMerchant();
    const r = await preflight(s); expect(r.status).toBe(200); expect(r.headers.get("cache-control")).toBe("no-store");
    const v = await r.json() as any;
    expect(v).toMatchObject({ id: s.id, operatorAccess: true, actions: { beer: false }, balances: { payer: { amount: 1000.01 } } });
    expect(v.actionReasons.beer).toContain("not finalized");
    for (const field of ["required", "unsigned", "capabilityHash", "transactionBase64"]) expect(v).not.toHaveProperty(field);
    expect(JSON.stringify(v)).not.toContain(merchantToken);
    for (const call of [reserve, write, simulate, sign]) expect(call).not.toHaveBeenCalled();
    expect(h.ledger.submissions).toHaveLength(0);
  });
  test("forged action/order preflight and POST never sign", async () => {
    const s = await offer(); await authorize(s);
    const sign = spyMerchant(), simulate = vi.spyOn(c.ledger, "simulate");
    expect((await preflight(s, merchantToken, "authorize")).status).toBe(400);
    expect((await action(s, "reclaim")).status).toBe(400);
    expect((await preflight({ ...s, id: "f".repeat(32) })).status).toBe(409);
    expect((await action({ ...s, id: "f".repeat(32) }, "beer")).status).toBe(409);
    expect(sign).not.toHaveBeenCalled(); expect(simulate).not.toHaveBeenCalled(); expect(h.ledger.submissions).toHaveLength(1);
  });
  test("preflight uses current finalized state, specific deadline reasons and never extends an offer", async () => {
    const s = await offer(); await authorize(s); const terms = s.required.accepts[0]!.extra;
    const initial = await (await preflight(s)).json() as any;
    expect(initial).toMatchObject({ actions: { beer: true, salmon: false, refund: false } });
    expect(initial.actionReasons.salmon).toBe("Finalize capture 40 first.");
    h.setTime(NOW + 150n);
    const expired = await (await preflight(s)).json() as any;
    expect(expired).toMatchObject({ actions: { beer: false, reclaim: true }, captureDeadline: terms!.captureDeadline, refundDeadline: terms!.refundDeadline });
    expect(expired.actionReasons.beer).toContain("deadline expired");
    expect((await action(s, "beer")).status).toBe(409); expect(h.ledger.submissions).toHaveLength(1);
    expect(c.orders.attempted(s.id, "beer")).toBe(false);
  });
  test("unavailable or stale finalized signature evidence cannot reach merchant signing", async () => {
    const s = await offer(); await authorize(s);
    c.ledger.getSignatureStatus = async () => ({ kind: "found", commitment: "confirmed", slot: 1n, err: null });
    const sign = spyMerchant(), simulate = vi.spyOn(c.ledger, "simulate");
    expect((await preflight(s)).status).toBe(409); expect((await action(s, "beer")).status).toBe(409);
    expect(sign).not.toHaveBeenCalled(); expect(simulate).not.toHaveBeenCalled(); expect(h.ledger.submissions).toHaveLength(1);
  });
  test("pending original settlement cannot unlock eligibility even with valid operator access", async () => {
    const s = await offer(); await authorize(s); h.ledger.failSubmit = "after-landing"; await action(s, "beer");
    const disk = readFileSync(c.orders.path(s.id), "utf8");
    const v = await (await preflight(s)).json() as any;
    expect(v.status).toBe("pending"); expect(Object.values(v.actions)).toEqual(Array(7).fill(false));
    expect(v.actionReasons.salmon).toContain("pending");
    expect(readFileSync(c.orders.path(s.id), "utf8")).toBe(disk); expect(h.ledger.submissions).toHaveLength(2);
  });
  test("a valid unsigned offer cannot be replaced or extended", async () => {
    const s = await offer(); const original = readFileSync(c.orders.path(s.id), "utf8");
    const r = await app.request(`${origin}/api/orders`, { method: "POST", headers: { origin, cookie: s.cookie, "content-type": "application/json" }, body: JSON.stringify({ payer: h.payer.address }) });
    expect(r.status).toBe(409); expect(readdirSync(c.orders.dir)).toHaveLength(1);
    expect(readFileSync(c.orders.path(s.id), "utf8")).toBe(original); expect(h.ledger.submissions).toHaveLength(0);
  });
  test("payer funding blocker is explicit before simulation, order creation or signing", async () => {
    const simulate = vi.spyOn(c.ledger, "simulate"), create = vi.spyOn(c.orders, "create");
    const r = await app.request(`${origin}/api/orders`, { method: "POST", headers: { origin, "content-type": "application/json" }, body: JSON.stringify({ payer: h.outsider.address }) });
    expect(r.status).toBe(402); expect(await r.text()).toContain("funding required");
    expect(simulate).not.toHaveBeenCalled(); expect(create).not.toHaveBeenCalled(); expect(h.ledger.submissions).toHaveLength(0);
  });
  test("merchant liquidity loss disables refund and refuses before signing or simulation", async () => {
    const s = await offer("refund"); await authorize(s); await expectAction(s, "beer");
    h.ok(await h.direct([getTransferInstruction({ source: await h.serverAta(), destination: await h.payerAta(), authority: h.server, amount: 40n * DEMO_UNIT })], [h.server]));
    const sign = spyMerchant(), simulate = vi.spyOn(c.ledger, "simulate");
    const v = await (await preflight(s, merchantToken, "refund")).json() as any;
    expect(v).toMatchObject({ actions: { refund: false }, balances: { merchant: { amount: 0 } }, refundableBaseUnits: "40000000" });
    expect(v.actionReasons.refund).toContain("cannot fund");
    const r = await action(s, "refund"); expect(r.status).toBe(409); expect(await r.text()).toContain("cannot fund");
    expect(sign).not.toHaveBeenCalled(); expect(simulate).not.toHaveBeenCalled(); expect(h.ledger.submissions).toHaveLength(2);
    expect(c.orders.attempted(s.id, "refund")).toBe(false);
  });
  test("capture crossing the deadline before inclusion fails atomically and preserves payer reclaim", async () => {
    const s = await offer(); await authorize(s); const payment = (await view(s)).payment;
    const submit = c.ledger.submit.bind(c.ledger);
    vi.spyOn(c.ledger, "submit").mockImplementation(async tx => { h.setTime(NOW + 150n); return submit(tx); });
    expect((await action(s, "beer")).status).toBe(409);
    expect(h.state(payment)).toMatchObject({ held: DEMO_BUDGET, refundable: 0n });
    expect(await view(s)).toMatchObject({ actions: { beer: false, reclaim: true } });
    expect(h.ledger.submissions).toHaveLength(2); expect(c.orders.attempted(s.id, "beer")).toBe(true);
  });
  test("payer reclaim winning a merchant capture race prevents a second transition", async () => {
    const s = await offer(); await authorize(s); const payment = (await view(s)).payment;
    const submit = c.ledger.submit.bind(c.ledger);
    vi.spyOn(c.ledger, "submit").mockImplementation(async tx => {
      h.setTime(NOW + 150n);
      h.ok(await h.direct([await reclaimInstruction({ programId: c.programId, payment, payer: h.payer.address, server: h.server.address, mint: h.mint })], [h.payer]));
      return submit(tx);
    });
    expect((await action(s, "beer")).status).toBe(409);
    expect(h.state(payment)).toMatchObject({ held: 0n, refundable: 0n });
    expect(h.tokens(await h.serverAta())).toBe(0n);
    expect(await view(s)).toMatchObject({ status: "closed", remaining: 0, released: 100 });
    expect(h.ledger.submissions).toHaveLength(2);
  });
});

describe("#52 exact-offer provenance through restaurant persistence and relay", () => {
  test("restart uses the original offer observation; client substitution cannot overwrite it", async () => {
    const s = await offer(); const original = c.orders.read(s.id).authorizeLifetime!;
    expect(original.messageHash).toBe((await import("../src/submission-journal.ts")).messageHash(getTransactionDecoder().decode(getBase64Encoder().encode(s.unsigned)).messageBytes));
    const journal = new FileSubmissionJournal(join(dir, "relay"));
    const { Facilitator } = await import("../src/facilitator.ts");
    const f = new Facilitator({ network: c.network, programId: c.programId, feePayer: h.facilitatorKey,
      ledger: h.ledger, journal, observationKey: c.bearerToken, ...demoSponsorComputeBounds() });
    const { LIFETIME_EXTENSION, attestObservation } = await import("../src/lifetime-provenance.ts");
    c.fetchImpl = async (_url, init) => {
      const body = JSON.parse(init!.body as string);
      expect(body.lifetimeObservation).toEqual(attestObservation(original, c.bearerToken));
      expect(body.paymentPayload.extensions).toBeUndefined();
      expect(c.orders.read(s.id).events[0]!.lifetimeObservation).toEqual(original);
      return Response.json(await f.settle(body));
    };
    c.getLatestBlockhash = vi.fn(async () => { throw new Error("must not refetch an authorize lifetime"); });
    app = createRestaurantApp(c); // persisted offer survives application restart.
    const signed = await sign(s.unsigned);
    const response = await app.request(`${origin}/resource?order=${s.id}`, { method: "POST", headers: { cookie: s.cookie, origin,
      "PAYMENT-SIGNATURE": encodeHeader({ x402Version: 2, resource: s.required.resource, accepted: s.required.accepts[0],
        payload: { transaction: signed }, extensions: { [LIFETIME_EXTENSION]: { observation: { ...original, lastValidBlockHeight: "1" }, attestation: "forged" } } }) } });
    expect(response.status).toBe(200); expect(c.getLatestBlockhash).not.toHaveBeenCalled();
    const entry = journal.list()[0]!;
    expect(entry.lifetimeProvenance!.observation).toEqual({ state: "recorded", source: "first-party", value: original });
    expect(entry.messageHash).toBe(original.messageHash);
    expect(c.orders.read(s.id).events[0]!.transactionBase64).toBe(signed);
  });
  test("legacy offer never borrows caller observation or fetches new provenance", async () => {
    const s = await offer(); const order = c.orders.read(s.id); delete order.authorizeLifetime; c.orders.write(order);
    const { LIFETIME_EXTENSION } = await import("../src/lifetime-provenance.ts");
    let sent: any;
    c.fetchImpl = async (_url, init) => { sent = JSON.parse(init!.body as string); return Response.json(await h.facilitator.settle(sent)); };
    c.getLatestBlockhash = vi.fn(async () => { throw new Error("must not backfill"); });
    const response = await app.request(`${origin}/resource?order=${s.id}`, { method: "POST", headers: { cookie: s.cookie, origin,
      "PAYMENT-SIGNATURE": encodeHeader({ x402Version: 2, resource: s.required.resource, accepted: s.required.accepts[0],
        payload: { transaction: await sign(s.unsigned) }, extensions: { [LIFETIME_EXTENSION]: { observation: { version: 1, source: "first-party" } } } }) } });
    expect(response.status).toBe(200); expect(sent.lifetimeObservation).toBeUndefined();
    expect(c.orders.read(s.id).events[0]!.lifetimeObservation).toBeUndefined(); expect(c.getLatestBlockhash).not.toHaveBeenCalled();
  });
  test.each(["beer", "finish", "void", "refund"])("%s persists builder observation before relay", async a => {
    const s = await offer(a === "refund" ? "refund" : "normal"); expect((await authorize(s)).status).toBe(200);
    if (a === "refund" || a === "finish") await expectAction(s, "beer");
    if (a === "finish") await expectAction(s, "salmon");
    const { attestObservation } = await import("../src/lifetime-provenance.ts");
    c.fetchImpl = async (_url, init) => {
      const body = JSON.parse(init!.body as string);
      const event = c.orders.read(s.id).events.at(-1)!;
      expect(event.action).toBe(a); expect(event.lifetimeObservation).toBeDefined();
      expect(body.lifetimeObservation).toEqual(attestObservation(event.lifetimeObservation!, c.bearerToken));
      expect(event.transactionBase64).toBe(body.paymentPayload.payload.transaction);
      return Response.json(await h.facilitator.settle(body));
    };
    await expectAction(s, a);
  });
});


describe("application partial refund", () => {
  const refund = (s: Session, body?: unknown) => app.request(`${origin}/api/orders/${s.id}/actions/refund`, {
    method: "POST", headers: { origin, authorization: `Bearer ${merchantToken}`, "content-type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  test("100 → capture 40 → capture 25 → void 35 → refund 10; one attempt survives restart", async () => {
    const s = await offer(); expect((await authorize(s)).status).toBe(200);
    await expectAction(s, "beer"); await expectAction(s, "salmon"); await expectAction(s, "finish");
    const before = await view(s);
    expect(before).toMatchObject({ captured: 65, released: 35, remaining: 0, refundableBaseUnits: "65000000" });
    expect((await refund(s)).status).toBe(200);
    const after = await view(s);
    expect(after).toMatchObject({ captured: 65, refunded: 10, released: 35, remaining: 0, refundableBaseUnits: "55000000" });
    expect(after.balances.payer.amount).toBe(before.balances.payer.amount + 10);
    expect(after.balances.merchant.amount).toBe(before.balances.merchant.amount - 10);
    const submitted = h.ledger.submissions.length;
    app = createRestaurantApp({ ...c, orders: new RestaurantOrders(c.orders.dir) });
    expect((await refund(s)).status).toBe(409);
    expect(h.ledger.submissions).toHaveLength(submitted);
  });
  test.each([{ amount: "1" }, { amount: "10000000" }, { amount: "0" }, { amount: "-1" }, { amount: "1.5" }, { amount: 10 }, { amount: "010" }, { amount: "18446744073709551616" }, { amount: "10000000", extra: true }, {}, null])("caller-supplied amount refuses without an attempt: %j", async body => {
    const s = await offer("refund"); await authorize(s); await expectAction(s, "beer");
    const count = h.ledger.submissions.length, simulated = h.ledger.simulated.length;
    expect((await refund(s, body)).status).toBe(400);
    expect(c.orders.attempted(s.id, "refund")).toBe(false);
    expect(c.orders.busy(s.id)).toBe(false);
    expect(h.ledger.submissions).toHaveLength(count); expect(h.ledger.simulated).toHaveLength(simulated);
  });
  test("lost partial-refund response retains the original attempt without retry", async () => {
    const s = await offer(); await authorize(s); await expectAction(s, "beer"); await expectAction(s, "salmon"); await expectAction(s, "finish");
    h.ledger.failSubmit = "after-landing";
    expect((await refund(s)).status).toBe(409);
    const order = c.orders.read(s.id), original = order.events.at(-1)!;
    expect(original).toMatchObject({ action: "refund", amount: "10000000", status: "pending" });
    expect(original.transaction).not.toBe("");
    const bytes = readFileSync(c.orders.path(s.id), "utf8"), count = h.ledger.submissions.length;
    app = createRestaurantApp({ ...c, orders: new RestaurantOrders(c.orders.dir) });
    expect((await refund(s)).status).toBe(409);
    expect(readFileSync(c.orders.path(s.id), "utf8")).toBe(bytes); expect(h.ledger.submissions).toHaveLength(count);
  });
});


test("concurrent fixed normal refunds share one durable reservation", async () => {
  const s = await offer(); await authorize(s); await expectAction(s, "beer"); await expectAction(s, "salmon"); await expectAction(s, "finish");
  const before = h.ledger.submissions.length;
  const responses = await Promise.all([action(s, "refund"), action(s, "refund")]);
  expect(responses.map(r => r.status).sort()).toEqual([200,409]);
  expect(h.ledger.submissions).toHaveLength(before + 1);
  expect(c.orders.read(s.id).events.filter(e => e.action === "refund")).toHaveLength(1);
});

// Exact b5002d3c review regressions: scenario-selected amount, not caller-selected API.
describe("Gate 1 refund scope review", () => {
  async function normalFinished() {
    const s = await offer(); await authorize(s);
    await expectAction(s, "beer"); await expectAction(s, "salmon"); await expectAction(s, "finish");
    return s;
  }
  test("bodyless normal refund selects exactly 10", async () => {
    const s = await normalFinished();
    await expectAction(s, "refund");
    expect(await view(s)).toMatchObject({ refunded: 10, refundableBaseUnits: "55000000" });
  });
  test("normal refund eligibility needs 10 liquidity even when F is 65", async () => {
    const s = await normalFinished();
    h.ok(await h.direct([getTransferInstruction({ source: await h.serverAta(), destination: await h.payerAta(), authority: h.server, amount: 55n * DEMO_UNIT })], [h.server]));
    expect(await view(s)).toMatchObject({ refundableBaseUnits: "65000000", balances: { merchant: { amount: 10 } }, actions: { refund: true } });
    await expectAction(s, "refund");
    expect(await view(s)).toMatchObject({ refunded: 10, refundableBaseUnits: "55000000", balances: { merchant: { amount: 0 } } });
  });
  test("normal refund rejects less than 10 liquidity before signing", async () => {
    const s = await normalFinished();
    h.ok(await h.direct([getTransferInstruction({ source: await h.serverAta(), destination: await h.payerAta(), authority: h.server, amount: 55n * DEMO_UNIT + 1n })], [h.server]));
    const sign = vi.fn(c.server.signTransactions), simulate = vi.spyOn(c.ledger, "simulate"), before = h.ledger.submissions.length;
    app = createRestaurantApp({ ...c, server: { ...c.server, signTransactions: sign } });
    expect(await view(s)).toMatchObject({ actions: { refund: false } });
    expect((await action(s, "refund")).status).toBe(409);
    expect(sign).not.toHaveBeenCalled(); expect(simulate).not.toHaveBeenCalled(); expect(h.ledger.submissions).toHaveLength(before);
    expect(c.orders.attempted(s.id, "refund")).toBe(false);
  });
  test("normal refund rejects finalized F below 10 before signing", async () => {
    const s = await normalFinished(); const payment = (await view(s)).payment as Address;
    h.ok(await h.direct([await refundInstruction({ programId: c.programId, payment, payer: h.payer.address, server: h.server.address, mint: h.mint }, 60n * DEMO_UNIT, 0n, 65n * DEMO_UNIT)], [h.server]));
    const sign = vi.fn(c.server.signTransactions), simulate = vi.spyOn(c.ledger, "simulate");
    app = createRestaurantApp({ ...c, server: { ...c.server, signTransactions: sign } });
    expect(await view(s)).toMatchObject({ refundableBaseUnits: "5000000", actions: { refund: false } });
    expect((await action(s, "refund")).status).toBe(409);
    expect(sign).not.toHaveBeenCalled(); expect(simulate).not.toHaveBeenCalled(); expect(c.orders.attempted(s.id, "refund")).toBe(false);
  });
  test("normal refund requires the normal capture and void sequence", async () => {
    const s = await offer(); await authorize(s); await expectAction(s, "beer");
    expect(await view(s)).toMatchObject({ actions: { refund: false } });
    expect((await action(s, "refund")).status).toBe(409);
    await expectAction(s, "salmon");
    expect((await action(s, "refund")).status).toBe(409);
    expect(c.orders.attempted(s.id, "refund")).toBe(false);
    await expectAction(s, "finish"); await expectAction(s, "refund");
  });
  test("dedicated refund still needs liquidity for full F", async () => {
    const s = await offer("refund"); await authorize(s); await expectAction(s, "beer");
    h.ok(await h.direct([getTransferInstruction({ source: await h.serverAta(), destination: await h.payerAta(), authority: h.server, amount: 30n * DEMO_UNIT })], [h.server]));
    expect(await view(s)).toMatchObject({ actions: { refund: false }, balances: { merchant: { amount: 10 } } });
    expect((await action(s, "refund")).status).toBe(409);
    expect(c.orders.attempted(s.id, "refund")).toBe(false);
  });
  test("dedicated refund scenario rejects arbitrary amount bodies before signing", async () => {
    const s = await offer("refund"); await authorize(s); await expectAction(s, "beer");
    const count = h.ledger.submissions.length;
    const r = await app.request(`${origin}/api/orders/${s.id}/actions/refund`, {
      method: "POST", headers: { origin, authorization: `Bearer ${merchantToken}`, "content-type": "application/json" }, body: '{"amount":"1"}',
    });
    expect(r.status).toBe(400); expect(h.ledger.submissions).toHaveLength(count);
    expect(c.orders.attempted(s.id, "refund")).toBe(false);
  });
});
