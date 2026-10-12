import { assertStoreAccess, domainFromEnvironment, withShared, type RecoveryDomain } from "./coordination.ts";
// Restaurant orchestration only. All economic movements use the unchanged SAC-006 builders,
// receipt validation, facilitator and SBF. A durable order binds one signed budget to its menu
// actions. HttpOnly per-order capabilities are application session control, not onchain authority.
import { transactionObservation, type LifetimeObservation } from "./lifetime-provenance.ts";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync, unlinkSync, openSync, fsyncSync, closeSync } from "node:fs";
import { join } from "node:path";
import { AsyncLocalStorage } from 'node:async_hooks';
import { Hono } from "hono";
import { AccountState, getTokenDecoder } from "@solana-program/token";
import { requireBearerToken } from "./auth.ts";
import { bodyLimit } from "hono/body-limit";
import { getCookie, setCookie } from "hono/cookie";
import { type Address, getBase64Encoder, getTransactionDecoder, getCompiledTransactionMessageDecoder, getSignatureFromTransaction, getPublicKeyFromAddress, verifySignature, isAddress, type SignatureBytes, type Transaction } from "@solana/kit";
import { createDurableFile, ensureDurableDirectory, replaceDurableFile } from "./durable-file.ts";
import { ata, TOKEN_PROGRAM_ADDRESS, decodePayment, paymentAddress, type Payment } from "./program.ts";
import { acceptedDeadlines, freshRequirements, peekAuthorize, settle, type ResourceServerConfig } from "./resource-server.ts";
import { encodeHeader, decodeHeader, parsePaymentPayload, PAYMENT_REQUIRED_HEADER, PAYMENT_SIGNATURE_HEADER, PAYMENT_RESPONSE_HEADER, type PaymentRequired } from "./http-transport.ts";
import { authorizeInstruction, encodeTransaction, captureInstruction, capturePayload, voidInstruction, voidPayload, refundInstruction, refundPayload, reclaimInstruction } from "./transactions.ts";
import { buildDemoTransaction } from "./demo-compute.ts";
import { messageHash, submissionOutcome, type SubmissionJournal } from "./submission-journal.ts";
import type { ChainReader } from "./reconciliation.ts";
import type { Ledger } from "./ledger.ts";
import { Reason, type PaymentRequirements, type SettleResponse } from "./types.ts";
import type { AdmissionJournal } from './admission-journal.ts';
import { b3RecoveryEvidence, type B3Recovery } from './b3-recovery.ts';
import type { RpcLedger } from './rpc-ledger.ts';
import { proveExpiredReclaimConsent } from './reclaim-consent-renewal.ts';
import { currentReclaimGeneration, nextReclaimArchive } from './reclaim-generations.ts';
import { abandonmentCustody, abandonmentEvidence, proveExpiredUnfundedAuthorize, sha256, type AuthorizeAbandonPolicy } from './authorize-abandon.ts';
import { authorizeIsolationEvidence, type InstalledIsolationPolicy } from './unknown-authorize-isolation.ts';

export const DEMO_UNIT = 1_000_000n;
export const DEMO_BUDGET = 100n * DEMO_UNIT;
export const SCENARIOS = ["normal", "refund", "cancelled", "unavailable", "partial-reclaim", "atomic"] as const;
type Scenario = typeof SCENARIOS[number];
type Action = "authorize" | "beer" | "salmon" | "finish" | "void" | "refund" | "reclaim" | "atomic";
type Event = { lifetimeObservation?: LifetimeObservation; action: Action; label: string; amount: string; at: string; status: "prepared" | "pending" | "finalized" | "rejected"; transaction: string; transactionBase64: string; receipt?: SettleResponse };
type Order = { authorizeLifetime?: LifetimeObservation; id: string; capabilityHash: string; payer: Address; payment: Address; scenario: Scenario; required: PaymentRequired; unsigned: string; createdAt: number; status: "draft" | "active" | "closed" | "pending" | "rejected"; events: Event[]; reclaimUnsigned?: string; reclaimLifetime?: { blockhash: string; lastValidBlockHeight: string; blockhashSlot?: string } };
export type RestaurantConfig = ResourceServerConfig & { ledger: Ledger & Pick<ChainReader, "getSignatureStatus"> & Pick<RpcLedger,"getAccountAtLeast"> & {offerBlockhashValid?: (hash: string) => Promise<boolean>; getClockAtLeast?:RpcLedger['getClockAtLeast']; getFinalizedBlockhashStatus?:RpcLedger['getFinalizedBlockhashStatus']}; orders: RestaurantOrders; reclaimJournal: SubmissionJournal; origin: string; merchantToken?: string; orderAdmission?: AdmissionJournal; b3Recovery?:B3Recovery; authorizeAbandonPolicy?:AuthorizeAbandonPolicy; authorizeIsolationPolicy?:InstalledIsolationPolicy };

export class RestaurantOrders {
  readonly dir: string;
  readonly coordination?: RecoveryDomain;
  constructor(dir: string, coordination = domainFromEnvironment()) { this.dir = dir; this.coordination = coordination; coordination?.assertMember(dir); ensureDurableDirectory(dir); }
  assertAccess(): void { assertStoreAccess(this.dir, this.coordination); }
  path(id: string): string { if (!/^[a-f0-9]{32}$/.test(id)) throw new Error("invalid order ID"); return join(this.dir, `${id}.json`); }
  read(id: string): Order { assertStoreAccess(this.dir, this.coordination); return JSON.parse(readFileSync(this.path(id), "utf8")) as Order; }
  create(order: Order): void { assertStoreAccess(this.dir, this.coordination); createDurableFile(this.path(order.id), JSON.stringify(order)); }
  write(order: Order): void { assertStoreAccess(this.dir, this.coordination); replaceDurableFile(this.path(order.id), JSON.stringify(order)); }
  reserve(id: string, action: Action): void { assertStoreAccess(this.dir, this.coordination);
    const busy = `${this.path(id)}.busy`;
    createDurableFile(busy, action); // Cross-process exclusive reservation before any network await.
    try { if (this.attempted(id, action)) throw new Error("action already reserved; inspect its original outcome"); }
    catch (e) { this.unlock(id); throw e; }
  }
  prepare(order: Order, event: Event): void { assertStoreAccess(this.dir, this.coordination);
    createDurableFile(`${this.path(order.id)}.${event.action}.lock`, JSON.stringify(event));
    order.events.push(event); order.status = "pending"; this.write(order);
  }
  unlock(id: string): void { assertStoreAccess(this.dir, this.coordination);
    unlinkSync(`${this.path(id)}.busy`);
    const fd = openSync(this.dir, "r"); try { fsyncSync(fd); } finally { closeSync(fd); }
  }
  attempted(id: string, action: Action): boolean { assertStoreAccess(this.dir, this.coordination); return existsSync(`${this.path(id)}.${action}.lock`); }
  busy(id: string): boolean { assertStoreAccess(this.dir, this.coordination); return existsSync(`${this.path(id)}.busy`); }
}
const decoder = getTransactionDecoder();
const decode = (wire: string): Transaction => decoder.decode(getBase64Encoder().encode(wire));
const digest = (s: string) => createHash("sha256").update(s).digest("hex");
const equalMessage = (a: Transaction, b: Transaction) => Buffer.from(a.messageBytes).equals(Buffer.from(b.messageBytes));
const money = (n: bigint) => Number(n) / Number(DEMO_UNIT);
const labels: Record<Action, string> = { authorize: "Budget authorized", beer: "Beer + Ribs", salmon: "Salmon", finish: "Order finished · remainder released", void: "Order cancelled · hold released", refund: "Consumed budget refunded", reclaim: "Payer reclaimed unused budget", atomic:"Atomic capture 40 + release 60" };
const merchantActions = ["beer", "salmon", "finish", "void", "refund", "atomic"] as const;
class RestaurantRefusal extends Error {}
const refundAmount = (order: Order, p: Payment) => order.scenario === "normal" ? 10n * DEMO_UNIT : p.refundable;

// One policy for read-only eligibility and signing preflight. Onchain Clock and (H,F)
// remain authoritative at execution, including races after this finalized snapshot.
function actionReasons(c: RestaurantConfig, order: Order, p: Payment | null, now: bigint, blocked: boolean) {
  const completed = (a: Action) => order.events.some(e => e.action === a && e.status === "finalized");
  function reason(a: Exclude<Action, "authorize">): string {
    if (blocked) return "Original operation pending or reserved; inspect its signatures.";
    if (!p) return "Wallet approval is not finalized authorization. Authorize the original offer first.";
    if (c.orders.attempted(order.id, a)) return "This action already has an original attempt; no retry is permitted.";
    if (a === "reclaim") {
      if (p.held <= 0n) return "No remaining hold to reclaim.";
      return now < p.captureDeadline ? "Payer reclaim opens at the onchain capture deadline." : "";
    }
    // Preserve the original application authorization gate for merchant signing.
    // A matching funded PDA does not reconcile a draft; payer reclaim is separate.
    if (order.status === "draft") return "Original application authorization is still draft; merchant signing is blocked.";
    if (order.scenario === "unavailable") return "Merchant unavailable scenario permits payer reclaim only.";
    if (a === "refund") {
      if (now >= p.refundDeadline) return "Onchain refund deadline expired.";
      if (order.scenario === "normal") {
        if (!completed("finish") || p.held !== 0n) return "Finalize captures 40 and 25 and void 35 before refund 10.";
        return p.refundable < refundAmount(order, p) ? "Refundable balance is below 10 test tokens." : "";
      }
      if (order.scenario !== "refund") return "Refund requires the normal or refund scenario.";
      return p.refundable <= 0n ? "No refundable captured balance." : "";
    }
    if (now >= p.captureDeadline) return "Onchain capture deadline expired; payer reclaim may be eligible.";
    if (p.held <= 0n) return "No remaining hold.";
    if (a === 'atomic') return order.scenario !== 'atomic' || p.held !== DEMO_BUDGET || p.refundable !== 0n ? 'Atomic scenario requires the original 100/0 hold.' : '';
    if (order.scenario === 'atomic') return 'Use the single atomic capture 40 + release 60 action.';
    if (order.scenario === 'partial-reclaim' && a !== 'beer') return 'Partial capture scenario permits capture 40, then payer reclaim after the real deadline.';
    if (a === "beer") {
      if (order.scenario === "cancelled") return "Cancelled scenario permits explicit void only.";
      return p.held < 40n * DEMO_UNIT ? "Remaining hold is below 40 test tokens." : "";
    }
    if (a === "salmon") {
      if (order.scenario !== "normal") return "Capture 25 belongs to the normal scenario.";
      if (!completed("beer")) return "Finalize capture 40 first.";
      return p.held < 25n * DEMO_UNIT ? "Remaining hold is below 25 test tokens." : "";
    }
    if (a === "finish") {
      if (order.scenario === "normal") return !completed("salmon") || p.held !== 35n * DEMO_UNIT ? "Finalize captures 40 and 25 before voiding the remaining 35." : "";
      return order.scenario !== "refund" || !completed("refund") ? "Complete the refund scenario before releasing the remaining hold." : "";
    }
    return ""; // Explicit void of a positive eligible hold.
  }
  return Object.fromEntries([...merchantActions, "reclaim"].map(a => [a, reason(a as Exclude<Action, "authorize">)]));
}

async function tokenBalance(c: RestaurantConfig, owner: Address) {
  try {
    const snapshot = await c.ledger.getAccountAtLeast(await ata(owner, c.asset), 0n);
    if (snapshot.kind !== "ok") return { amount: null, reason: "Finalized token balance unavailable." };
    if (!snapshot.account) return { amount: 0, reason: "Test-mint token account missing; operator funding required." };
    const decoder = getTokenDecoder();
    if (snapshot.account.owner !== TOKEN_PROGRAM_ADDRESS || snapshot.account.data.length !== decoder.fixedSize) return { amount: null, reason: "Test-mint token account invalid." };
    const t = decoder.decode(snapshot.account.data);
    if (t.owner !== owner || t.mint !== c.asset || t.state !== AccountState.Initialized) return { amount: null, reason: "Test-mint token account cannot transfer." };
    return { amount: money(t.amount), reason: "" };
  } catch { return { amount: null, reason: "Finalized token balance unavailable." }; }
}

type SignatureObservations=Map<string,Awaited<ReturnType<RestaurantConfig['ledger']['getSignatureStatus']>>>;
const requestSignatures=new AsyncLocalStorage<Map<RestaurantConfig['ledger'],SignatureObservations>>();
async function originalStatus(c:RestaurantConfig,signature:string) {
  const scope=requestSignatures.getStore();let observations=scope?.get(c.ledger);
  if(scope && !observations){observations=new Map();scope.set(c.ledger,observations);}
  const known=observations?.get(signature);if(known)return known;
  const status=await c.ledger.getSignatureStatus(signature);
  // Finalized outcomes are immutable. Do not cache weak/missing/unavailable
  // evidence, and never carry any observation into a later HTTP request.
  if(status.kind==='found' && status.commitment==='finalized')observations?.set(signature,status);
  return status;
}
export async function restaurantSnapshot(c: RestaurantConfig, order: Order, observations?:SignatureObservations): Promise<Payment | null> {
  let slot = 0n;
  for (const e of order.events) if (e.transaction) {
    const status = observations?.get(e.transaction) ?? await originalStatus(c,e.transaction);
    if (e.status === "finalized" && (status.kind !== "found" || status.commitment !== "finalized" || status.err !== null)) throw new Error("original finalized signature evidence unavailable; inspect before new actions");
    if (status.kind === "found" && status.commitment === "finalized" && status.slot > slot) slot = status.slot;
  }
  const snapshot = await c.ledger.getAccountAtLeast(order.payment, slot);
  if (snapshot.kind !== "ok") throw new Error("finalized payment state unavailable; inspect original signatures");
  if (!snapshot.account) return null;
  const p = decodePayment(snapshot.account.data);
  if (!p || snapshot.account.owner !== c.programId || p.payer !== order.payer || p.server !== c.server.address || p.mint !== c.asset || p.maximum !== DEMO_BUDGET || String(p.captureDeadline) !== String(order.required.accepts[0]!.extra!.captureDeadline) || String(p.refundDeadline) !== String(order.required.accepts[0]!.extra!.refundDeadline)) throw new Error("payment identity differs from this order");
  return p;
}
async function orderClock(c: RestaurantConfig,order:Order,observations?:SignatureObservations): Promise<bigint> {
  if (!c.ledger.getClockAtLeast) return c.now(); // Local ledger fixture implements its own Clock.
  let slot=0n;
  for(const e of order.events) if(e.transaction) {
    const status=observations?.get(e.transaction) ?? await originalStatus(c,e.transaction);
    if(e.status==='finalized' && (status.kind!=='found' || status.commitment!=='finalized' || status.err!==null)) throw Error('original finalized Clock fence unavailable');
    if(status.kind==='found' && status.commitment==='finalized' && status.slot>slot)slot=status.slot;
  }
  const clock=await c.ledger.getClockAtLeast(slot,Date.now()+10_000);
  if(clock.kind!=='ok' || clock.commitment!=='finalized' || clock.slot<slot)throw Error('finalized Clock evidence unavailable');
  return clock.unixTimestamp;
}

export function createRestaurantApp(c: RestaurantConfig): Hono {
  if (c.amount !== DEMO_BUDGET) throw new Error("restaurant budget must be exactly 100 six-decimal demo USDC");
  // Separate application authority: an order capability never authorizes merchant signing.
  const merchantToken = c.merchantToken;
  if (merchantToken !== undefined && (merchantToken.length < 32 || merchantToken.trim() !== merchantToken || /[\r\n]/.test(merchantToken) || merchantToken === c.bearerToken)) {
    throw new Error("merchant token must be independent and at least 32 characters");
  }
  const merchantAuth = merchantToken ? requireBearerToken(merchantToken) : undefined;
  const app = new Hono();
  // Acquire before any order/draft read; all callbacks and durable results stay in this scope.
  if (c.orders.coordination !== c.reclaimJournal.coordination && c.orders.coordination?.metadata.domain !== c.reclaimJournal.coordination?.metadata.domain) throw new Error("restaurant journals require one complete domain");
  app.use("*", async (_ctx, next) => requestSignatures.run(new Map(),()=>withShared(c.orders.coordination, async () => { c.orders.assertAccess(); c.reclaimJournal.assertAccess?.(); await next(); })));
  const cookieName = "capture402-order";
  const secured = c.origin.startsWith("https:");
  function owned(id: string, cookie: string | undefined): Order {
    const order = c.orders.read(id);
    if (!cookie || cookie.length > 256) throw new Error("this order requires its wallet-created demo session");
    const actual = Buffer.from(digest(cookie)); const expected = Buffer.from(order.capabilityHash);
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) throw new Error("this order requires its wallet-created demo session");
    return order;
  }
  app.use("*", bodyLimit({ maxSize: 32_768, onError: ctx => ctx.json({ error: "request too large" }, 413) }));
  app.use("*", async (ctx, next) => {
    ctx.header("Cache-Control", "no-store");
    if (ctx.req.method === "POST" && ctx.req.header("origin") !== c.origin) return ctx.json({ error: "same-origin demo action required" }, 403);
    if (Number(ctx.req.header("content-length") ?? 0) > 32_768) return ctx.json({ error: "request too large" }, 413);
    await next();
  });
  // SDK/provider errors can embed private credential URLs. Never echo them to the browser.
  app.onError((error, ctx) => ctx.json({ error: error instanceof RestaurantRefusal ? error.message : error.message.includes("ENOENT") ? "order unavailable" : error.message.includes("EEXIST") ? "action reserved; inspect original outcome before any new consent" : "Finalized RPC evidence unavailable or order conflict; refresh and inspect original signatures." }, 409));

  async function publicSignatureStatus(signature: string, observation?:Awaited<ReturnType<RestaurantConfig['ledger']['getSignatureStatus']>>) {
    const status = observation ?? await originalStatus(c,signature);
    if (status.kind === "unavailable") return { kind: "unavailable", detail: "RPC signature evidence unavailable" };
    return JSON.parse(JSON.stringify(status, (_k,v) => typeof v === "bigint" ? v.toString() : v));
  }
  function retainedReclaimGeneration(order:Order) {
    return currentReclaimGeneration(c.orders.path(order.id),order,
      wire=>c.reclaimJournal.findByMessageHash(messageHash(decode(wire).messageBytes)).length > 0);
  }
  async function view(order: Order) {
    // One fresh observation per original signature in this response, shared by
    // the payment/Clock fences and receipts. Nothing is cached across requests.
    const observations:SignatureObservations=new Map();
    for(const e of order.events)if(e.transaction && !observations.has(e.transaction))observations.set(e.transaction,await originalStatus(c,e.transaction));
    const p = await restaurantSnapshot(c, order,observations);
    const now = await orderClock(c,order,observations);
    const blocked = order.status === "pending" || c.orders.busy(order.id);
    const captured = order.events.filter(e => e.status === "finalized" && ["beer", "salmon", "atomic"].includes(e.action)).reduce((s,e) => s + BigInt(e.amount), 0n);
    const refunded = order.events.filter(e => e.status === "finalized" && e.action === "refund").reduce((s,e) => s + BigInt(e.amount), 0n);
    const reasons = actionReasons(c, order, p, now, blocked);
    const balances = { payer: await tokenBalance(c, order.payer), merchant: await tokenBalance(c, c.server.address) };
    if (!reasons.refund && (balances.merchant.amount === null || balances.merchant.amount < money(refundAmount(order, p!)))) reasons.refund = balances.merchant.reason || "Merchant test-token balance cannot fund this refund.";
    const path=c.orders.path(order.id);
    const abandoned=abandonmentEvidence(c.authorizeAbandonPolicy,order,path);
    const isolated=authorizeIsolationEvidence(c.authorizeIsolationPolicy,order,path);
    if(isolated && p)throw Error('Isolated original now has a payment; continuation stopped.');
    if(abandoned && p) throw Error('Abandoned identity now has a payment; continuation stopped.');
    const successorReserved=!!(abandoned || isolated) && existsSync(`${path}.authorize-successor.lock`);
    const generation=retainedReclaimGeneration(order);
    const consentUsed=!!generation && (existsSync(`${path}.reclaim-consent-${digest(generation.newUnsigned)}.lock`) ||
      c.reclaimJournal.findByMessageHash(messageHash(decode(generation.newUnsigned).messageBytes)).length > 0);
    const draftValid=generation && !consentUsed && !blocked && !c.orders.attempted(order.id,'reclaim') && !order.events.some(e=>e.action==='reclaim') && c.ledger.offerBlockhashValid
      ? await c.ledger.offerBlockhashValid(generation.newLifetime.blockhash) : undefined;
    return { id: order.id, payer: order.payer, payment: order.payment, scenario: order.scenario,
      reclaimGeneration: generation ? digest(generation.newUnsigned) : undefined,
      reclaimDraftState: generation ? consentUsed || blocked || c.orders.attempted(order.id,'reclaim') || order.events.some(e=>e.action==='reclaim') ? 'stopped' : draftValid === true ? 'ready' : draftValid === false ? 'expired-or-unavailable' : 'stopped' : undefined,
      reclaimPreparation: !blocked && !reasons.reclaim && existsSync(`${path}.reclaim-consent.lock`) && !consentUsed && !order.events.some(e=>e.action==='reclaim') && (!generation || draftValid === false),
      authorizeAbandoned: abandoned,
      authorizeIsolation:isolated && !successorReserved ? isolated : undefined,
      authorizeAbandonEligible: !blocked && !p && !abandoned && now>=BigInt(order.required.accepts[0]!.extra!.refundDeadline as number) && !!abandonmentCustody(c.authorizeAbandonPolicy,order,path),
      status: blocked || successorReserved ? "pending" : abandoned ? 'abandoned' : p ? p.held === 0n ? "closed" : "active" : order.status,
      authorized: p ? money(p.maximum) : 0, captured: money(captured), remaining: p ? money(p.held) : 0, refunded: money(refunded), released: p ? money(p.maximum - p.held - captured) : 0,
      heldBaseUnits: p?.held.toString(), refundableBaseUnits: p?.refundable.toString(),
      captureDeadline: Number(order.required.accepts[0]!.extra!.captureDeadline), refundDeadline: Number(order.required.accepts[0]!.extra!.refundDeadline), now: Number(now),
      actions: Object.fromEntries(Object.entries(reasons).map(([action, reason]) => [action, !reason])), actionReasons: reasons, balances,
      events: await Promise.all(order.events.map(async e => ({ action: e.action, label: e.label, amount: money(BigInt(e.amount)), at: e.at, status: e.status, signature: e.transaction, ...(e.transaction ? { chainStatus: await publicSignatureStatus(e.transaction,observations.get(e.transaction)) } : {}) }))),
      ...(b3RecoveryEvidence(c.b3Recovery,order,c.orders.path(order.id),blocked) ? {b3Recovery:b3RecoveryEvidence(c.b3Recovery,order,c.orders.path(order.id),blocked)} : {}),
      ...(order.status === "draft" && !abandoned ? { required: order.required, unsigned: order.unsigned } : {}),
    };
  }
  async function recordResult(order: Order, event: Event, receipt: SettleResponse, kind: "succeeded" | "rejected" | "unresolved") {
    event.receipt = receipt; event.transaction = receipt.transaction;
    event.status = kind === "succeeded" ? "finalized" : kind === "rejected" ? "rejected" : "pending";
    order.status = kind === "unresolved" ? "pending" : event.action === "authorize" && kind === "rejected" ? "rejected" : "active";
    c.orders.write(order);
    if (kind !== "unresolved") c.orders.unlock(order.id); // Uncertainty/crash retains the reservation permanently.
  }
  app.get("/resource", async ctx => {
    // Discovery never prepares a wallet transaction, creates an order or issues a capability.
    // In particular, SameSite=Strict cookies are absent on cross-site top-level navigation.
    const required: PaymentRequired = { x402Version: 2, resource: { url: `${c.origin}/resource`, description: "Pivovar Marina hackathon budget", mimeType: "application/json" }, accepts: [await freshRequirements(c)] };
    ctx.header(PAYMENT_REQUIRED_HEADER, encodeHeader(required)); return ctx.json(required, 402);
  });
  app.post("/api/orders", async ctx => {
    // The exact Origin gate above runs before parsing, chain reads, simulation or durable writes.
    if (ctx.req.header("sec-fetch-site") === "cross-site") return ctx.json({ error: "same-origin demo action required" }, 403);
    if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(ctx.req.header("content-type") ?? "")) return ctx.json({ error: "JSON order request required" }, 415);
    let body: unknown;
    try { body = await ctx.req.json(); } catch { return ctx.json({ error: "invalid JSON order request" }, 400); }
    if (!body || typeof body !== "object" || Array.isArray(body) || Object.keys(body).some(key => key !== "payer" && key !== "scenario")) return ctx.json({ error: "invalid order request" }, 400);
    const { payer, scenario = "normal" } = body as { payer?: unknown; scenario?: unknown };
    if (typeof payer !== "string" || !isAddress(payer) || typeof scenario !== "string" || !(SCENARIOS as readonly string[]).includes(scenario)) return ctx.json({ error: "connect a Solana wallet and select a demo scenario" }, 400);
    const previous = getCookie(ctx, cookieName);
    let abandonedPredecessor:string|undefined;
    if (previous?.includes(".")) {
      {
        const old = owned(previous.split(".")[0]!, previous);
        const p = await restaurantSnapshot(c, old);
        const abandoned=abandonmentEvidence(c.authorizeAbandonPolicy,old,c.orders.path(old.id));
        const isolated=authorizeIsolationEvidence(c.authorizeIsolationPolicy,old,c.orders.path(old.id));
        if(isolated) {
          if(payer!==old.payer)return ctx.json({error:'Selected original payer required for its one explicit successor.'},409);
          if(!c.ledger.getFinalizedBlockhashStatus)throw Error('Fresh canonical isolation evidence unavailable.');
          const expiry=await c.ledger.getFinalizedBlockhashStatus(old.authorizeLifetime!.blockhash,BigInt(isolated.proof.originSlot),Date.now()+10000);
          if(expiry.kind!=='ok' || expiry.valid || expiry.slot<BigInt(isolated.proof.expirySlot))throw Error('Fresh canonical original expiry unavailable.');
          const fenced=await c.ledger.getAccountAtLeast(old.payment,expiry.slot,Date.now()+10000);
          if(fenced.kind!=='ok' || fenced.slot<expiry.slot || fenced.account!==null)throw Error('Original successful authorization cannot be excluded.');
          const status=await c.ledger.getSignatureStatus(isolated.originalSignature);
          if(status.kind==='found' && (status.commitment!=='finalized' || status.err===null))throw Error('Original signature contradicts isolation; inspect it.');
        }
        if(abandoned || isolated) {
          if(p || existsSync(`${c.orders.path(old.id)}.authorize-successor.lock`)) return ctx.json({error:'Original successor or payment already reserved; inspect it without replacement.'},409);
          abandonedPredecessor=old.id;
        }
        if (!isolated && (c.orders.busy(old.id) || old.status === "pending") || (p && p.held > 0n)) return ctx.json({ error: "finish or reconcile the existing budget before opening another" }, 409);
        if (old.status === "draft" && !abandonmentEvidence(c.authorizeAbandonPolicy,old,c.orders.path(old.id)) && (existsSync(`${c.orders.path(old.id)}.wallet-consent.lock`) || old.events.length !== 0 || await c.now() < BigInt(old.required.accepts[0]!.extra!.captureDeadline as number))) return ctx.json({ error: "Original unsigned offer is still valid or has an attempt; inspect it before replacement." }, 409);
      }
    }
    const id = randomBytes(16).toString("hex"); const capability = `${id}.${randomBytes(32).toString("hex")}`;
    const salt = randomBytes(32); const requirements = await freshRequirements(c);
    const balance = await tokenBalance(c, payer);
    if (balance.amount === null || balance.amount < 100) return ctx.json({ error: balance.reason || "Payer needs 100 test-mint tokens; operator funding required. No authorization submitted." }, 402);
    const required: PaymentRequired = { x402Version: 2, resource: { url: `${c.origin}/resource`, description: "Pivovar Marina · 100 test-token Devnet budget", mimeType: "application/json" }, accepts: [requirements] };
    const tx = await buildDemoTransaction({ feePayer: c.feePayer, signers: [], lifetime: await c.getLatestBlockhash(), instructions: [await authorizeInstruction({ programId: c.programId, payer, server: c.server.address, mint: c.asset, funder: c.feePayer, salt, maximum: DEMO_BUDGET, captureDeadline: BigInt(requirements.extra!.captureDeadline as number), refundDeadline: BigInt(requirements.extra!.refundDeadline as number) })] }, c.ledger);
    const order: Order = { id, capabilityHash: digest(capability), payer, payment: await paymentAddress(c.programId, payer, salt), scenario: scenario as Scenario, required, unsigned: encodeTransaction(tx), authorizeLifetime: transactionObservation(tx), createdAt: Number(await c.now()), status: "draft", events: [] };
    // One durable successor intent before admission/publication. Concurrent POSTs
    // cannot consume two extra A slots; crash/lost response never creates another.
    if(abandonedPredecessor) createDurableFile(`${c.orders.path(abandonedPredecessor)}.authorize-successor.lock`,JSON.stringify({schema:1,previousOrder:abandonedPredecessor,nextOrder:id}));
    c.orderAdmission?.reserve(); // Durable cap before offer publication/wallet signing; never refunded.
    c.orders.create(order);
    setCookie(ctx, cookieName, capability, { httpOnly: true, secure: secured, sameSite: "Strict", path: "/", maxAge: 86400 });
    ctx.header(PAYMENT_REQUIRED_HEADER, encodeHeader(required));
    return ctx.json({ order: id, required, unsigned: order.unsigned }, 402);
  });
  app.get("/api/orders/:id", async ctx => ctx.json(await view(owned(ctx.req.param("id"), getCookie(ctx, cookieName)))));
  app.get('/api/orders/:id/signing-preflight', async ctx => {
    const order = owned(ctx.req.param('id'),getCookie(ctx,cookieName));
    const reclaim = ctx.req.query('operation') === 'reclaim';
    const dispatch = reclaim && ctx.req.query('phase') === 'dispatch';
    const unsigned = reclaim ? order.reclaimUnsigned : order.unsigned;
    if(!reclaim && existsSync(`${c.orders.path(order.id)}.authorize-abandon.lock`)) return ctx.json({error:'Original expired authorization was abandoned; fresh signing is stopped.'},409);
    const p = await restaurantSnapshot(c,order);
    if (reclaim) {
      const generation=retainedReclaimGeneration(order);
      const marker=`${c.orders.path(order.id)}.${generation ? `reclaim-consent-${digest(unsigned ?? '')}` : 'reclaim-consent'}.lock`;
      if(dispatch) {
        const consent=existsSync(marker) ? JSON.parse(readFileSync(marker,'utf8')) : undefined;
        if(!unsigned || !consent || Object.keys(consent).sort().join()!=='order,unsignedSha256' || consent.order!==order.id || consent.unsignedSha256!==digest(unsigned)) return ctx.json({error:'Exact retained consent required for dispatch preflight.'},409);
      } else if(existsSync(marker)) return ctx.json({error:'Retained consent already used; signing stopped.'},409);
    }
    if (!unsigned || c.orders.busy(order.id) || order.status === 'pending' ||
      (reclaim ? !p || !!actionReasons(c,order,p,await orderClock(c,order),false).reclaim : order.status !== 'draft' || order.events.length !== 0 || p !== null || await orderClock(c,order) >= BigInt(order.required.accepts[0]!.extra!.captureDeadline as number))) {
      return ctx.json({error:'Original offer is not eligible for fresh consent.'},409);
    }
    const message = getCompiledTransactionMessageDecoder().decode(decode(unsigned).messageBytes);
    if (!c.ledger.offerBlockhashValid || !await c.ledger.offerBlockhashValid(message.lifetimeToken)) return ctx.json({error:'Original blockhash expired or unavailable; no replacement is automatic.'},409);
    return ctx.json({id:order.id,operation:reclaim?'reclaim':'authorize',phase:dispatch?'dispatch':'consent',unsignedSha256:digest(unsigned),fresh:!dispatch});
  });
  app.post('/api/orders/:id/wallet-consent',async ctx => {
    let order = owned(ctx.req.param('id'),getCookie(ctx,cookieName));
    const body = await ctx.req.json();
    const reclaim=ctx.req.query('operation')==='reclaim';
    c.orders.reserve(order.id,reclaim?'reclaim':'authorize');
    try {
      // Serialize the consent marker against draft replacement and merchant actions.
      order=c.orders.read(order.id);
      if(!reclaim && existsSync(`${c.orders.path(order.id)}.authorize-abandon.lock`)) return ctx.json({error:'Original authorization abandoned; no fresh consent.'},409);
      const unsigned=reclaim?order.reclaimUnsigned:order.unsigned;
      if (!unsigned || Object.keys(body).sort().join() !== 'unsignedSha256' || body.unsignedSha256 !== digest(unsigned) || order.status==='pending') return ctx.json({error:'Original consent state differs.'},409);
      if (reclaim) {
        const p=await restaurantSnapshot(c,order);
        if (!p || actionReasons(c,order,p,await orderClock(c,order),false).reclaim) return ctx.json({error:'Original reclaim consent is not eligible.'},409);
      } else if(order.status!=='draft' || order.events.length || await orderClock(c,order)>=BigInt(order.required.accepts[0]!.extra!.captureDeadline as number)) return ctx.json({error:'Original consent state differs.'},409);
      const renewed=reclaim && !!retainedReclaimGeneration(order);
      if(reclaim) {
        const message=getCompiledTransactionMessageDecoder().decode(decode(unsigned).messageBytes);
        if(!c.ledger.offerBlockhashValid || !await c.ledger.offerBlockhashValid(message.lifetimeToken)) return ctx.json({error:'Expired or unavailable draft cannot receive fresh consent.'},409);
      }
      const marker=renewed ? `reclaim-consent-${digest(unsigned)}` : reclaim?'reclaim-consent':'wallet-consent';
      createDurableFile(`${c.orders.path(order.id)}.${marker}.lock`,JSON.stringify({order:order.id,unsignedSha256:body.unsignedSha256}));
      return ctx.json({reserved:true});
    } finally {c.orders.unlock(order.id);}
  });
  app.post('/api/orders/:id/abandon-authorize',async ctx => {
    let order=owned(ctx.req.param('id'),getCookie(ctx,cookieName));
    if(await ctx.req.text()!=='')return ctx.json({error:'No supplied wire, terms or proof accepted.'},400);
    c.orders.reserve(order.id,'authorize');
    try {
      order=c.orders.read(order.id);
      const path=c.orders.path(order.id),custody=abandonmentCustody(c.authorizeAbandonPolicy,order,path);
      if(!custody || existsSync(`${path}.authorize-abandon.lock`) || !c.ledger.getFinalizedBlockhashStatus || !c.ledger.getClockAtLeast ||
        c.store.list().some(e=>e.authorize?.payment===order.payment || e.terminal?.payment===order.payment) ||
        c.reclaimJournal.findByMessageHash(messageHash(decode(order.unsigned).messageBytes)).length) return ctx.json({error:'Selected original custody is not an unused draft; preserve it.'},409);
      const proof=await proveExpiredUnfundedAuthorize({order,programId:c.programId,server:c.server.address,mint:c.asset,funder:c.feePayer,network:c.network,maximum:DEMO_BUDGET,
        captureDeadline:BigInt(order.required.accepts[0]!.extra!.captureDeadline as number),refundDeadline:BigInt(order.required.accepts[0]!.extra!.refundDeadline as number),
        reader:{getAccountAtLeast:(...args)=>c.ledger.getAccountAtLeast(...args),getFinalizedBlockhashStatus:(...args)=>c.ledger.getFinalizedBlockhashStatus!(...args),getClockAtLeast:(...args)=>c.ledger.getClockAtLeast!(...args)}});
      // The one fsynced immutable classification is the entire commit. The original
      // order, wire, deadlines and consent are never mutated. Partial files block.
      createDurableFile(`${path}.authorize-abandon.lock`,JSON.stringify({schema:1,policySha256:sha256(JSON.stringify(c.authorizeAbandonPolicy)),...custody,proof}));
      return ctx.json({abandoned:true,proof});
    } finally {c.orders.unlock(order.id);}
  });
  app.post("/resource", async ctx => {
    const order = owned(ctx.req.query("order") ?? "", getCookie(ctx, cookieName));
    if (order.status !== "draft") return ctx.json({ error: "budget already submitted; inspect the original payment" }, 409);
    const header = ctx.req.header(PAYMENT_SIGNATURE_HEADER); if (!header) return ctx.json({ error: "PAYMENT-SIGNATURE required" }, 400);
    const payload = parsePaymentPayload(decodeHeader(header));
    const deadlines = await acceptedDeadlines(c, payload.accepted); if (typeof deadlines === "string") return ctx.json({ error: deadlines }, 402);
    if (JSON.stringify(payload.resource) !== JSON.stringify(order.required.resource) || JSON.stringify(payload.accepted) !== JSON.stringify(order.required.accepts[0])) return ctx.json({ error: "payment envelope differs from the issued budget" }, 400);
    if (typeof payload.payload.transaction !== "string" || Object.keys(payload.payload).length !== 1) return ctx.json({ error: "authorize transaction required" }, 400);
    const tx = decode(payload.payload.transaction); const signed = await peekAuthorize(c, tx);
    if (signed.payer !== order.payer || !equalMessage(tx, decode(order.unsigned))) return ctx.json({ error: "wallet must sign the exact offered budget" }, 400);
    c.orders.reserve(order.id, "authorize");
    if(existsSync(`${c.orders.path(order.id)}.authorize-abandon.lock`)) {c.orders.unlock(order.id);return ctx.json({error:"Original authorization abandoned; no dispatch."},409);}
    const event: Event = { action: "authorize", label: labels.authorize, amount: DEMO_BUDGET.toString(), at: new Date().toISOString(), status: "prepared", transaction: "", transactionBase64: payload.payload.transaction, lifetimeObservation: order.authorizeLifetime };
    c.orders.prepare(order, event);
    const result = await settle(c, { x402Version: 2, paymentPayload: { ...payload, extensions: undefined }, paymentRequirements: order.required.accepts[0]! }, tx, order.payer, order.authorizeLifetime);
    await recordResult(order, event, result.receipt, result.kind);
    ctx.header(PAYMENT_RESPONSE_HEADER, encodeHeader(result.receipt));
    return ctx.json({ receipt: result.receipt, order: order.id }, result.kind === "succeeded" ? 200 : 402);
  });
  app.use("/api/orders/:id/actions/*", async (ctx, next) => {
    if (!merchantAuth) return ctx.json({ error: "merchant operations disabled" }, 503);
    return merchantAuth(ctx, next);
  });
  // Order-scoped read-only preflight on the existing action surface, behind the
  // very same bearer check as POST. Invalid credentials cannot cause economics.
  app.get("/api/orders/:id/actions/:action", async ctx => {
    if (!(merchantActions as readonly string[]).includes(ctx.req.param("action"))) return ctx.json({ error: "unsupported menu action" }, 400);
    const snapshot = await view(c.orders.read(ctx.req.param("id")));
    const { required: _required, unsigned: _unsigned, ...publicView } = snapshot;
    return ctx.json({ ...publicView, operatorAccess: true });
  });
  app.post("/api/orders/:id/actions/:action", async ctx => {
    let order = c.orders.read(ctx.req.param("id")); const action = ctx.req.param("action") as Action;
    if (!(merchantActions as readonly string[]).includes(action)) return ctx.json({ error: "unsupported menu action" }, 400);
    // Refund amount belongs to the scenario, never to caller-supplied JSON.
    if (action === "refund" && await ctx.req.text()) return ctx.json({ error: "Refund amount is fixed by the scenario; omit the request body." }, 400);
    c.orders.reserve(order.id, action);
    order = c.orders.read(order.id);
    let prepared = false;
    try {
      const p = await restaurantSnapshot(c, order);
      // No new consent while an earlier attempt is unresolved.
      const now = await orderClock(c,order);
      const reason = actionReasons(c, order, p, now, order.status === "pending")[action];
      if (reason) throw new RestaurantRefusal(reason);
      if (!p) throw new RestaurantRefusal("Original finalized payment unavailable.");
      const amount = action === "beer" || action === 'atomic' ? 40n * DEMO_UNIT : action === "salmon" ? 25n * DEMO_UNIT : action === "refund" ? refundAmount(order, p) : p.held;
      if (action === "refund") {
        const balance = await tokenBalance(c, p.server);
        if (balance.amount === null || balance.amount < money(amount)) throw new RestaurantRefusal(balance.reason || "Merchant test-token balance cannot fund this refund.");
      }
      const stored = { programId: c.programId, payment: order.payment, payer: p.payer, server: p.server, mint: p.mint };
      const ix = action === "beer" || action === "salmon" || action === 'atomic' ? await captureInstruction(stored, amount, action === 'atomic', p.held, p.refundable) : action === "refund" ? await refundInstruction(stored, amount, p.held, p.refundable) : await voidInstruction(stored, p.held, p.refundable);
      const tx = await buildDemoTransaction({ feePayer: c.feePayer, signers: [c.server], lifetime: await c.getLatestBlockhash(), instructions: [ix] }, c.ledger);
      const scheme = action === "beer" || action === "salmon" || action === 'atomic' ? capturePayload(order.payment, tx, amount, action === 'atomic', p.held, p.refundable) : action === "refund" ? refundPayload(order.payment, tx, amount, p.held, p.refundable) : voidPayload(order.payment, tx, p.held, p.refundable);
      const event: Event = { action, label: labels[action], amount: amount.toString(), at: new Date().toISOString(), status: "prepared", transaction: "", transactionBase64: encodeTransaction(tx), lifetimeObservation: transactionObservation(tx) };
      c.orders.prepare(order, event); prepared = true;
      const req = order.required.accepts[0]!;
      const result = await settle(c, { x402Version: 2, paymentPayload: { x402Version: 2, accepted: req, payload: scheme }, paymentRequirements: req }, tx, order.payer);
      await recordResult(order, event, result.receipt, result.kind);
      ctx.header(PAYMENT_RESPONSE_HEADER, encodeHeader(result.receipt));
      return ctx.json({ receipt: result.receipt }, result.kind === "succeeded" ? 200 : 409);
    } catch (e) {
      if (!prepared && order.status !== "pending" && !c.orders.attempted(order.id, action)) {
        // This handler has not reached settle(), so no relay request or broadcast
        // can have occurred. Return that definitive outcome for the exact POST;
        // a generic 409 leaves the browser's pre-request UNKNOWN latch stranded.
        // Partial preparation, an unlock failure, and every post-prepare error
        // retain the existing fail-closed path, without a not-submitted claim.
        c.orders.unlock(order.id);
        const receipt: SettleResponse = { success: false, errorReason: Reason.settlementNotSubmitted,
          transaction: "", network: c.network, payer: order.payer };
        ctx.header(PAYMENT_RESPONSE_HEADER, encodeHeader(receipt));
        return ctx.json({ error: e instanceof RestaurantRefusal ? e.message
          : "Finalized RPC evidence unavailable or order conflict; refresh and inspect original signatures.", receipt }, 409);
      }
      throw e;
    }
  });
  app.get("/api/orders/:id/reclaim", async ctx => {
    let order = owned(ctx.req.param("id"), getCookie(ctx, cookieName));
    if(existsSync(`${c.orders.path(order.id)}.reclaim-consent.lock`)) {
      const renewal=retainedReclaimGeneration(order);
      if(renewal && !existsSync(`${c.orders.path(order.id)}.reclaim-consent-${digest(renewal.newUnsigned)}.lock`) && !c.orders.busy(order.id) && order.status!=='pending' && !c.orders.attempted(order.id,'reclaim'))
        return ctx.json({unsigned:order.reclaimUnsigned,payer:order.payer}); // Same retained wire only; signing preflight checks validity.
      return ctx.json({error:'Original reclaim consent already attempted; inspect retained draft/signature before replacement.'},409);
    }
    c.orders.reserve(order.id, "reclaim");
    try {
      order = c.orders.read(order.id);
      const p = await restaurantSnapshot(c, order);
      if (!p || p.held === 0n || (await orderClock(c,order)) < p.captureDeadline || order.status === "pending") return ctx.json({ error: "reclaim is not eligible yet" }, 409);
      const lifetime = await c.getLatestBlockhash();
      const tx = await buildDemoTransaction({ feePayer: p.payer, signers: [], lifetime, instructions: [await reclaimInstruction({ programId: c.programId, payment: order.payment, payer: p.payer, server: p.server, mint: p.mint })] }, c.ledger);
      order.reclaimLifetime = { blockhash: lifetime.blockhash, lastValidBlockHeight: lifetime.lastValidBlockHeight.toString(), ...(lifetime.blockhashSlot === undefined ? {} : { blockhashSlot: lifetime.blockhashSlot.toString() }) };
      order.reclaimUnsigned = encodeTransaction(tx); c.orders.write(order); return ctx.json({ unsigned: order.reclaimUnsigned, payer: p.payer });
    } finally { c.orders.unlock(order.id); }
  });
  app.post('/api/orders/:id/reclaim-renewal',async ctx => {
    let order=owned(ctx.req.param('id'),getCookie(ctx,cookieName));
    if(await ctx.req.text() !== '') return ctx.json({error:'Renewal accepts no supplied wire or terms.'},400);
    c.orders.reserve(order.id,'reclaim');
    try {
      order=c.orders.read(order.id);
      const path=c.orders.path(order.id), consentPath=`${path}.reclaim-consent.lock`;
      const generation=retainedReclaimGeneration(order);
      if(!existsSync(consentPath) || generation && existsSync(`${path}.reclaim-consent-${digest(generation.newUnsigned)}.lock`) || !order.reclaimUnsigned || !order.reclaimLifetime ||
        order.status==='pending' || order.events.some(e=>e.action==='reclaim') || !c.ledger.getFinalizedBlockhashStatus || !c.ledger.getClockAtLeast)
        return ctx.json({error:'Only an expired initial consent or unused retained draft can be explicitly prepared.'},409);
      // Existing finalized events remain authoritative; absence of a signature is not proof.
      await restaurantSnapshot(c,order);
      let minContextSlot=0n;
      for(const e of order.events) if(e.transaction) {
        const status=await c.ledger.getSignatureStatus(e.transaction);
        if(status.kind!=='found' || status.commitment!=='finalized' || status.err!==null) return ctx.json({error:'Original outcome unavailable; renewal blocked.'},409);
        if(status.slot>minContextSlot)minContextSlot=status.slot;
      }
      const oldUnsigned=order.reclaimUnsigned, oldLifetime=order.reclaimLifetime, oldConsent=generation ? null : readFileSync(consentPath,'utf8');
      if(c.reclaimJournal.findByMessageHash(messageHash(decode(oldUnsigned).messageBytes)).length) return ctx.json({error:'Retained journal attempt blocks preparation.'},409);
      const proof=await proveExpiredReclaimConsent({unsigned:oldUnsigned,consent:oldConsent,order:order.id,payment:order.payment,payer:order.payer,
        server:c.server.address,mint:c.asset,programId:c.programId,maximum:DEMO_BUDGET,
        captureDeadline:BigInt(order.required.accepts[0]!.extra!.captureDeadline as number),refundDeadline:BigInt(order.required.accepts[0]!.extra!.refundDeadline as number),
        lifetime:oldLifetime,minContextSlot,reader:{getAccountAtLeast:(...args)=>c.ledger.getAccountAtLeast(...args),
          getFinalizedBlockhashStatus:(...args)=>c.ledger.getFinalizedBlockhashStatus!(...args),getClockAtLeast:(...args)=>c.ledger.getClockAtLeast!(...args)}});
      const lifetime=await c.getLatestBlockhash();
      if(lifetime.blockhash===oldLifetime.blockhash) return ctx.json({error:'Fresh distinct blockhash required.'},409);
      const tx=await buildDemoTransaction({feePayer:order.payer,signers:[],lifetime,instructions:[await reclaimInstruction({programId:c.programId,payment:order.payment,payer:order.payer,server:c.server.address,mint:c.asset})]},c.ledger);
      const newUnsigned=encodeTransaction(tx), newLifetime={blockhash:lifetime.blockhash,lastValidBlockHeight:lifetime.lastValidBlockHeight.toString(),...(lifetime.blockhashSlot===undefined?{}:{blockhashSlot:lifetime.blockhashSlot.toString()})};
      if(!c.ledger.offerBlockhashValid || !await c.ledger.offerBlockhashValid(lifetime.blockhash)) return ctx.json({error:'Fresh draft expired or unavailable before publication; nothing prepared.'},409);
      // Immutable archive is flushed before the draft changes. Partial write/crash stays blocked.
      createDurableFile(generation ? nextReclaimArchive(path,oldUnsigned) : `${path}.reclaim-renewal.lock`,JSON.stringify({schema:1,order:order.id,payment:order.payment,payer:order.payer,oldUnsigned,oldLifetime,oldConsent,proof,newUnsigned,newLifetime}));
      order.reclaimUnsigned=newUnsigned;order.reclaimLifetime=newLifetime;c.orders.write(order);
      return ctx.json({unsigned:newUnsigned,payer:order.payer,proof});
    } finally {c.orders.unlock(order.id);}
  });
  app.post("/api/orders/:id/reclaim", async ctx => {
    let order = owned(ctx.req.param("id"), getCookie(ctx, cookieName)); const body = await ctx.req.json() as { transaction?: string };
    if (!order.reclaimUnsigned || typeof body.transaction !== "string") return ctx.json({ error: "prepare and wallet-sign reclaim first" }, 400);
    const tx = decode(body.transaction); const m = getCompiledTransactionMessageDecoder().decode(tx.messageBytes); const signature = tx.signatures[order.payer];
    if (!equalMessage(tx, decode(order.reclaimUnsigned)) || m.header.numSignerAccounts !== 1 || m.staticAccounts[0] !== order.payer || !signature || !await verifySignature(await getPublicKeyFromAddress(order.payer), signature as SignatureBytes, tx.messageBytes)) return ctx.json({ error: "payer must sign the exact reclaim" }, 400);
    c.orders.reserve(order.id, "reclaim");
    order = c.orders.read(order.id);
    const p = await restaurantSnapshot(c, order);
    if (!p || p.held === 0n || (await orderClock(c,order)) < p.captureDeadline || order.status === "pending") { c.orders.unlock(order.id); return ctx.json({ error: "reclaim no longer eligible" }, 409); }
    // A concurrent preparation may have replaced the unsigned draft before this reservation.
    // Never associate its lifetime evidence with another signed wire.
    if (!order.reclaimUnsigned || !equalMessage(tx, decode(order.reclaimUnsigned)) || order.reclaimLifetime && order.reclaimLifetime.blockhash !== m.lifetimeToken) {
      c.orders.unlock(order.id); return ctx.json({ error: "reclaim draft changed; inspect the current offer" }, 409);
    }
    const generation=retainedReclaimGeneration(order);
    if(generation) {
      const marker=`${c.orders.path(order.id)}.reclaim-consent-${digest(generation.newUnsigned)}.lock`;
      const consent=existsSync(marker) ? JSON.parse(readFileSync(marker,'utf8')) : undefined;
      if(!consent || Object.keys(consent).sort().join()!=='order,unsignedSha256' || consent.order!==order.id || consent.unsignedSha256!==digest(generation.newUnsigned)) {
        c.orders.unlock(order.id); return ctx.json({error:'Fresh generation consent required before signed dispatch.'},409);
      }
    }
    const sig = getSignatureFromTransaction(tx);
    const event: Event = { action: "reclaim", label: labels.reclaim, amount: p.held.toString(), at: new Date().toISOString(), status: "prepared", transaction: sig, transactionBase64: body.transaction };
    c.orders.prepare(order, event);
    const simulation = await c.ledger.simulate({ ...tx, signatures: { ...tx.signatures, [order.payer]: null } });
    if (!simulation.ok) throw new Error("reclaim simulation refused; inspect the reserved attempt");
    c.reclaimJournal.prepare({ signature: sig, messageHash: messageHash(tx.messageBytes), transactionBase64: body.transaction, blockhash: m.lifetimeToken, operation: "reclaim", payment: order.payment, payer: order.payer, expectedHeld: p.held.toString(), expectedRefundable: p.refundable.toString(), ...(order.reclaimLifetime ?? {}) });
    const result = await c.ledger.submit(tx); c.reclaimJournal.resolve(sig, { ...submissionOutcome(result), recordedAt: new Date().toISOString() });
    const success = result.kind === "submitted" && result.outcome?.commitment === "finalized" && result.outcome.status === "succeeded";
    const failed = result.kind === "not-submitted" || result.kind === "submitted" && result.outcome?.commitment === "finalized" && result.outcome.status === "failed";
    const receipt: SettleResponse = { success, transaction: sig, network: c.network, payer: order.payer, ...(success ? {} : { errorReason: failed ? "invalid_transaction_state" : "settlement_pending" }) };
    await recordResult(order, event, receipt, success ? "succeeded" : failed ? "rejected" : "unresolved");
    ctx.header(PAYMENT_RESPONSE_HEADER,encodeHeader(receipt));
    return ctx.json({ receipt }, success ? 200 : 409);
  });
  return app;
}
