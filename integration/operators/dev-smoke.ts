// Operator-only, one-shot HTTPS lifecycle using the isolated dev payer.
// The reservation, session and signed consent stay private; no POST is retried.
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { request } from "node:https";
import { getBase64Encoder, getTransactionDecoder, partiallySignTransaction, type Address } from "@solana/kit";
import { getTokenDecoder } from "@solana-program/token";
import { createDurableFile } from "../src/durable-file.ts";
import { loadDeploymentRecord } from "../src/deployment-record.ts";
import { decodeHeader, encodeHeader, parsePaymentRequired } from "../src/http-transport.ts";
import { ata, decodePayment, TOKEN_PROGRAM_ADDRESS } from "../src/program.ts";
import { RpcLedger } from "../src/rpc-ledger.ts";
import { encodeTransaction } from "../src/transactions.ts";
import { loadKeypair } from "./lib.ts";

const DIRECTORY = "/var/lib/capture402-dev/setup";
const ORIGIN = "https://dev.capture402.xyz";
let phase = "explicit action";
type Event = { action: string; status: string; signature: string; chainStatus: { commitment?: string; err?: unknown } };
type View = { status: string; payment: Address; authorized: number; captured: number; refunded: number; released: number; remaining: number; events: Event[] };

export function validateSmokeView(view: View): void {
  if (view.status !== "closed" || view.authorized !== 100 || view.captured !== 0 || view.refunded !== 0 || view.released !== 100 || view.remaining !== 0
      || view.events.length !== 2 || view.events.map(e => e.action).join(",") !== "authorize,void"
      || view.events.some(e => e.status !== "finalized" || !e.signature || e.chainStatus.commitment !== "finalized" || e.chainStatus.err !== null)) {
    throw new Error("dev lifecycle lacks exact finalized release evidence");
  }
}

const save = (name: string, value: unknown) => createDurableFile(join(DIRECTORY, `${name}.json`), JSON.stringify(value, (_k, v) => typeof v === "bigint" ? v.toString() : v, 2));

async function main(): Promise<void> {
  const action = process.argv[2];
  if (action !== "run-once" && action !== "observe-original") throw new Error("explicit run-once or observe-original action required");
  // Exclusive before any RPC or order creation; an interrupted run is reconciled read-only.
  if (action === "run-once") save("smoke-reservation", { origin: ORIGIN, scenario: "normal", actions: ["authorize", "void"], startedAt: new Date().toISOString() });
  const overall = AbortSignal.timeout(180_000);
  const record = loadDeploymentRecord("/opt/capture402-dev/current/docs/evidence/sac-007/deployment-identity.v1.json");
  const ledger = new RpcLedger({ deployment: record, network: record.network.caip2, genesisHash: record.network.genesisHash,
    rpcUrl: "https://api.devnet.solana.com", confirmTimeoutMs: 60_000 });
  phase = "deployment verification";
  await ledger.verifyGenesis();
  const payer = await loadKeypair("/etc/capture402-dev/keys/payer.json");
  const identities = JSON.parse(readFileSync("/etc/capture402-dev/identities.json", "utf8")) as Record<string, Address>;
  if (identities.payer !== payer.address || new Set(Object.values(identities)).size !== 4) throw new Error("dev identity mismatch");
  const token = process.env.SAC006_MERCHANT_TOKEN;
  if (action === "run-once" && !token) throw new Error("private merchant credential required");

  // Native HTTPS validates the dev certificate/SNI while connecting to local nginx.
  const http = (path: string, method = "GET", headers: Record<string, string> = {}, body?: unknown) => new Promise<{ status: number; headers: import("node:http").IncomingHttpHeaders; body: unknown }>((resolve, reject) => {
    const wire = body === undefined ? undefined : JSON.stringify(body);
    const req = request(new URL(path, ORIGIN), { method, headers: { ...headers, ...(wire ? { "content-type": "application/json" } : {}) },
      family: 4, lookup: (_host, _options, callback) => callback(null, "127.0.0.1", 4),
      signal: AbortSignal.any([overall, AbortSignal.timeout(75_000)]) }, response => {
      const chunks: Buffer[] = []; let size = 0;
      response.on("data", (chunk: Buffer) => { size += chunk.length; if (size > 1_048_576) response.destroy(new Error("response too large")); else chunks.push(chunk); });
      response.on("error", reject);
      response.on("end", () => {
        try { resolve({ status: response.statusCode!, headers: response.headers, body: JSON.parse(Buffer.concat(chunks).toString("utf8")) }); }
        catch { reject(new Error("invalid dev response")); }
      });
    });
    req.on("error", reject); req.end(wire);
  });
  const balances = async (minimum: bigint) => {
    const values = [];
    for (const owner of [payer.address, identities.merchant!]) {
      overall.throwIfAborted();
      const read = await ledger.getAccountAtLeast(await ata(owner, identities.mint!), minimum);
      if (read.kind !== "ok" || read.slot < minimum || !read.account || read.account.owner !== TOKEN_PROGRAM_ADDRESS) throw new Error("finalized token balance unavailable");
      const decoded = getTokenDecoder().decode(read.account.data);
      if (decoded.owner !== owner || decoded.mint !== identities.mint) throw new Error("substituted token account");
      values.push(decoded.amount.toString());
    }
    return values;
  };
  if (action === "run-once") {
    phase = "baseline balances";
    const before = await balances(0n);
    save("smoke-before", before);
    phase = "order offer";
    const offer = await http("/api/orders", "POST", { origin: ORIGIN }, { payer: payer.address, scenario: "normal" });
    save("smoke-offer", offer);
    if (offer.status !== 402) throw new Error("expected dev offer");
    const payload = offer.body as { order: string; unsigned: string };
    if (!/^[a-f0-9]{32}$/.test(payload.order)) throw new Error("invalid order");
    const required = parsePaymentRequired(decodeHeader(String(offer.headers["payment-required"])));
    if (required.accepts[0]!.asset !== identities.mint || required.accepts[0]!.amount !== "100000000") throw new Error("unexpected dev offer terms");
    const cookie = offer.headers["set-cookie"]?.[0]?.split(";")[0];
    if (!cookie) throw new Error("missing private session");
    const signed = encodeTransaction(await partiallySignTransaction([payer.keyPair], getTransactionDecoder().decode(getBase64Encoder().encode(payload.unsigned))));
    save("smoke-consent", { order: payload.order, transactionBase64: signed });
    phase = "authorize response";
    const authorized = await http(`/resource?order=${payload.order}`, "POST", { origin: ORIGIN, cookie,
      "PAYMENT-SIGNATURE": encodeHeader({ x402Version: 2, resource: required.resource, accepted: required.accepts[0], payload: { transaction: signed } }) });
    save("smoke-authorize-response", authorized);
    if (authorized.status !== 200 || !(authorized.body as { receipt?: { success?: boolean } }).receipt?.success) throw new Error("authorization unresolved; retain original consent");
    // The merchant supplies independent private authority; the payer cookie is omitted.
    save("smoke-void-reservation", { order: payload.order, action: "void" });
    phase = "void response";
    const released = await http(`/api/orders/${payload.order}/actions/void`, "POST", { origin: ORIGIN, authorization: `Bearer ${token}` });
    save("smoke-void-response", released);
    if (released.status !== 200 || !(released.body as { receipt?: { success?: boolean } }).receipt?.success) throw new Error("release unresolved; reconcile original dev journal");
  }
  const original = JSON.parse(readFileSync(join(DIRECTORY, "smoke-offer.json"), "utf8")) as { body: { order: string }; headers: { "set-cookie": string[] } };
  const payload = original.body;
  if (!/^[a-f0-9]{32}$/.test(payload.order)) throw new Error("invalid original order");
  const cookie = original.headers["set-cookie"][0]?.split(";")[0];
  if (!cookie) throw new Error("missing original session");
  phase = "original order view";
  const response = await http(`/api/orders/${payload.order}`, "GET", { cookie });
  if (response.status !== 200) throw new Error("order view unavailable");
  const view = response.body as View;
  validateSmokeView(view);
  let minimum = 0n;
  const signatures = [];
  phase = "original signature evidence";
  for (const event of view.events) {
    overall.throwIfAborted();
    const status = await ledger.getSignatureStatus(event.signature);
    if (status.kind !== "found" || status.commitment !== "finalized" || status.err !== null) throw new Error("original signature not finalized");
    minimum = status.slot > minimum ? status.slot : minimum;
    signatures.push({ action: event.action, signature: event.signature, slot: status.slot.toString(), commitment: status.commitment, err: null });
  }
  overall.throwIfAborted();
  phase = "finalized payment state";
  const payment = await ledger.getAccountAtLeast(view.payment, minimum);
  if (payment.kind !== "ok" || payment.slot < minimum || !payment.account || payment.account.owner !== record.programId) throw new Error("finalized payment unavailable");
  const state = decodePayment(payment.account.data);
  if (!state || state.held !== 0n || state.refundable !== 0n) throw new Error("dev payment not fully released");
  phase = "finalized token balances";
  const after = await balances(minimum);
  // The initial inspected run predates smoke-before. Its fresh asset setup gives
  // an explicit expected balance, not an invented pre-payment observation.
  const observedBefore = existsSync(join(DIRECTORY, "smoke-before.json"));
  const before: string[] = observedBefore ? JSON.parse(readFileSync(join(DIRECTORY, "smoke-before.json"), "utf8"))
    : [JSON.parse(readFileSync(join(DIRECTORY, "asset-preparation.json"), "utf8")).tokenAmount, "0"];
  if (JSON.stringify(before) !== JSON.stringify(after)) throw new Error("token balances were not restored");
  const summary = { origin: ORIGIN, order: payload.order, payment: view.payment, payer: payer.address, merchant: identities.merchant, mint: identities.mint,
    signatures, held: "0", refundable: "0", paymentSlot: payment.slot.toString(), baseline: observedBefore ? "observed before authorization" : "expected from fresh asset preparation",
    before, after, browserWalletAcceptance: "not exercised" };
  phase = "durable summary";
  if (!existsSync(join(DIRECTORY, "smoke-result.json"))) save("smoke-result", summary);
  console.log(JSON.stringify(summary));
}

if (process.argv[1]?.endsWith("dev-smoke.ts")) main().catch(() => {
  console.error(`Dev smoke stopped during ${phase}. Preserve private evidence; reconcile the original order and signatures without retrying POSTs.`);
  process.exitCode = 1;
});
