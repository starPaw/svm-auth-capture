// Synthetic original + real accepted codecs. All post-projection effects are trapped.
import { afterEach, expect, test, vi } from "vitest";
import { readFileSync, writeFileSync } from "node:fs";
import { getSignatureFromTransaction, partiallySignTransaction, getCompiledTransactionMessageDecoder } from "@solana/kit";
import { encodeTransaction } from "../src/transactions.js";
import { hash, createQuarantineView, ASSETS, strictJson } from "../src/quarantine-view.js";
import { project } from "../src/quarantine-projector.js";
import { createHarness, type Harness } from "./fixture.js";
let h: Harness | undefined;
afterEach(async () => { await h?.close(); vi.restoreAllMocks(); });
const sha = process.env.B2_SOURCE_SHA ?? "c".repeat(40), id = "a".repeat(32), cookie = `${id}.${"b".repeat(64)}`;
const merchant = "synthetic-merchant-credential-00000001", operator = "synthetic-operator-credential-00000001";
const at = "2026-10-10T09:00:00.000Z";
const member = (name: string, value: unknown) => ({ name, rawBase64: Buffer.from(typeof value === "string" ? value : JSON.stringify(value)).toString("base64") });
test.each(['{"v":1,"v":2}', '{"v":1,"\\u0076":2}', '{"a":[{"b":1,"b":2}]}', '{"x":1e999}', '\ufeff{}', '{"x":NaN}', '{} extra'])("strict JSON rejects duplicate/unsupported raw bytes %s", raw => {
  expect(() => strictJson(raw)).toThrow();
});
async function fixture(associated = true, provenance = false) {
  h = await createHarness();
  const salt = h.newSalt(), tx = await h.signedAuthorize({ salt });
  const full = await partiallySignTransaction([h.facilitatorKey.keyPair], tx);
  const signature = getSignatureFromTransaction(full), unsigned = encodeTransaction(tx), wire = encodeTransaction(full);
  const blockhash = getCompiledTransactionMessageDecoder().decode(tx.messageBytes).lifetimeToken;
  const payment = await h.paymentFor(salt);
  const journal: any = { signature, messageHash: hash(tx.messageBytes), transactionBase64: wire, blockhash, operation: "authorize", payment, payer: h.payer.address, expectedHeld: "0", expectedRefundable: "0", attempts: [{ preparedAt: at }] };
  if (provenance) journal.lifetimeProvenance = { version: 1, messageHash: journal.messageHash, blockhash, observation: { state: "unavailable", reason: "missing" }, origin: { state: "unverified", reason: "missing-observation" } };
  const event = { action: "authorize", label: "Budget authorized", amount: "100", at, status: "pending", transaction: signature, transactionBase64: unsigned };
  const order = { id, capabilityHash: hash(cookie), payer: h.payer.address, payment, scenario: "normal", required: { x402Version: 2, resource: { url: "https://retained.invalid/resource" }, accepts: [h.requirements()] }, unsigned, createdAt: 1000, status: "pending", events: [event] };
  const j = member(`${signature}.json`, journal);
  return { input: { stores: { facilitator: [j], operations: [], reclaim: [], orders: associated ? [member(`${id}.json`, order), member(`${id}.json.authorize.lock`, { ...event, status: "prepared", transaction: "" }), member(`${id}.json.busy`, "authorize")] : [] }, selected: { signature, messageHash: journal.messageHash, wireSha256: hash(Buffer.from(wire, "base64")), journalSha256: hash(Buffer.from(j.rawBase64, "base64")) }, network: h.ledger.network, genesisHash: h.payer.address, programId: h.facilitator.programId, viewerSha: sha, inventorySha256: "d".repeat(64), tupleSha256: "e".repeat(64), snapshotAt: at }, journal, order };
}
function view(p: unknown) {
  const assets = Object.fromEntries(ASSETS.map(path => [path, readFileSync(new URL(`../web/quarantine/${path.split('/').at(-1)}`, import.meta.url), "utf8")])) as Record<typeof ASSETS[number], string>;
  return createQuarantineView(p, { merchantHash: hash(merchant), operatorHash: hash(operator) }, assets);
}
test.each([false, true])("legacy/#52 exact original creates actual immutable retained data (%s)", async ext => {
  const { input } = await fixture(true, ext), before = JSON.stringify(input);
  const p = await project(input); expect(p.original.association).toBe(id); expect(Object.isFrozen(p.orders[0]!.events)).toBe(true);
  expect(JSON.stringify(input)).toBe(before);
  const v = view(p), r = await v(new Request(`https://view/api/orders/${id}`, { headers: { cookie: `capture402-order=${cookie}` } }));
  expect(r.status).toBe(200); expect(await r.json()).toMatchObject({ status: "pending", events: [{ signature: input.selected.signature }], capabilities: { sign: false, refund: false } });
  expect(r.headers.get("set-cookie")).toBeNull();
});
test("facilitator-only original has authorized unassociated diagnosis, never a synthetic order", async () => {
  const { input } = await fixture(false), p = await project(input), v = view(p);
  expect(p.orders).toEqual([]); expect(p.original.association).toBeNull();
  const r = await v(new Request("https://view/api/quarantine/status", { headers: { authorization: `Bearer ${operator}` } }));
  expect(r.status).toBe(200); expect(await r.json()).toMatchObject({ original: { status: "UNKNOWN", association: null } });
});
test.each(["absent", "bad", "other-order", "duplicate", "merchant", "operator"])("customer auth failure %s does not enumerate or issue capability", async kind => {
  const { input } = await fixture(), v = view(await project(input));
  const r = await v(new Request(`https://view/api/orders/${kind === 'other-order' ? '0'.repeat(32) : id}`, { headers: { cookie: kind === "duplicate" ? `capture402-order=${cookie}; capture402-order=${cookie}` : kind === "absent" ? "" : `capture402-order=${kind === 'bad' ? 'bad' : kind === 'merchant' ? merchant : kind === 'operator' ? operator : cookie}` } }));
  expect(r.status).toBe(403); expect(await r.text()).toBe('{"error":"quarantine request denied"}'); expect(r.headers.get("set-cookie")).toBeNull();
});
test.each(["beer", "salmon", "finish", "void", "refund"])("merchant retained %s keeps independent auth", async action => {
  const { input } = await fixture(), v = view(await project(input));
  for (const token of [cookie, operator, "wrong"]) expect((await v(new Request(`https://view/api/orders/${id}/actions/${action}`, { headers: { authorization: `Bearer ${token}` } }))).status).toBe(403);
  expect((await v(new Request(`https://view/api/orders/${id}/actions/${action}`, { headers: { authorization: `Bearer ${merchant}` } }))).status).toBe(200);
});
test("all denied routes/methods with exact/new message/salt/offer headers reach zero effect calls", async () => {
  const { input } = await fixture(), p = await project(input), v = view(p);
  const traps = [vi.spyOn(h!.ledger, "submit").mockImplementation(() => { throw new Error("submit trap"); }), vi.spyOn(h!.facilitator, "settle").mockImplementation(() => { throw new Error("settle trap"); }), vi.spyOn(globalThis, "fetch").mockImplementation(() => { throw new Error("network trap"); })];
  const denied = ["/resource", "/verify", "/settle", "/supported", "/api/orders", `/api/orders/${id}/reclaim`, "/assets/wallet.js", "/assets/unknown.js", "/unknown", `/api/orders/${id}/actions/authorize`, "/api/config?mode=economic"];
  for (const path of denied) for (const method of ["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE"]) for (const original of ["", input.selected.signature, "new-salt-and-offer"]) {
    const r = await v(new Request(`https://view${path}`, { method, headers: { authorization: `Bearer ${merchant}`, cookie: `capture402-order=${cookie}`, ...(original ? { "payment-signature": String(original) } : {}) } }));
    expect(r.status).toBe(403); expect(r.headers.get("payment-required")).toBeNull();
  }
  for (const trap of traps) expect(trap).not.toHaveBeenCalled();
  for (const path of ["/", "/customer", "/merchant", "/api/config", ...ASSETS, `/api/orders/${id}`, `/api/orders/${id}/actions/beer`, "/api/quarantine/status"]) for (const method of ["POST", "HEAD", "OPTIONS", "PUT", "DELETE"]) expect((await v(new Request(`https://view${path}`, { method }))).status).toBe(403);
  for (const trap of traps) expect(trap).not.toHaveBeenCalled();
});
test("projection/responses/frontend exclude wires, offers, secrets and signing/provider flows", async () => {
  const { input, journal, order } = await fixture(), p = await project(input), v = view(p);
  const all = [JSON.stringify(p)];
  for (const path of ["/", "/customer", "/merchant", "/api/config", ...ASSETS, `/api/orders/${id}`, "/api/quarantine/status"]) all.push(await (await v(new Request(`https://view${path}`, { headers: { cookie: `capture402-order=${cookie}`, authorization: `Bearer ${operator}` } }))).text());
  const output = all.join("\n");
  for (const secret of [journal.transactionBase64, order.unsigned, cookie, merchant, operator, order.required.resource.url]) expect(output).not.toContain(secret);
  expect(output).not.toMatch(/solflare|window\.solana|signTransaction|sendTransaction|PAYMENT-REQUIRED|transactionBase64|reclaimUnsigned/);
});
test.each(["version", "attempt", "wire", "signature", "field", "orphan", "otherUnknown", "lock", "hash", "tuple", "bom"])("strict validator refuses %s without rewrite", async kind => {
  const { input, journal } = await fixture(); const bad: any = structuredClone(input);
  if (kind === "version") bad.version = 2;
  else if (kind === "tuple") bad.viewerSha = "bad";
  else if (kind === "hash") bad.selected.journalSha256 = "f".repeat(64);
  else if (kind === "orphan") bad.stores.reclaim.push(member(`reclaim-${journal.payment}.lock`, journal.signature));
  else if (kind === "lock") bad.stores.orders.splice(1, 1);
  else if (kind === "bom") bad.stores.facilitator[0].rawBase64 = Buffer.concat([Buffer.from([239, 187, 191]), Buffer.from(bad.stores.facilitator[0].rawBase64, 'base64')]).toString('base64');
  else if (kind === "otherUnknown") bad.stores.facilitator.push(bad.stores.facilitator[0]);
  else { const j = structuredClone(journal); if (kind === "attempt") j.attempts = [{ preparedAt: at, outcome: { result: 'unknown', recordedAt: at } }]; if (kind === "wire") j.transactionBase64 = Buffer.from('changed').toString('base64'); if (kind === "signature") j.signature = '1'.repeat(88); if (kind === "field") j.hiddenEconomicVersion = 2; bad.stores.facilitator[0] = member(`${j.signature}.json`, j); }
  const before = JSON.stringify(bad); await expect(project(bad)).rejects.toThrow(); expect(JSON.stringify(bad)).toBe(before);
});
test("late remote finality and retained input mutation cannot change sealed UNKNOWN", async () => {
  const { input } = await fixture(), p = await project(input), v = view(p), before = JSON.stringify(p);
  input.stores.facilitator[0]!.rawBase64 = member('ignored', { finalized: true }).rawBase64;
  const r = await v(new Request("https://view/api/quarantine/status", { headers: { authorization: `Bearer ${operator}` } }));
  expect((await r.json()).original.status).toBe("UNKNOWN"); expect(JSON.stringify(p)).toBe(before);
  expect(h!.ledger.submissions).toHaveLength(0);
});
test("export only synthetic Linux fixture when requested", async () => {
  const { input } = await fixture(); const p = await project(input);
  if (process.env.B2_SYNTHETIC_FIXTURE) writeFileSync(process.env.B2_SYNTHETIC_FIXTURE, JSON.stringify({ input, projection: p, auth: { merchantHash: hash(merchant), operatorHash: hash(operator) }, cookie, merchant, operator }));
});
