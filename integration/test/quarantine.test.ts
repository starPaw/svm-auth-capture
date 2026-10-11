// Synthetic original + real accepted codecs. All post-projection effects are trapped.
import { afterEach, expect, test, vi } from "vitest";
import { readFileSync, writeFileSync } from "node:fs";
import * as fs from "node:fs";
import * as fsPromises from "node:fs/promises";
import * as kit from "@solana/kit";
import { getSignatureFromTransaction, partiallySignTransaction, getCompiledTransactionMessageDecoder, type Blockhash } from "@solana/kit";
import { encodeTransaction, buildTransaction, reclaimInstruction } from "../src/transactions.js";
import { hash, createQuarantineView, ASSETS, strictJson } from "../src/quarantine-view.js";
import { project } from "../src/quarantine-projector.js";
import { createHarness, type Harness } from "./fixture.js";
vi.mock("@solana/kit", { spy: true });
vi.mock("node:fs", { spy: true });
vi.mock("node:fs/promises", { spy: true });
let h: Harness | undefined;
afterEach(async () => { await h?.close(); vi.resetAllMocks(); vi.restoreAllMocks(); });
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
async function operationJournal(operation: "authorize" | "capture" | "void" | "refund" | "reclaim") {
  const salt = h!.newSalt(), payment = await h!.paymentFor(salt);
  const tx = operation === "authorize" ? await h!.signedAuthorize({ salt })
    : operation === "capture" ? await h!.signedCapture(payment, 25n, false, 100n, 0n)
    : operation === "void" ? await h!.signedVoid(payment, 100n, 0n)
    : operation === "refund" ? await h!.signedRefund(payment, 25n, 0n, 100n)
    : await buildTransaction({ feePayer: h!.payer.address, instructions: [await reclaimInstruction({ programId: h!.facilitator.programId, payer: h!.payer.address, server: h!.server.address, mint: h!.mint, payment })], signers: [h!.payer], lifetime: { blockhash: "1".repeat(32) as Blockhash, lastValidBlockHeight: 1000n } });
  const full = operation === "reclaim" ? tx : await partiallySignTransaction([h!.facilitatorKey.keyPair], tx);
  const signature = getSignatureFromTransaction(full), wire = encodeTransaction(full);
  const j = { signature, messageHash: hash(full.messageBytes), transactionBase64: wire, blockhash: getCompiledTransactionMessageDecoder().decode(full.messageBytes).lifetimeToken, operation, payment, payer: h!.payer.address, expectedHeld: operation === "authorize" || operation === "refund" ? "0" : "100", expectedRefundable: operation === "refund" ? "100" : "0", attempts: [{ preparedAt: at }] as any[] };
  return { journal: j, member: member(`${signature}.json`, j), role: operation === "reclaim" ? "reclaim" as const : "facilitator" as const };
}
test.each(["authorize", "capture", "void", "refund", "reclaim"] as const)("selected UNKNOWN %s is restricted to AUTHORIZE without mutation or effects", async operation => {
  const { input } = await fixture(false), record = await operationJournal(operation);
  input.stores.facilitator = record.role === "facilitator" ? [record.member] : [];
  input.stores.reclaim = record.role === "reclaim" ? [record.member, member(`reclaim-${record.journal.payment}.lock`, record.journal.signature)] as never : [];
  input.selected = { signature: record.journal.signature, messageHash: record.journal.messageHash, wireSha256: hash(Buffer.from(record.journal.transactionBase64, "base64")), journalSha256: hash(Buffer.from(record.member.rawBase64, "base64")) };
  const before = JSON.stringify(input);
  const traps = [vi.spyOn(kit, "partiallySignTransaction"), vi.spyOn(kit, "signTransaction"), vi.spyOn(kit, "signTransactionWithSigners"), vi.spyOn(h!.ledger, "submit"), vi.spyOn(h!.facilitator, "settle"), vi.spyOn(globalThis, "fetch"), vi.spyOn(fs, "writeFileSync"), vi.spyOn(fsPromises, "writeFile")];
  for (const trap of traps) trap.mockClear().mockImplementation(() => { throw new Error("economic/write trap"); });
  if (operation === "authorize") expect((await project(input)).original).toMatchObject({ operation: "authorize", status: "UNKNOWN", signature: input.selected.signature });
  else await expect(project(input)).rejects.toThrow();
  expect(JSON.stringify(input)).toBe(before);
  for (const trap of traps) expect(trap).not.toHaveBeenCalled();
  expect(h!.ledger.submissions).toHaveLength(0);
});
test.each((["capture", "void", "refund", "reclaim"] as const).flatMap(operation => ["not-submitted", "finalized-succeeded", "finalized-failed"].map(result => ({ operation, result }))))("non-selected terminal $operation ($result) history stays eligible and UNKNOWN refuses", async ({ operation, result }) => {
  const { input } = await fixture(false), record = await operationJournal(operation);
  record.journal.attempts[0].outcome = { result, recordedAt: at };
  input.stores[record.role].push(member(record.member.name, record.journal) as never);
  if (record.role === "reclaim") input.stores.reclaim.push(member(`reclaim-${record.journal.payment}.lock`, record.journal.signature) as never);
  const before = JSON.stringify(input);
  expect((await project(input)).original.operation).toBe("authorize");
  expect(JSON.stringify(input)).toBe(before);
  delete record.journal.attempts[0].outcome;
  input.stores[record.role][input.stores[record.role].findIndex(m => m.name === record.member.name)] = member(record.member.name, record.journal) as never;
  const unknown = JSON.stringify(input);
  await expect(project(input)).rejects.toThrow();
  expect(JSON.stringify(input)).toBe(unknown); expect(h!.ledger.submissions).toHaveLength(0);
});
test.each(["signature", "messageHash", "wireSha256", "journalSha256"] as const)("selected AUTHORIZE still requires exact %s", async field => {
  const { input } = await fixture(false);
  input.selected[field] = field === "signature" ? "1".repeat(88) : "f".repeat(64);
  const before = JSON.stringify(input);
  await expect(project(input)).rejects.toThrow();
  expect(JSON.stringify(input)).toBe(before); expect(h!.ledger.submissions).toHaveLength(0);
});
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
test.each(["missing-busy", "rejected-original", "closed-empty"])("status/reservation conflict %s fails closed", async kind => {
  const { input, order } = await fixture();
  if (kind === "missing-busy") input.stores.orders.pop();
  else {
    order.status = kind === "closed-empty" ? "closed" : "rejected";
    if (kind === "closed-empty") order.events = [];
    else { order.events[0]!.status = "rejected"; order.events[0]!.transaction = '1'.repeat(88) as typeof order.events[0]["transaction"]; }
    input.stores.orders[0] = member(`${id}.json`, order); input.stores.orders.pop();
    if (kind === "closed-empty") input.stores.orders.pop();
  }
  await expect(project(input)).rejects.toThrow();
});
test.each([false, true])("real payer-fee-payer reclaim chain validates legacy/#52 and reverse edges (%s)", async ext => {
  const { input, journal } = await fixture(true, ext), payment = await h!.paymentFor(h!.newSalt());
  let prior: string | undefined;
  for (const blockhash of [journal.blockhash, '1'.repeat(32)]) {
    const ix = await reclaimInstruction({ programId: h!.facilitator.programId, payer: h!.payer.address, server: h!.server.address, mint: h!.mint, payment });
    const tx = await buildTransaction({ feePayer: h!.payer.address, instructions: [ix], signers: [h!.payer], lifetime: { blockhash: blockhash as Blockhash, lastValidBlockHeight: 1000n } });
    const sig = getSignatureFromTransaction(tx), messageHash = hash(tx.messageBytes);
    const j = { signature: sig, messageHash, transactionBase64: encodeTransaction(tx), blockhash, operation: 'reclaim', payer: h!.payer.address, payment, expectedHeld: '100', expectedRefundable: '0', attempts: [{ preparedAt: at, outcome: { result: 'finalized-failed', recordedAt: at } }], ...(prior ? { retryAfter: prior } : {}), ...(ext ? { lifetimeProvenance: { version: 1, messageHash, blockhash, observation: { state: 'unavailable', reason: 'missing' }, origin: { state: 'unverified', reason: 'missing-observation' } } } : {}) };
    input.stores.reclaim.push(member(`${sig}.json`, j) as never, member(`reclaim-${payment}${prior ? '-after-' + prior : ''}.lock`, sig) as never); prior = sig;
  }
  expect((await project(input)).original.status).toBe('UNKNOWN');
  input.stores.reclaim.push(member(`reclaim-${payment}-after-${'1'.repeat(88)}.lock`, prior!) as never);
  await expect(project(input)).rejects.toThrow(); expect(h!.ledger.submissions).toHaveLength(0);
});
async function terminalFixture(rejected = false) {
  const { input, order } = await fixture(false);
  const salt = h!.newSalt(), tx = await h!.signedAuthorize({ salt }), payment = await h!.paymentFor(salt);
  const auth = await partiallySignTransaction([h!.facilitatorKey.keyPair], tx);
  const events: any[] = [];
  const add = (signed: typeof auth, unsigned: typeof tx, action: string, operation: string, expectedHeld: string, response: any) => {
    const signature = getSignatureFromTransaction(signed);
    input.stores.facilitator.push(member(`${signature}.json`, { signature, messageHash: hash(signed.messageBytes), transactionBase64: encodeTransaction(signed), blockhash: getCompiledTransactionMessageDecoder().decode(signed.messageBytes).lifetimeToken, operation, payment, payer: h!.payer.address, expectedHeld, expectedRefundable: '0', attempts: [{ preparedAt: at, outcome: { result: rejected ? 'finalized-failed' : 'finalized-succeeded', recordedAt: at } }] }));
    const event = { action, label: 'Retained action', amount: '100', at, status: rejected ? 'rejected' : 'finalized', transaction: signature, transactionBase64: encodeTransaction(unsigned), receipt: { transaction: signature, network: input.network, payer: h!.payer.address, ...response } };
    events.push(event);
    input.stores.orders.push(member(`${id}.json.${action}.lock`, { ...event, status: 'prepared', transaction: '', receipt: undefined }));
  };
  add(auth, tx, 'authorize', 'authorize', '0', rejected ? { success: false, errorReason: 'invalid_transaction_state' } : { success: true, amount: '100', extensions: { 'auth-capture': { operation: 'authorize', payment, amount: '100', held: '100', refundable: '0' } } });
  if (!rejected) {
    const unsigned = await h!.signedVoid(payment, 100n, 0n), signed = await partiallySignTransaction([h!.facilitatorKey.keyPair], unsigned);
    add(signed, unsigned, 'void', 'void', '100', { success: true, extensions: { 'auth-capture': { operation: 'void', payment, amount: '100', held: '0', refundable: '0' } } });
  }
  const retained = { ...order, payment, unsigned: encodeTransaction(tx), status: rejected ? 'rejected' : 'closed', events };
  input.stores.orders.unshift(member(`${id}.json`, retained));
  return { input, retained };
}
test.each([false, true])('authenticated terminal history retains real finalized/rejected timeline (%s)', async rejected => {
  const { input } = await terminalFixture(rejected), before = JSON.stringify(input);
  const p = await project(input);
  expect(p.orders[0]!.status).toBe(rejected ? 'rejected' : 'closed'); expect(p.original.association).toBeNull();
  expect(JSON.stringify(input)).toBe(before); expect(h!.ledger.submissions).toHaveLength(0);
});
test.each(['amount', 'payment', 'payer', 'network', 'signature', 'held', 'success-error', 'outcome'])('terminal receipt binding rejects %s without effects', async field => {
  const { input, retained } = await terminalFixture(); const r = retained.events[0].receipt;
  if (field === 'amount') r.amount = '999';
  else if (field === 'payment') r.extensions['auth-capture'].payment = h!.payer.address;
  else if (field === 'payer') r.payer = h!.server.address;
  else if (field === 'network') r.network = 'solana:other';
  else if (field === 'signature') r.transaction = input.selected.signature;
  else if (field === 'held') r.extensions['auth-capture'].held = '999';
  else if (field === 'success-error') r.errorReason = 'settlement_pending';
  else { const m = input.stores.facilitator[1]!, j = JSON.parse(Buffer.from(m.rawBase64, 'base64').toString()); j.attempts[0].outcome.result = 'finalized-failed'; input.stores.facilitator[1] = member(m.name, j); }
  input.stores.orders[0] = member(`${id}.json`, retained);
  await expect(project(input)).rejects.toThrow(); expect(h!.ledger.submissions).toHaveLength(0);
});
test.each(['finalized-succeeded', 'finalized-failed', 'not-submitted'])('actual restaurant reclaim preserves action and payment-chain locks (%s)', async result => {
  const { input, retained } = await terminalFixture();
  // Replace the void with an actual payer-signed reclaim, without submitting it.
  input.stores.facilitator.pop(); retained.events.pop(); input.stores.orders.pop();
  const payment = retained.payment;
  const ix = await reclaimInstruction({ programId: h!.facilitator.programId, payer: h!.payer.address, server: h!.server.address, mint: h!.mint, payment });
  const tx = await buildTransaction({ feePayer: h!.payer.address, instructions: [ix], signers: [h!.payer], lifetime: { blockhash: '1'.repeat(32) as Blockhash, lastValidBlockHeight: 1000n } });
  const signature = getSignatureFromTransaction(tx), wire = encodeTransaction(tx);
  input.stores.reclaim.push(member(`${signature}.json`, { signature, messageHash: hash(tx.messageBytes), transactionBase64: wire, blockhash: getCompiledTransactionMessageDecoder().decode(tx.messageBytes).lifetimeToken, operation: 'reclaim', payment, payer: h!.payer.address, expectedHeld: '100', expectedRefundable: '0', attempts: [{ preparedAt: at, outcome: { result, recordedAt: at } }] }) as never, member(`reclaim-${payment}.lock`, signature) as never);
  const event = { action: 'reclaim', label: 'Retained reclaim', amount: '100', at, status: result === 'finalized-succeeded' ? 'finalized' : 'rejected', transaction: signature, transactionBase64: wire, receipt: { success: result === 'finalized-succeeded', transaction: signature, network: input.network, payer: h!.payer.address, ...(result === 'finalized-succeeded' ? {} : { errorReason: 'invalid_transaction_state' }) } };
  retained.events.push(event); retained.status = result === 'finalized-succeeded' ? 'closed' : 'active';
  input.stores.orders[0] = member(`${id}.json`, retained);
  input.stores.orders.push(member(`${id}.json.reclaim.lock`, { ...event, status: 'prepared', receipt: undefined }));
  expect((await project(input)).orders[0]!.events.at(-1)!.action).toBe('reclaim');
  input.stores.orders.pop(); await expect(project(input)).rejects.toThrow();
  expect(h!.ledger.submissions).toHaveLength(0);
});
test("export only synthetic Linux fixture when requested", async () => {
  const { input } = await fixture(); const p = await project(input);
  if (process.env.B2_SYNTHETIC_FIXTURE) writeFileSync(process.env.B2_SYNTHETIC_FIXTURE, JSON.stringify({ input, projection: p, auth: { merchantHash: hash(merchant), operatorHash: hash(operator) }, cookie, merchant, operator }));
});

test("quarantine consumes exact complete coordination metadata but never exposes private paths", async () => {
  const { input } = await fixture();
  const roles = ["facilitator", "operations", "orders", "reclaim"] as const;
  const members = roles.map((role,i) => ({ role, path: `/private/synthetic/${role}`, device: "1", inode: String(i+1), lockDevice: "1", lockInode: String(i+11) }));
  for (const role of roles) (input.stores[role] as any[]).push(member(".coordination.lock", JSON.stringify({ version: 1, protocol: "flock-v1", domain: "a".repeat(32), role, members, writers: ["facilitator", "payer", "resource", "restaurant"] })));
  const before = JSON.stringify(input), p = await project(input);
  expect(JSON.stringify(input)).toBe(before); expect(JSON.stringify(p)).not.toContain("/private/synthetic");
  input.stores.facilitator.pop(); await expect(project(input)).rejects.toThrow();
});
test.each(["unknown-file", "unknown-field", "writer", "corrupt", "alias"])("quarantine rejects %s coordination instead of ignoring unknown files", async kind => {
  const { input } = await fixture(false); const roles = ["facilitator", "operations", "orders", "reclaim"] as const;
  const members = roles.map((role,i) => ({ role, path: `/private/synthetic/${role}`, device: "1", inode: String(i+1), lockDevice: "1", lockInode: String(i+11) }));
  for (const role of roles) {
    const v: any = { version: 1, protocol: "flock-v1", domain: "b".repeat(32), role, members, writers: ["facilitator", "payer", "resource", "restaurant"] };
    if (kind === "unknown-field" && role === "orders") v.extra = true;
    if (kind === "writer" && role === "orders") v.writers.pop();
    if (kind === "alias") v.members[1] = { ...members[1], path: members[0]!.path };
    (input.stores[role] as any[]).push(member(kind === "unknown-file" ? ".coordination-new.lock" : ".coordination.lock", kind === "corrupt" ? "broken" : JSON.stringify(v)));
  }
  await expect(project(input)).rejects.toThrow();
});
