// Offline validator: pure data input, verification and projection. No store constructors,
// RPC readers, signers, transport, application or environment imports.
import * as kit from "@solana/kit";
import * as abi from "./program.ts";
import { ACTIONS, MODE, check, object, text, hex, decimal, timestamp, base58, hash, projection, strictJson, type RetainedOrder } from "./quarantine-view.ts";

type Member = { name: string; rawBase64: string };
type Wire = { tx: kit.Transaction; message: Extract<kit.CompiledTransactionMessage, { version: "legacy" }> & { lifetimeToken: kit.Blockhash }; op: NonNullable<ReturnType<typeof abi.decodeInstructionData>>; payment: string; payer?: string };
const terminal = new Set(["not-submitted", "finalized-succeeded", "finalized-failed"]);
const actions = ["authorize", ...ACTIONS, "reclaim"];
const opFor = (action: string) => action === "beer" || action === "salmon" ? "capture" : action === "finish" ? "void" : action;
function list(v: unknown, max = 4096): asserts v is any[] { check(Array.isArray(v) && v.length <= max); }
function canonical(raw: string, max: number) { text(raw, max * 2); const b = Buffer.from(raw, "base64"); check(b.length <= max && b.toString("base64") === raw); return b; }
function observation(v: any, wire: Wire, network: string) {
  object(v, ["version", "messageHash", "blockhash", "lastValidBlockHeight", "contextSlot", "commitment", "network", "genesisHash"]);
  check(v.version === 1 && v.messageHash === hash(wire.tx.messageBytes) && v.blockhash === wire.message.lifetimeToken);
  decimal(v.lastValidBlockHeight); if (v.contextSlot !== null) decimal(v.contextSlot);
  check([null, "processed", "confirmed", "finalized"].includes(v.commitment)); check(v.network === null || v.network === network);
  if (v.genesisHash !== null) base58(v.genesisHash);
}
function provenance(v: any, w: Wire, network: string, genesis: string) {
  object(v, ["version", "messageHash", "blockhash", "observation", "origin"]);
  check(v.version === 1 && v.messageHash === hash(w.tx.messageBytes) && v.blockhash === w.message.lifetimeToken);
  const o = v.observation;
  if (o.state === "recorded") { object(o, ["state", "source", "value"]); check(["first-party", "request"].includes(o.source)); observation(o.value, w, network); }
  else { object(o, ["state", "reason"]); check(o.state === "unavailable" && ["missing", "invalid", "binding-mismatch"].includes(o.reason)); }
  const r = v.origin;
  if (r.state === "verified") {
    object(r, ["state", "blockhash", "slot", "commitment", "network", "genesisHash"]); decimal(r.slot);
    check(o.state === "recorded" && r.blockhash === v.blockhash && r.slot === o.value.contextSlot && r.commitment === "finalized" && r.network === network && r.genesisHash === genesis && o.value.genesisHash === genesis);
  } else {
    object(r, ["state", "reason"]); check(r.state === "unverified" && ["missing-observation", "invalid-observation", "binding-mismatch", "network-mismatch", "origin-unavailable", "lookup-unavailable"].includes(r.reason));
  }
}
async function wire(raw: string, program: string, signed: boolean): Promise<Wire> {
  const b = canonical(raw, 1232); check(b.length > 0);
  const tx = kit.getTransactionDecoder().decode(b);
  const [m, end] = kit.getCompiledTransactionMessageDecoder().read(tx.messageBytes, 0);
  check(m.version === "legacy" && end === tx.messageBytes.length && kit.getBase64EncodedWireTransaction(tx) === raw);
  check(Buffer.from(kit.getCompiledTransactionMessageEncoder().encode(m)).equals(Buffer.from(tx.messageBytes)));
  const keys = m.staticAccounts, h = m.header;
  check(keys.length <= 256 && new Set(keys).size === keys.length && h.numSignerAccounts > 0 && h.numSignerAccounts <= keys.length && h.numReadonlySignerAccounts <= h.numSignerAccounts && h.numReadonlyNonSignerAccounts <= keys.length - h.numSignerAccounts);
  for (const k of keys.slice(0, h.numSignerAccounts)) {
    const sig = tx.signatures[k];
    if (signed) check(sig && await kit.verifySignature(await kit.getPublicKeyFromAddress(k), sig, tx.messageBytes));
    else if (sig) check(await kit.verifySignature(await kit.getPublicKeyFromAddress(k), sig, tx.messageBytes));
  }
  let ix: typeof m.instructions[number] | undefined; const tags = new Set();
  for (const i of m.instructions) {
    check(i.programAddressIndex >= h.numSignerAccounts && i.programAddressIndex < keys.length && (i.accountIndices ?? []).every(n => n < keys.length));
    if (keys[i.programAddressIndex] === program) { check(!ix); ix = i; }
    else {
      const d = Buffer.from(i.data ?? []); check(keys[i.programAddressIndex] === "ComputeBudget111111111111111111111111111111" && !(i.accountIndices ?? []).length && [2, 3].includes(d[0]!) && d.length === (d[0] === 2 ? 5 : 9) && !tags.has(d[0])); tags.add(d[0]);
    }
  }
  check(ix); const op = abi.decodeInstructionData(new Uint8Array(ix.data ?? [])); check(op);
  const indices = ix.accountIndices ?? [], accounts = indices.map(n => keys[n]!);
  const auth = op.op === "authorize", reclaim = op.op === "reclaim";
  check(h.numSignerAccounts === (reclaim ? 1 : 2));
  const payment = accounts[auth ? 2 : 1]!; base58(payment);
  const payer = auth || reclaim ? accounts[0]! : undefined;
  if (auth) check(accounts[0] === keys[1] && await abi.paymentAddress(program as kit.Address, payer as kit.Address, op.salt) === payment);
  else check(accounts[0] === keys[reclaim ? 0 : 1]);
  // Full account/role bindings for signed journals are checked below with retained payer.
  check("lifetimeToken" in m);
  return { tx, message: m as Wire["message"], op, payment, payer };
}
async function bind(w: Wire, e: any, program: string) {
  const m = w.message, keys = m.staticAccounts, h = m.header;
  const ix = m.instructions.find(i => keys[i.programAddressIndex] === program)!;
  const auth = w.op.op === "authorize", reclaim = w.op.op === "reclaim";
  const a = (ix.accountIndices ?? []).map(n => keys[n]!);
  check(w.op.op === e.operation && w.payment === e.payment && (w.payer === undefined || w.payer === e.payer));
  const server = reclaim ? e.payer : a[auth ? 1 : 0]!, mint = a[auth ? 3 : 2]!;
  check(reclaim || server !== e.payer);
  const common = { payer: e.payer as kit.Address, server, payment: e.payment as kit.Address, mint,
    source: await abi.ata(e.payer, mint), payerAta: await abi.ata(e.payer, mint),
    vault: await abi.ata(e.payment, mint), serverAta: await abi.ata(server, mint), funder: keys[0]! };
  const slots = auth ? abi.authorizeAccounts(common) : reclaim ? abi.reclaimAccounts(common) : w.op.op === "capture" ? abi.captureAccounts(common) : w.op.op === "void" ? abi.voidAccounts(common) : abi.refundAccounts(common);
  check((ix.accountIndices ?? []).length === slots.length && (ix.accountIndices ?? []).every((n, i) => {
    const s = slots[i]!, signer = n < h.numSignerAccounts;
    const writable = signer ? n < h.numSignerAccounts - h.numReadonlySignerAccounts : n < keys.length - h.numReadonlyNonSignerAccounts;
    return keys[n] === s.address && signer === (s.signer || n === 0) && writable === (s.writable || n === 0);
  }));
  if (auth) check(e.expectedHeld === "0" && e.expectedRefundable === "0");
  else if (w.op.op !== "reclaim" && w.op.op !== "authorize") check(e.expectedHeld === w.op.expectedHeld.toString() && e.expectedRefundable === w.op.expectedRefundable.toString());
}
function receipt(r: any, network: string) {
  object(r, ["success", "transaction", "network"], ["errorReason", "payer", "amount", "extensions"]);
  check(typeof r.success === "boolean" && r.network === network); if (r.transaction !== "") base58(r.transaction, true);
  check(!r.success || r.errorReason === undefined);
  if (r.errorReason !== undefined) text(r.errorReason); if (r.payer !== undefined) base58(r.payer); if (r.amount !== undefined) decimal(r.amount);
  if (r.extensions !== undefined) {
    object(r.extensions, ["auth-capture"]); const x = r.extensions["auth-capture"];
    object(x, ["operation", "payment", "amount", "held", "refundable"], ["releaseRemainder", "released"]);
    check(["authorize", "capture", "void", "refund"].includes(x.operation)); base58(x.payment); [x.amount, x.held, x.refundable].forEach(decimal);
    if (x.releaseRemainder !== undefined) check(typeof x.releaseRemainder === "boolean"); if (x.released !== undefined) decimal(x.released);
  }
}
function amount(w: Wire): string | undefined {
  const o = w.op; return o.op === "authorize" ? o.maximum.toString() : o.op === "void" ? o.expectedHeld.toString() : o.op === "capture" || o.op === "refund" ? o.amount.toString() : undefined;
}
function boundReceipt(r: any, w: Wire, network: string, payer: string, signature: string) {
  receipt(r, network); check(r.transaction === signature && (r.payer === undefined || r.payer === payer));
  if (r.amount !== undefined) check(w.op.op !== "void" && r.amount === amount(w));
  if (!r.success) { check(r.extensions === undefined && r.amount === undefined); return; }
  if (w.op.op === "reclaim") { check(r.extensions === undefined); return; }
  check(r.extensions); const x = r.extensions["auth-capture"], o = w.op;
  check(x.operation === o.op && x.payment === w.payment && x.amount === amount(w));
  if (o.op === "authorize") check(x.held === o.maximum.toString() && x.refundable === "0" && x.releaseRemainder === undefined && x.released === undefined);
  else if (o.op === "capture") check(o.amount <= o.expectedHeld && x.releaseRemainder === o.releaseRemainder && x.held === (o.releaseRemainder ? 0n : o.expectedHeld - o.amount).toString() && x.refundable === (o.expectedRefundable + o.amount).toString() && (o.releaseRemainder ? x.released === (o.expectedHeld - o.amount).toString() : x.released === undefined));
  else if (o.op === "refund") check(o.amount <= o.expectedRefundable && x.held === o.expectedHeld.toString() && x.refundable === (o.expectedRefundable - o.amount).toString() && x.releaseRemainder === undefined && x.released === undefined);
  else check(x.held === "0" && x.refundable === o.expectedRefundable.toString() && x.releaseRemainder === undefined && x.released === undefined);
}
export async function project(input: unknown) {
  object(input, ["stores", "selected", "network", "genesisHash", "programId", "viewerSha", "inventorySha256", "tupleSha256", "snapshotAt"]);
  text(input.network); base58(input.genesisHash); base58(input.programId); hex(input.viewerSha, 40); hex(input.inventorySha256); hex(input.tupleSha256); timestamp(input.snapshotAt);
  const { network, programId: program, genesisHash: genesis } = input;
  object(input.selected, ["signature", "messageHash", "wireSha256", "journalSha256"]); base58(input.selected.signature, true);
  [input.selected.messageHash, input.selected.wireSha256, input.selected.journalSha256].forEach(v => hex(v));
  object(input.stores, ["facilitator", "operations", "reclaim", "orders"]);
  const stores: Record<string, Map<string, { raw: Buffer; value: any }>> = {};
  for (const [role, members] of Object.entries(input.stores)) {
    list(members); const map = new Map(); stores[role] = map;
    for (const v of members) {
      object(v, ["name", "rawBase64"]); text(v.name); check(/^[a-zA-Z0-9.-]+$/.test(v.name) && !v.name.includes(".tmp-") && !map.has(v.name));
      const raw = canonical(v.rawBase64, 4 * 1024 * 1024 - 1); check(raw.length > 0);
      const str = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(raw); check(!str.startsWith("\ufeff"));
      const value = v.name.endsWith(".json") || v.name.endsWith(".lock") && role === "orders" ? strictJson(str) : str;
      map.set(v.name, { raw, value });
    }
  }
  const journals = new Map<string, { entry: any; w: Wire; raw: Buffer; role: string }>();
  for (const role of ["facilitator", "reclaim"]) for (const [name, { raw, value: e }] of stores[role]!) {
    if (!name.endsWith(".json")) { check(role === "reclaim" && /^reclaim-[1-9A-HJ-NP-Za-km-z]{32,44}(?:-after-[1-9A-HJ-NP-Za-km-z]{80,90})?\.lock$/.test(name)); continue; }
    object(e, ["signature", "messageHash", "transactionBase64", "blockhash", "operation", "payment", "payer", "expectedHeld", "expectedRefundable", "attempts"], ["lifetimeProvenance", "blockhashSlot", "lastValidBlockHeight", "reclaimRecovery", "retryAfter"]);
    base58(e.signature, true); check(name === `${e.signature}.json` && !journals.has(e.signature)); hex(e.messageHash); base58(e.blockhash); base58(e.payment); base58(e.payer); decimal(e.expectedHeld); decimal(e.expectedRefundable);
    check(role === "reclaim" ? e.operation === "reclaim" : ["authorize", "capture", "void", "refund"].includes(e.operation));
    const w = await wire(e.transactionBase64, program, true); await bind(w, e, program);
    check(hash(w.tx.messageBytes) === e.messageHash && w.message.lifetimeToken === e.blockhash && kit.getSignatureFromTransaction(w.tx) === e.signature);
    list(e.attempts, 64); check(e.attempts.length > 0);
    for (const a of e.attempts) {
      object(a, ["preparedAt"], ["outcome"]); timestamp(a.preparedAt);
      if (a.outcome !== undefined) { object(a.outcome, ["result", "recordedAt"], ["detail"]); check([...terminal, "unresolved", "submit-threw"].includes(a.outcome.result)); timestamp(a.outcome.recordedAt); if (a.outcome.detail !== undefined) text(a.outcome.detail, 4096); }
    }
    if (e.signature !== input.selected.signature) check(e.attempts.every((a: any) => terminal.has(a.outcome?.result)));
    // #57 permits only the selected historical UNKNOWN AUTHORIZE, not other operations.
    else check(role === "facilitator" && e.operation === "authorize" && !terminal.has(e.attempts.at(-1).outcome?.result) && !e.attempts.some((a: any) => a.outcome?.result === "finalized-succeeded"));
    if (e.lifetimeProvenance !== undefined) provenance(e.lifetimeProvenance, w, network, genesis);
    for (const k of ["blockhashSlot", "lastValidBlockHeight"]) if (e[k] !== undefined) decimal(e[k]);
    if (e.retryAfter !== undefined) base58(e.retryAfter, true);
    if (e.reclaimRecovery !== undefined) {
      const p = e.reclaimRecovery; object(p, ["kind", "blockhash", "originSlot", "expirySlot", "paymentSlot"]); check(p.kind === "expired-no-effect"); base58(p.blockhash); [p.originSlot, p.expirySlot, p.paymentSlot].forEach(decimal); check(BigInt(p.expirySlot) > BigInt(p.originSlot) && BigInt(p.paymentSlot) >= BigInt(p.expirySlot));
    }
    check(e.operation === "reclaim" || e.retryAfter === undefined && e.reclaimRecovery === undefined);
    journals.set(e.signature, { entry: e, w, raw, role });
  }
  const selected = journals.get(input.selected.signature); check(selected);
  check(hash(selected.raw) === input.selected.journalSha256 && selected.entry.messageHash === input.selected.messageHash && hash(canonical(selected.entry.transactionBase64, 1232)) === input.selected.wireSha256);
  const original = selected.entry;
  const validateReceipt = (r: any, w: Wire, payer: string, signature: string) => {
    boundReceipt(r, w, network, payer, signature);
    const j = signature ? journals.get(signature) : [...journals.values()].find(j => j.entry.messageHash === hash(w.tx.messageBytes));
    if (!j) { check(!r.success && signature === ""); return; }
    const outcome = j.entry.attempts.at(-1).outcome?.result;
    if (r.success) check(outcome === "finalized-succeeded" && signature === j.entry.signature);
    else if (outcome === "not-submitted") check(w.op.op === "reclaim" ? signature === j.entry.signature && r.errorReason === "invalid_transaction_state" : signature === "" && r.errorReason === "settlement_not_submitted");
    else if (outcome === "finalized-failed") check(signature === j.entry.signature && r.errorReason === "invalid_transaction_state");
    else check(signature === j.entry.signature && r.errorReason === "settlement_pending");
  };
  // Validate reclaim reservations in BOTH directions, including every successor.
  const reached = new Set<string>();
  for (const [name, { value: sig }] of stores.reclaim!) if (/^reclaim-[^-]+\.lock$/.test(name)) {
    const payment = name.slice(8, -5); let cursor = sig; let previous: string | undefined;
    for (;;) {
      base58(cursor, true); check(!reached.has(cursor)); reached.add(cursor);
      const current = journals.get(cursor); check(current && current.role === "reclaim" && current.entry.payment === payment && current.entry.retryAfter === previous);
      if (previous) {
        const p = journals.get(previous)!.entry, e = current.entry;
        check(e.payer === p.payer && (p.attempts.at(-1).outcome?.result === "finalized-failed" || e.reclaimRecovery?.blockhash === p.blockhash && p.attempts.at(-1).outcome?.result !== "finalized-succeeded" && e.expectedHeld === p.expectedHeld && e.expectedRefundable === p.expectedRefundable));
      }
      const next = stores.reclaim!.get(`reclaim-${payment}-after-${cursor}.lock`);
      if (!next) break; previous = cursor; cursor = next.value;
    }
  }
  for (const [sig, v] of journals) if (v.role === "reclaim") check(reached.has(sig));
  for (const [name, v] of stores.reclaim!) if (name.endsWith(".lock")) {
    const [payment, predecessor] = name.slice(8, -5).split("-after-");
    check(reached.has(v.value) && journals.get(v.value)?.entry.payment === payment && journals.get(v.value)?.entry.retryAfter === predecessor);
    if (predecessor) check(reached.has(predecessor) && journals.get(predecessor)?.entry.payment === payment);
  }
  // Every operation is either terminal or directly authenticated to the one original.
  for (const [name, { value: r }] of stores.operations!) {
    check(name.endsWith(".json")); object(r, ["fingerprint", "caller", "resource", "createdAt", "updatedAt", "status"], ["authorize", "authorizeReceipt", "handlerResult", "terminal", "terminalReceipt", "note"]);
    hex(r.fingerprint); check(name === `${r.fingerprint}.json`); base58(r.caller); text(r.resource, 4096); timestamp(r.createdAt); timestamp(r.updatedAt);
    check(["authorize-rejected", "completed", "authorize-pending", "authorizing"].includes(r.status));
    check(r.authorize); const a = r.authorize;
    const validatePre = async (a: any, terminalOp = false) => {
      object(a, ["transactionBase64", "signature", "blockhash", "payment", "expectedHeld", "expectedRefundable", ...(terminalOp ? ["op"] : [])], ["lastValidBlockHeight", "lifetimeObservation"]);
      if (a.signature !== "") base58(a.signature, true); base58(a.blockhash); base58(a.payment); decimal(a.expectedHeld); decimal(a.expectedRefundable);
      const w = await wire(a.transactionBase64, program, false); await bind(w, { ...a, payer: r.caller, operation: terminalOp ? a.op : "authorize" }, program); check(w.message.lifetimeToken === a.blockhash);
      if (a.signature !== "") { const j = journals.get(a.signature); check(j && j.entry.messageHash === hash(w.tx.messageBytes) && j.entry.payer === r.caller && j.entry.payment === a.payment); }
      if (a.lastValidBlockHeight !== undefined) decimal(a.lastValidBlockHeight); if (a.lifetimeObservation !== undefined) observation(a.lifetimeObservation, w, network);
      return w;
    };
    const w = await validatePre(a); check(w.op.op === "authorize");
    check(hash(Buffer.concat([Buffer.from(r.caller), Buffer.from([0]), Buffer.from(r.resource), Buffer.from([0]), Buffer.from(w.op.salt)])) === r.fingerprint);
    if (r.status === "authorizing" || r.status === "authorize-pending") check(hash(w.tx.messageBytes) === original.messageHash && a.payment === original.payment && r.caller === original.payer && (a.signature === original.signature || r.status === "authorizing" && a.signature === "") && r.terminal === undefined && r.handlerResult === undefined);
    if (r.authorizeReceipt !== undefined) validateReceipt(r.authorizeReceipt, w, r.caller, a.signature);
    if (r.terminal !== undefined) { check(["capture", "void"].includes(r.terminal.op)); const tw = await validatePre(r.terminal, true); check(tw.payment === w.payment); if (r.terminalReceipt !== undefined) validateReceipt(r.terminalReceipt, tw, r.caller, r.terminal.signature); }
    check(r.terminalReceipt === undefined || r.terminal);
    if (r.handlerResult !== undefined) { object(r.handlerResult, ["ok"], ["detail", "amount", "releaseRemainder"]); check(typeof r.handlerResult.ok === "boolean"); if (r.handlerResult.detail !== undefined) text(r.handlerResult.detail, 4096); if (r.handlerResult.amount !== undefined) decimal(r.handlerResult.amount); if (r.handlerResult.releaseRemainder !== undefined) check(typeof r.handlerResult.releaseRemainder === "boolean"); }
    if (r.note !== undefined) text(r.note, 4096);
    if (r.status === "completed") check(r.authorizeReceipt?.success === true && r.terminalReceipt?.success === true && r.handlerResult);
    if (r.status === "authorize-rejected") check(r.authorizeReceipt?.success === false && r.terminal === undefined && r.handlerResult === undefined);
  }
  const retained: RetainedOrder[] = []; let association: string | null = null; const usedLocks = new Set<string>();
  for (const [name, { value: r }] of stores.orders!) {
    if (!/^[a-f0-9]{32}\.json$/.test(name)) continue;
    object(r, ["id", "capabilityHash", "payer", "payment", "scenario", "required", "unsigned", "createdAt", "status", "events"], ["authorizeLifetime", "reclaimUnsigned", "reclaimLifetime"]);
    hex(r.id, 32); check(name === `${r.id}.json`); hex(r.capabilityHash); base58(r.payer); base58(r.payment); check(["normal", "refund", "cancelled", "unavailable"].includes(r.scenario));
    check(Number.isSafeInteger(r.createdAt) && r.createdAt >= 0 && ["draft", "active", "closed", "pending", "rejected"].includes(r.status));
    const req = r.required; object(req, ["x402Version", "resource", "accepts"], ["error"]); check(req.x402Version === 2); object(req.resource, ["url"], ["description", "mimeType"]); text(req.resource.url, 4096); for (const k of ["description", "mimeType"]) if (req.resource[k] !== undefined) text(req.resource[k]); if (req.error !== undefined) text(req.error);
    list(req.accepts, 1); check(req.accepts.length === 1); const terms = req.accepts[0];
    object(terms, ["scheme", "network", "amount", "asset", "payTo", "maxTimeoutSeconds", "extra"]);
    check(terms.scheme === "auth-capture" && terms.network === network); decimal(terms.amount); base58(terms.asset); base58(terms.payTo); check(Number.isSafeInteger(terms.maxTimeoutSeconds) && terms.maxTimeoutSeconds > 0);
    object(terms.extra, ["captureDeadline", "feePayer", "paymentFlow", "programId", "refundDeadline"]); check(terms.extra.programId === program && terms.extra.paymentFlow === "escrow"); base58(terms.extra.feePayer);
    check(Number.isSafeInteger(terms.extra.captureDeadline) && terms.extra.captureDeadline > 0 && Number.isSafeInteger(terms.extra.refundDeadline) && terms.extra.refundDeadline >= terms.extra.captureDeadline);
    const unsigned = await wire(r.unsigned, program, false); await bind(unsigned, { operation: "authorize", payer: r.payer, payment: r.payment, expectedHeld: "0", expectedRefundable: "0" }, program); check(unsigned.op.op === "authorize");
    check(unsigned.op.maximum.toString() === terms.amount && unsigned.op.captureDeadline === BigInt(terms.extra.captureDeadline) && unsigned.op.refundDeadline === BigInt(terms.extra.refundDeadline) && unsigned.message.staticAccounts[0] === terms.extra.feePayer);
    const ix = unsigned.message.instructions.find(i => unsigned.message.staticAccounts[i.programAddressIndex] === program)!;
    check(unsigned.message.staticAccounts[ix.accountIndices![1]!] === terms.payTo && unsigned.message.staticAccounts[ix.accountIndices![3]!] === terms.asset);
    if (r.authorizeLifetime !== undefined) observation(r.authorizeLifetime, unsigned, network);
    list(r.events, 64); const events = []; const seen = new Set<string>();
    for (const e of r.events) {
      object(e, ["action", "label", "amount", "at", "status", "transaction", "transactionBase64"], ["receipt", "lifetimeObservation"]);
      check(actions.includes(e.action) && !seen.has(e.action)); seen.add(e.action); text(e.label); decimal(e.amount); timestamp(e.at); check(["prepared", "pending", "finalized", "rejected"].includes(e.status)); if (e.transaction !== "") base58(e.transaction, true);
      const w = await wire(e.transactionBase64, program, false); check(w.op.op === opFor(e.action) && w.payment === r.payment);
      await bind(w, { operation: w.op.op, payer: r.payer, payment: r.payment,
        expectedHeld: w.op.op === "authorize" || w.op.op === "reclaim" ? "0" : w.op.expectedHeld.toString(),
        expectedRefundable: w.op.op === "authorize" || w.op.op === "reclaim" ? "0" : w.op.expectedRefundable.toString() }, program);
      if (e.action === "authorize") check(Buffer.from(w.tx.messageBytes).equals(Buffer.from(unsigned.tx.messageBytes)) && e.amount === terms.amount);
      if (e.receipt) check(e.receipt.success === (e.status === "finalized") && (e.status !== "pending" || e.receipt.errorReason === "settlement_pending"));
      if (["finalized", "rejected"].includes(e.status)) {
        check(e.receipt && hash(w.tx.messageBytes) !== original.messageHash);
        if (e.transaction !== "") {
          const j = journals.get(e.transaction); check(j && j.entry.messageHash === hash(w.tx.messageBytes) && j.entry.payer === r.payer && j.entry.payment === r.payment && (e.status === "finalized" ? j.entry.attempts.at(-1).outcome?.result === "finalized-succeeded" : ["not-submitted", "finalized-failed"].includes(j.entry.attempts.at(-1).outcome?.result)));
        } else check(e.status === "rejected" && e.receipt.success === false);
      }
      if (e.lifetimeObservation !== undefined) observation(e.lifetimeObservation, w, network);
      if (e.receipt !== undefined) validateReceipt(e.receipt, w, r.payer, e.transaction);
      if (w.op.op !== "reclaim") check(e.amount === amount(w));
      else { const j = journals.get(e.transaction); check(j && e.amount === j.entry.expectedHeld); }
      if (["pending", "prepared"].includes(e.status)) {
        check(hash(w.tx.messageBytes) === original.messageHash && (e.transaction === original.signature || e.status === "prepared" && e.transaction === "") && r.payer === original.payer && r.payment === original.payment && r.status === "pending");
        check(association === null || association === r.id); association = r.id;
      }
      const lockName = `${r.id}.json.${e.action}.lock`, lock = stores.orders!.get(lockName);
      // Every restaurant attempt has its immutable action lock. Reclaim additionally
      // has the journal's payment-chain reservation and preserves its signed wire.
      {
        check(lock); object(lock.value, ["action", "label", "amount", "at", "status", "transaction", "transactionBase64"], ["receipt", "lifetimeObservation"]);
        const l = lock.value; check(l.action === e.action && l.status === "prepared" && l.transactionBase64 === e.transactionBase64 && l.at === e.at && l.amount === e.amount && l.label === e.label);
        check(l.transaction === (e.action === "reclaim" ? e.transaction : "") && l.receipt === undefined);
        if (e.action === "reclaim") check(journals.get(e.transaction)?.entry.transactionBase64 === e.transactionBase64);
        if (l.lifetimeObservation !== undefined) observation(l.lifetimeObservation, w, network); usedLocks.add(lockName);
      }
      events.push({ action: e.action, amount: e.amount, at: e.at, status: e.status, signature: e.transaction });
    }
    check(r.status !== "pending" || association === r.id); check(r.status !== "draft" || r.events.length === 0);
    if (r.status === "active" || r.status === "closed") check(r.events.some((e: any) => e.action === "authorize" && e.status === "finalized"));
    if (r.status === "closed") check(r.events.some((e: any) => ["finish", "void", "reclaim"].includes(e.action) && e.status === "finalized"));
    if (r.status === "rejected") check(r.events.length === 1 && r.events[0].action === "authorize" && r.events[0].status === "rejected");
    const busy = stores.orders!.get(`${r.id}.json.busy`);
    check(association !== r.id || busy);
    if (busy) { check(association === r.id && r.events.some((e: any) => e.action === busy.value && ["prepared", "pending"].includes(e.status))); usedLocks.add(`${r.id}.json.busy`); }
    if (r.reclaimUnsigned !== undefined) { const w = await wire(r.reclaimUnsigned, program, false); check(w.op.op === "reclaim" && w.payment === r.payment && w.payer === r.payer); }
    if (r.reclaimLifetime !== undefined) { const l = r.reclaimLifetime; object(l, ["blockhash", "lastValidBlockHeight"], ["blockhashSlot"]); base58(l.blockhash); decimal(l.lastValidBlockHeight); if (l.blockhashSlot !== undefined) decimal(l.blockhashSlot); check(r.reclaimUnsigned !== undefined && (await wire(r.reclaimUnsigned, program, false)).message.lifetimeToken === l.blockhash); }
    retained.push({ id: r.id, capabilityHash: r.capabilityHash, payer: r.payer, payment: r.payment, createdAt: r.createdAt, status: r.status, events });
  }
  for (const name of stores.orders!.keys()) check(/^[a-f0-9]{32}\.json$/.test(name) || usedLocks.has(name));
  return projection({ version: 1, mode: MODE, snapshotAt: input.snapshotAt, viewerSha: input.viewerSha, inventorySha256: input.inventorySha256, tupleSha256: input.tupleSha256, network, programId: program,
    original: { signature: original.signature, messageHash: original.messageHash, wireSha256: input.selected.wireSha256, journalSha256: input.selected.journalSha256, operation: original.operation, payment: original.payment, payer: original.payer, status: "UNKNOWN", association, attribution: "retained-facilitator-original" }, orders: retained });
}
if (process.argv[1]?.endsWith("quarantine-projector.ts")) {
  let data = "";
  for await (const chunk of process.stdin) { data += chunk; check(data.length < 32 * 1024 * 1024); }
  try { process.stdout.write(JSON.stringify(await project(strictJson(data))) + "\n"); }
  catch { console.error("PROJECTION_REFUSED"); process.exitCode = 1; }
}
