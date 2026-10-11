// Read-only RestaurantOrders diagnosis. Local receipts and balances never establish the
// original operation's outcome. Only an authenticated original signature at finalized does.
import { createHash } from "node:crypto";
import { constants, openSync, closeSync, fstatSync, lstatSync, readSync, readdirSync } from "node:fs";
import { join } from "node:path";
import {
  type Address, type SignatureBytes, getBase64Encoder, getCompiledTransactionMessageDecoder,
  getTransactionDecoder, getSignatureFromTransaction, getPublicKeyFromAddress, verifySignature,
  getBase64EncodedWireTransaction, isAddress, isSignature,
} from "@solana/kit";
import { ata, authorizeAccounts, captureAccounts, voidAccounts, refundAccounts, reclaimAccounts,
  decodeInstructionData, decodePayment, paymentAddress } from "./program.ts";
import { messageHash, type SubmissionEntry } from "./submission-journal.ts";
import type { ChainReader, SignatureLookup } from "./reconciliation.ts";

const ACTIONS = ["authorize", "beer", "salmon", "finish", "void", "refund", "reclaim"] as const;
type Action = typeof ACTIONS[number];
type Event = { action: Action; amount: string; status: string; transaction: string; transactionBase64: string; receipt?: { transaction?: string; success?: boolean } };
type Order = { id: string; status: string; payer: Address; payment: Address; unsigned: string; reclaimUnsigned?: string; events: Event[];
  required: { accepts: { network: string; payTo: Address; asset: Address; amount: string; extra: { captureDeadline: number | string; refundDeadline: number | string } }[] } };
type Identity = { payer: Address; payment: Address; server: Address; mint: Address; maximum: bigint; captureDeadline: bigint; refundDeadline: bigint; sponsor?: Address; authorizeMessageHash?: string };
type Wire = { bytes: Uint8Array; wireSha256: string; messageHash: string; blockhash: string; signature?: string; fullySigned: boolean; operation: string; expectedBalances?: { held: string; refundable: string } };
export type RestaurantActionEvidence = {
  action: Action; sources: ("order" | "action-lock")[]; amount?: string; orderStatus?: string; lockStatus?: string;
  wireSha256: string[]; lockSha256?: string; messageHash?: string; expectedBalances?: { held: string; refundable: string };
  signature?: string; signatureSource?: "signed-wire" | "submission-journal" | "exact-message-history";
  journals: { sha256: string; signature: string; wireSha256: string; attempts: number; outcomes: string[]; latestOutcome?: string }[];
  status?: { kind: "unavailable" | "not-found" } | { kind: "found"; slot: string; commitment: string; result: "succeeded" | "failed" };
  history?: { kind: "unavailable" } | { kind: "ok"; matches: number; truncated: boolean };
  blockhash?: { kind: "unavailable" } | { kind: "ok"; valid: boolean; slot: string };
  verdict: "finalized-succeeded" | "finalized-failed" | "not-final" | "may-still-land" | "unknown"; issues: string[];
};
export type RestaurantReconcileReport = {
  version: 1; readOnly: true; order: { id: string; sha256: string; status: string; payer: string; payment: string };
  busy: { present: boolean; action?: Action; sha256?: string }; actions: RestaurantActionEvidence[]; issues: string[];
  reclaimReservations: { sha256: string; signature: string; predecessor?: string }[];
  payment: { kind: "unavailable" } | { kind: "ok"; slot: string; exists: false } |
    { kind: "ok"; slot: string; exists: true; held: string; refundable: string };
  conclusion: "definitive" | "unknown"; nextEvidence?: string;
};
export type RestaurantReconcileOptions = {
  ordersDir: string; orderId: string; programId: Address; network: string;
  reader: ChainReader; journalDirs?: readonly string[];
  /** Fenced recovery authenticates its retained preimage and permits ONLY lock-only reconstruction.
   * The ordinary diagnosis command never supplies these options or gains write authority. */
  recoveryPreimage?: Buffer;
  allowLockOnly?: boolean;
};
const sha256 = (bytes: string | Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const decimal = (v: unknown): v is string => typeof v === "string" && /^(0|[1-9][0-9]*)$/.test(v);
const action = (v: unknown): v is Action => ACTIONS.includes(v as Action);
const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
function event(v: unknown): v is Event {
  return object(v) && action(v.action) && decimal(v.amount) && ["prepared", "pending", "finalized", "rejected"].includes(v.status as string) &&
    typeof v.transaction === "string" && (!v.transaction || isSignature(v.transaction)) && typeof v.transactionBase64 === "string" &&
    (v.receipt === undefined || object(v.receipt) && typeof v.receipt.transaction === "string" &&
      (!v.receipt.transaction || isSignature(v.receipt.transaction)) && typeof v.receipt.success === "boolean");
}

function readRegular(path: string): Buffer {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > 1_048_576) throw new Error("file unavailable");
    const bytes = Buffer.alloc(1_048_577);
    let size = 0, count: number;
    while (size < bytes.length && (count = readSync(fd, bytes, size, bytes.length - size, null)) > 0) size += count;
    if (size > 1_048_576) throw new Error("bounded local read exceeded");
    // Validate text without using decoded text as file evidence: TextDecoder strips a BOM.
    new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, size));
    return Buffer.from(bytes.subarray(0, size));
  } finally { closeSync(fd); }
}

// No RestaurantOrders constructor: even a missing directory must never be created here.
// Capture the read set twice so a concurrent durable replacement cannot produce a definitive
// report from mixed versions. Failed reads and malformed records remain generic and private.
function files(dir: string): Map<string, Buffer> {
  if (!lstatSync(dir).isDirectory() || lstatSync(dir).isSymbolicLink()) throw new Error("directory unavailable");
  const names = readdirSync(dir).sort();
  if (names.length > 2000) throw new Error("bounded local read exceeded");
  const result = new Map<string, Buffer>();
  let totalBytes = 0;
  for (const name of names) {
    if (!name.endsWith(".json") && !name.endsWith(".lock") && !name.endsWith(".busy")) continue;
    const raw = readRegular(join(dir, name));
    totalBytes += raw.length;
    if (totalBytes > 32 * 1_048_576) throw new Error("bounded local read exceeded");
    result.set(name, raw);
  }
  return result;
}
function orderFiles(dir: string, id: string): Map<string, Buffer> {
  const directory = lstatSync(dir);
  if (!directory.isDirectory() || directory.isSymbolicLink()) throw new Error("directory unavailable");
  const result = new Map<string, Buffer>();
  for (const suffix of [".json", ".json.busy", ...ACTIONS.map(a => `.json.${a}.lock`)]) {
    const name = id + suffix;
    try {
      result.set(name, readRegular(join(dir, name)));
    } catch (e) { if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e; }
  }
  return result;
}
function parseJson(bytes: Buffer): unknown {
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
}
function sameFiles(a: Map<string, Buffer>, b: Map<string, Buffer>): boolean {
  return a.size === b.size && [...a].every(([name, bytes]) => b.get(name)?.equals(bytes));
}

async function decodeWire(wire: string, identity: Identity, programId: Address, expectedAction: Action, amount: string, requireAuthority = true): Promise<Wire> {
  if (typeof wire !== "string" || !wire || wire.length > 1644 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(wire)) throw new Error("wire invalid");
  const raw = getBase64Encoder().encode(wire);
  if (raw.length > 1232) throw new Error("wire invalid");
  const tx = getTransactionDecoder().decode(raw), bytes = new Uint8Array(tx.messageBytes);
  const [m, end] = getCompiledTransactionMessageDecoder().read(bytes, 0);
  if (end !== bytes.length || getBase64EncodedWireTransaction(tx) !== wire) throw new Error("noncanonical wire");
  if (m.version !== "legacy") throw new Error("unsupported original wire");
  const computeTags = new Set<number>();
  for (const i of m.instructions) {
    if (m.staticAccounts[i.programAddressIndex] === programId) continue;
    const data = new Uint8Array(i.data ?? []), tag = data[0];
    if (m.staticAccounts[i.programAddressIndex] !== "ComputeBudget111111111111111111111111111111" ||
        (i.accountIndices ?? []).length || tag !== 2 && tag !== 3 ||
        data.length !== (tag === 2 ? 5 : 9) || computeTags.has(tag)) throw new Error("instruction outside restaurant wire");
    computeTags.add(tag);
  }
  const instructions = m.instructions.filter(i => m.staticAccounts[i.programAddressIndex] === programId);
  if (instructions.length !== 1) throw new Error("operation invalid");
  const ix = instructions[0]!, op = decodeInstructionData(new Uint8Array(ix.data ?? []));
  const expectedOp = expectedAction === "beer" || expectedAction === "salmon" ? "capture" : expectedAction === "finish" ? "void" : expectedAction;
  if (!op || op.op !== expectedOp) throw new Error("action mismatch");
  const accounts = (ix.accountIndices ?? []).map(i => m.staticAccounts[i]);
  const authority = op.op === "authorize" || op.op === "reclaim" ? identity.payer : identity.server;
  const sponsor = identity.sponsor ?? m.staticAccounts[0]!;
  if (op.op === "reclaim" ? m.header.numSignerAccounts !== 1 || m.staticAccounts[0] !== identity.payer :
      m.header.numSignerAccounts !== 2 || m.staticAccounts[0] !== sponsor || m.staticAccounts[1] !== authority || sponsor === authority) throw new Error("signer layout mismatch");
  const common = { payer: identity.payer, server: identity.server, payment: identity.payment, mint: identity.mint,
    source: await ata(identity.payer, identity.mint), payerAta: await ata(identity.payer, identity.mint),
    vault: await ata(identity.payment, identity.mint), serverAta: await ata(identity.server, identity.mint), funder: sponsor };
  const expectedAccounts = op.op === "authorize" ? authorizeAccounts(common) : op.op === "capture" ? captureAccounts(common) :
    op.op === "refund" ? refundAccounts(common) : op.op === "void" ? voidAccounts(common) : reclaimAccounts(common);
  if (accounts.length !== expectedAccounts.length || (ix.accountIndices ?? []).some((index, n) => {
    const expected = expectedAccounts[n]!;
    const signer = index < m.header.numSignerAccounts;
    const writable = signer ? index < m.header.numSignerAccounts - m.header.numReadonlySignerAccounts :
      index < m.staticAccounts.length - m.header.numReadonlyNonSignerAccounts;
    // Payer-direct reclaim makes the economic signer writable as the fee payer.
    return accounts[n] !== expected.address || signer !== expected.signer ||
      writable !== (expected.writable || op.op === "reclaim" && n === 0);
  })) throw new Error("account layout mismatch");
  if (accounts[0] !== authority || accounts[op.op === "authorize" ? 2 : 1] !== identity.payment ||
      accounts[op.op === "authorize" ? 3 : 2] !== identity.mint || op.op === "authorize" && accounts[1] !== identity.server) throw new Error("identity mismatch");
  if (op.op === "authorize" && (op.maximum !== identity.maximum || op.captureDeadline !== identity.captureDeadline ||
      op.refundDeadline !== identity.refundDeadline || await paymentAddress(programId, identity.payer, op.salt) !== identity.payment ||
      BigInt(amount) !== op.maximum)) throw new Error("authorization mismatch");
  if (op.op === "authorize" && identity.authorizeMessageHash && messageHash(bytes) !== identity.authorizeMessageHash) throw new Error("offered authorization mismatch");
  if ((op.op === "capture" || op.op === "refund") && op.amount !== BigInt(amount) ||
      op.op === "capture" && op.releaseRemainder || op.op === "void" && op.expectedHeld !== BigInt(amount)) throw new Error("amount mismatch");
  let fullySigned = true;
  const signers = m.staticAccounts.slice(0, m.header.numSignerAccounts);
  if (!signers.includes(authority)) throw new Error("authority absent");
  for (const signer of signers) {
    const sig = tx.signatures[signer];
    const present = sig && new Uint8Array(sig).some(b => b !== 0);
    if (!present) { fullySigned = false; if (requireAuthority && signer === authority) throw new Error("authority unsigned"); }
    else if (!await verifySignature(await getPublicKeyFromAddress(signer), sig as SignatureBytes, bytes)) throw new Error("signature invalid");
  }
  const feeSignature = tx.signatures[m.staticAccounts[0]!];
  return { bytes, messageHash: messageHash(bytes), wireSha256: sha256(new Uint8Array(raw)), blockhash: m.lifetimeToken,
    fullySigned, operation: op.op,
    ...(op.op === "authorize" ? { expectedBalances: { held: "0", refundable: "0" } } :
      "expectedHeld" in op ? { expectedBalances: { held: op.expectedHeld.toString(), refundable: op.expectedRefundable.toString() } } : {}),
    ...(feeSignature && new Uint8Array(feeSignature).some(b => b !== 0) ? { signature: getSignatureFromTransaction(tx) } : {}) };
}

/** Uses only ChainReader methods. No signer, writer, simulation or broadcast capability. */
export async function reconcileRestaurantOrder(options: RestaurantReconcileOptions): Promise<RestaurantReconcileReport> {
  const { ordersDir, orderId, programId, network, reader } = options;
  if (!/^[a-f0-9]{32}$/.test(orderId)) throw new Error("invalid order ID");
  let local: Map<string, Buffer>, order: Order, identity: Identity;
  try {
    local = orderFiles(ordersDir, orderId);
    order = parseJson(options.recoveryPreimage ?? local.get(`${orderId}.json`)!) as Order;
    const accepted = order.required.accepts[0]!;
    if (order.id !== orderId || !isAddress(order.payer) || !isAddress(order.payment) || !isAddress(accepted.payTo) ||
        !isAddress(accepted.asset) || accepted.network !== network || accepted.amount !== "100000000" ||
        !["draft", "active", "closed", "pending", "rejected"].includes(order.status) ||
        !Array.isArray(order.events) || order.events.length > ACTIONS.length || !order.events.every(event)) throw new Error("order invalid");
    identity = { payer: order.payer, payment: order.payment, server: accepted.payTo, mint: accepted.asset,
      maximum: BigInt(accepted.amount), captureDeadline: BigInt(accepted.extra.captureDeadline), refundDeadline: BigInt(accepted.extra.refundDeadline) };
    const offered = await decodeWire(order.unsigned, identity, programId, "authorize", accepted.amount, false);
    identity.authorizeMessageHash = offered.messageHash;
    identity.sponsor = getCompiledTransactionMessageDecoder().decode(offered.bytes).staticAccounts[0]!;
  } catch { throw new Error("restaurant order unavailable or invalid"); }
  const issues: string[] = [];
  const busyBytes = local.get(`${orderId}.json.busy`), busyValue = busyBytes?.toString("utf8");
  const busy = { present: busyBytes !== undefined, ...(busyBytes !== undefined ? { sha256: sha256(busyBytes) } : {}), ...(action(busyValue) ? { action: busyValue } : {}) };
  if (busy.present && !busy.action) issues.push("invalid busy reservation");
  const journalSnapshots = new Map<string, Map<string, Buffer>>();
  const entries: { entry: SubmissionEntry; sha256: string; dir: string }[] = [];
  const dirs = [...new Set(options.journalDirs ?? [])];
  if (!dirs.length) issues.push("submission journals not supplied");
  for (const dir of dirs) {
    try {
      const snapshot = files(dir); journalSnapshots.set(dir, snapshot);
      for (const [name, raw] of snapshot) if (name.endsWith(".json")) {
        const entry = parseJson(raw) as SubmissionEntry;
        if (!object(entry) || typeof entry.messageHash !== "string" || !/^[a-f0-9]{64}$/.test(entry.messageHash) ||
            !isAddress(entry.payment) || !isAddress(entry.payer) || !isAddress(entry.blockhash) || typeof entry.transactionBase64 !== "string" ||
            !["authorize", "capture", "void", "refund", "reclaim", "setup"].includes(entry.operation) ||
            !isSignature(entry.signature) || !decimal(entry.expectedHeld) || !decimal(entry.expectedRefundable) ||
            name !== `${entry.signature}.json` || !Array.isArray(entry.attempts) ||
            !entry.attempts.length || !entry.attempts.every(a => object(a) && typeof a.preparedAt === "string" &&
              (a.outcome === undefined || object(a.outcome) && typeof a.outcome.recordedAt === "string" &&
                ["not-submitted", "unresolved", "finalized-succeeded", "finalized-failed", "submit-threw"].includes(a.outcome.result as string)))) throw new Error("journal invalid");
        entries.push({ entry, sha256: sha256(raw), dir });
      }
    } catch { issues.push("submission journal unavailable or invalid"); }
  }
  const reclaimReservations: RestaurantReconcileReport["reclaimReservations"] = [];
  for (const [dir, snapshot] of journalSnapshots) {
    const rootName = `reclaim-${identity.payment}.lock`, prefix = `reclaim-${identity.payment}-after-`;
    const reservations = [...snapshot].filter(([name]) => name === rootName || name.startsWith(prefix) && name.endsWith(".lock"));
    const successors = new Map<string, string>();
    const reclaimEntries = entries.filter(j => j.dir === dir && j.entry.operation === "reclaim" && j.entry.payment === identity.payment);
    for (const { entry } of reclaimEntries) {
      if (entry.retryAfter !== undefined && (!isSignature(entry.retryAfter) || entry.retryAfter === entry.signature)) {
        issues.push("reclaim reservation predecessor invalid"); continue;
      }
      const name = entry.retryAfter === undefined ? rootName : `${prefix}${entry.retryAfter}.lock`;
      if (snapshot.get(name)?.toString("utf8") !== entry.signature) issues.push("reclaim submission journal lacks matching reservation");
    }
    for (const [name, raw] of reservations) {
      const signature = raw.toString("utf8");
      const predecessor = name === rootName ? undefined : name.slice(prefix.length, -5);
      if (!isSignature(signature) || predecessor !== undefined && !isSignature(predecessor)) {
        issues.push("reclaim reservation invalid"); continue;
      }
      reclaimReservations.push({ sha256: sha256(raw), signature, ...(predecessor ? { predecessor } : {}) });
      if (!reclaimEntries.some(j => j.entry.signature === signature &&
          j.entry.payer === identity.payer && j.entry.retryAfter === predecessor)) {
        issues.push("reclaim reservation lacks matching submission journal");
      }
      if (predecessor) successors.set(predecessor, signature);
    }
    const visited = new Set<string>();
    let current = snapshot.get(rootName)?.toString("utf8");
    while (current && !visited.has(current)) { visited.add(current); current = successors.get(current); }
    if (current || reservations.some(([, raw]) => !visited.has(raw.toString("utf8")))) issues.push("reclaim reservation chain invalid");
  }
  const actions: RestaurantActionEvidence[] = [], used = new Set<SubmissionEntry>();
  let minSlot = 0n;
  for (const a of ACTIONS) {
    const originals = order.events.filter(e => e.action === a);
    const rawLock = local.get(`${orderId}.json.${a}.lock`);
    if (!originals.length && rawLock === undefined) continue;
    const report: RestaurantActionEvidence = { action: a, sources: originals.length ? ["order"] : [],
      wireSha256: [], journals: [], verdict: "unknown", issues: [] };
    actions.push(report);
    let lock: Event | undefined;
    if (rawLock !== undefined) {
      report.sources.push("action-lock");
      report.lockSha256 = sha256(rawLock);
      try { const parsed = parseJson(rawLock); if (!event(parsed) || parsed.action !== a) throw new Error("lock invalid"); lock = parsed; report.lockStatus = lock.status; }
      catch { report.issues.push("action lock invalid"); }
    } else report.issues.push("action lock missing");
    if (originals.length > 1) report.issues.push("duplicate order action");
    const original = originals[0];
    if (original) report.orderStatus = original.status;
    if (!original && lock && !options.allowLockOnly) report.issues.push("prepared action missing from order");
    const copies = [...originals, ...(lock ? [lock] : [])], wires: Wire[] = [];
    for (const copy of copies) {
      try {
        const decoded = await decodeWire(copy.transactionBase64, identity, programId, a, copy.amount);
        if (a === "reclaim") {
          const offered = await decodeWire(order.reclaimUnsigned!, identity, programId, a, copy.amount, false);
          if (offered.messageHash !== decoded.messageHash) throw new Error("reclaim offer mismatch");
        }
        wires.push(decoded);
      }
      catch { report.issues.push("original wire invalid or not bound to order"); }
    }
    report.wireSha256 = [...new Set(wires.map(w => w.wireSha256))];
    report.amount = copies[0]?.amount;
    const hashes = new Set(wires.map(w => w.messageHash));
    if (hashes.size > 1 || new Set(copies.map(c => c.amount)).size > 1) report.issues.push("order and lock disagree");
    const wire = wires[0]; if (!wire) continue;
    report.messageHash = wire.messageHash;
    report.expectedBalances = wire.expectedBalances;
    const candidates = new Set(wires.flatMap(w => w.signature ? [w.signature] : []));
    let source: RestaurantActionEvidence["signatureSource"] = candidates.size ? "signed-wire" : undefined;
    for (const item of entries.filter(j => hashes.has(j.entry.messageHash))) {
      used.add(item.entry);
      try {
        const j = item.entry, signed = await decodeWire(j.transactionBase64, identity, programId, a, report.amount!);
        if (!signed.fullySigned || signed.signature !== j.signature || signed.messageHash !== j.messageHash ||
            signed.messageHash !== wire.messageHash || signed.blockhash !== j.blockhash || j.operation !== signed.operation ||
            j.payment !== identity.payment || j.payer !== identity.payer ||
            a === "reclaim" && j.expectedHeld !== report.amount ||
            signed.expectedBalances && (j.expectedHeld !== signed.expectedBalances.held ||
              j.expectedRefundable !== signed.expectedBalances.refundable)) throw new Error("journal binding invalid");
        candidates.add(j.signature); source ??= "submission-journal";
        report.journals.push({ sha256: item.sha256, signature: j.signature, wireSha256: signed.wireSha256,
          attempts: j.attempts.length, outcomes: j.attempts.flatMap(a => a.outcome ? [a.outcome.result] : []),
          ...(j.attempts.at(-1)?.outcome ? { latestOutcome: j.attempts.at(-1)!.outcome!.result } : {}) });
      } catch { report.issues.push("submission journal does not authenticate original operation"); }
    }
    const claims = new Set(copies.flatMap(c => [c.transaction, c.receipt?.transaction ?? ""].filter(Boolean)));
    if (!candidates.size) {
      try {
        const search = await reader.findSignaturesByMessage(identity.payment, wire.bytes);
        report.history = search.kind === "ok" ? { kind: "ok", matches: search.signatures.length, truncated: search.truncated } : { kind: "unavailable" };
        if (search.kind === "ok" && search.signatures.length === 1 && !search.truncated && isSignature(search.signatures[0]!)) {
          candidates.add(search.signatures[0]!); source = "exact-message-history";
        }
      } catch { report.history = { kind: "unavailable" }; }
    }
    if (candidates.size !== 1) report.issues.push(candidates.size ? "ambiguous original signature" : "authenticated original signature unavailable");
    const signature = [...candidates][0];
    if (claims.size && (claims.size !== 1 || !signature || !claims.has(signature))) report.issues.push("receipt signature not bound to original message");
    if (signature && candidates.size === 1) {
      report.signature = signature; report.signatureSource = source;
      let status: SignatureLookup;
      try { status = await reader.getSignatureStatus(signature); } catch { status = { kind: "unavailable", detail: "" }; }
      if (status.kind === "found" && status.slot >= 0n && ["processed", "confirmed", "finalized"].includes(status.commitment) &&
          (status.err === null || typeof status.err === "string" && status.err.length > 0)) {
        if (status.slot > minSlot) minSlot = status.slot;
        report.status = { kind: "found", slot: status.slot.toString(), commitment: status.commitment, result: status.err === null ? "succeeded" : "failed" };
        report.verdict = status.commitment === "finalized" ? status.err === null ? "finalized-succeeded" : "finalized-failed" : "not-final";
        if (status.commitment === "finalized" && report.journals.some(j => j.outcomes.some(outcome =>
          outcome === "finalized-succeeded" && status.err !== null ||
          outcome === "finalized-failed" && status.err === null) ||
          j.latestOutcome === "not-submitted")) report.issues.push("journal outcome disagrees with finalized evidence");
        if (copies.some(c => c.status === "finalized" && report.verdict !== "finalized-succeeded" ||
            c.status === "rejected" && report.verdict === "finalized-succeeded" ||
            c.receipt && c.receipt.success && report.verdict !== "finalized-succeeded")) report.issues.push("persisted result disagrees with chain evidence");
      } else report.status = { kind: status.kind === "not-found" ? "not-found" : "unavailable" };
    }
    if (report.verdict === "unknown") {
      try {
        const check = await reader.isBlockhashValid(wire.blockhash);
        if (check.kind === "ok" && check.slot >= 0n) {
          report.blockhash = { kind: "ok", valid: check.valid, slot: check.slot.toString() };
          if (check.slot > minSlot) minSlot = check.slot;
          if (check.valid && report.status?.kind === "not-found") report.verdict = "may-still-land";
        } else report.blockhash = { kind: "unavailable" };
      } catch { report.blockhash = { kind: "unavailable" }; }
    }
    if (report.issues.length) report.verdict = "unknown";
  }
  if (entries.some(j => !used.has(j.entry) && j.entry.payment === identity.payment)) issues.push("submission journal operation missing from order and locks");
  if (busy.action && !actions.some(a => a.action === busy.action)) issues.push("busy reservation has no prepared action");
  if (order.status === "pending" && !actions.length) issues.push("pending order has no prepared action");
  let payment: RestaurantReconcileReport["payment"] = { kind: "unavailable" };
  try {
    const read = await reader.getAccountAtLeast(identity.payment, minSlot);
    if (read.kind === "ok" && read.slot >= minSlot) {
      if (!read.account) payment = { kind: "ok", slot: read.slot.toString(), exists: false };
      else {
        const p = decodePayment(read.account.data);
        if (!p || read.account.owner !== programId || read.account.executable || p.payer !== identity.payer ||
            p.server !== identity.server || p.mint !== identity.mint || p.maximum !== identity.maximum ||
            p.captureDeadline !== identity.captureDeadline || p.refundDeadline !== identity.refundDeadline ||
            await paymentAddress(programId, p.payer, p.salt) !== identity.payment) issues.push("finalized payment identity mismatch");
        else payment = { kind: "ok", slot: read.slot.toString(), exists: true, held: p.held.toString(), refundable: p.refundable.toString() };
      }
    }
  } catch { /* Never serialize provider errors, URLs, or credentials. */ }
  if (payment.kind === "unavailable") issues.push("finalized payment evidence unavailable or stale");
  // SAC-006 never closes/re-authorizes a payment, and held only decreases. Use those
  // invariants to detect contradictions with proven success, never to prove a missing
  // transaction failed. Later capture/refund/reclaim can change the pair legitimately.
  if (payment.kind === "ok") for (const a of actions) {
    if (a.verdict !== "finalized-succeeded") continue;
    const maximumHeld = a.action === "finish" || a.action === "void" || a.action === "reclaim" ? 0n :
      a.expectedBalances ? a.action === "authorize" ? identity.maximum :
        BigInt(a.expectedBalances.held) - (a.action === "beer" || a.action === "salmon" ? BigInt(a.amount!) : 0n) : identity.maximum;
    if (!payment.exists || BigInt(payment.held) > maximumHeld) {
      a.issues.push("finalized payment contradicts original success"); a.verdict = "unknown";
      issues.push("finalized payment contradicts original success");
    }
  }
  try {
    if (!sameFiles(orderFiles(ordersDir, orderId), local) ||
        dirs.some(dir => !journalSnapshots.has(dir) || !sameFiles(files(dir), journalSnapshots.get(dir)!))) issues.push("local evidence changed during reconciliation");
  } catch { issues.push("local evidence changed or became unavailable during reconciliation"); }
  const definitive = actions.length > 0 && !issues.length && actions.every(a => a.verdict === "finalized-succeeded" || a.verdict === "finalized-failed");
  return { version: 1, readOnly: true, order: { id: orderId, sha256: sha256(local.get(`${orderId}.json`)!), status: order.status, payer: order.payer, payment: order.payment },
    busy, reclaimReservations, actions, payment, issues, conclusion: definitive ? "definitive" : "unknown",
    ...(definitive ? {} : { nextEvidence: "Obtain authenticated original signed-wire/signature and finalized history; preserve all reservations. Balances or missing history cannot prove non-execution." }) };
}
