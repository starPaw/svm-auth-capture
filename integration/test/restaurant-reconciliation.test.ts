import { mkdtempSync, mkdirSync, readdirSync, readFileSync, writeFileSync, unlinkSync, statSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import {
  generateKeyPairSigner, getAddressEncoder, getSignatureFromTransaction, partiallySignTransaction,
  getBase64Encoder, getTransactionDecoder, type Address, type Transaction,
} from "@solana/kit";
import { beforeEach, describe, expect, test, vi } from "vitest";
import { reconcileRestaurantOrder, type RestaurantReconcileOptions } from "../src/restaurant-reconciliation.ts";
import { authorizeInstruction, buildTransaction, captureInstruction, encodeTransaction, reclaimInstruction, refundInstruction, voidInstruction } from "../src/transactions.ts";
import { DISCRIMINATOR, LOCAL_PROGRAM_ID, NATIVE_MINT, paymentAddress } from "../src/program.ts";
import { messageHash, type SubmissionEntry } from "../src/submission-journal.ts";
import { RestaurantOrders } from "../src/restaurant.ts";
import { demoComputeInstructions } from "../src/demo-compute.ts";
import type { ChainReader, SignatureLookup } from "../src/reconciliation.ts";

const ID = "1234567890abcdef1234567890abcdef";
const NETWORK = "solana:synthetic-fixture";
const BLOCKHASH = "11111111111111111111111111111111" as Parameters<ChainReader["isBlockhashValid"]>[0];
const PRIVATE = "private-capability-token-and-provider-credential";
let payer: Awaited<ReturnType<typeof generateKeyPairSigner>>, merchant: typeof payer, sponsor: typeof payer;
let payment: Address, partial: Transaction, signed: Transaction, signature: string;
let root: string, orders: string, journal: string, path: string, lockPath: string, busyPath: string;
let order: any, event: any, entry: SubmissionEntry, reader: ChainReader, options: RestaurantReconcileOptions;
const salt = new Uint8Array(32).fill(7);
function account(held = 100_000_000n, refundable = 0n) {
  const data = new Uint8Array(176), addresses = getAddressEncoder(), view = new DataView(data.buffer);
  data.set(DISCRIMINATOR); data.set(addresses.encode(payer.address), 8); data.set(addresses.encode(merchant.address), 40);
  data.set(addresses.encode(NATIVE_MINT), 72); data.set(salt, 104);
  view.setBigUint64(136, 100_000_000n, true); view.setBigInt64(144, 1000n, true); view.setBigInt64(152, 1100n, true);
  view.setBigUint64(160, held, true); view.setBigUint64(168, refundable, true);
  return { owner: LOCAL_PROGRAM_ID, data, lamports: 1n, executable: false };
}
function persist() {
  writeFileSync(path, JSON.stringify(order));
  writeFileSync(lockPath, JSON.stringify(event));
  writeFileSync(busyPath, "beer");
}
function persistJournal() { writeFileSync(join(journal, signature + ".json"), JSON.stringify(entry)); }
function snapshot(dir: string): unknown {
  return readdirSync(dir).sort().map(name => {
    const file = join(dir, name), stat = statSync(file);
    return stat.isDirectory() ? [name, snapshot(file)] : [name, readFileSync(file).toString("base64"), stat.mtimeMs];
  });
}
async function inspect() {
  const before = snapshot(root);
  const result = await reconcileRestaurantOrder(options);
  expect(snapshot(root)).toEqual(before);
  expect(JSON.stringify(result)).not.toContain(PRIVATE);
  expect(JSON.stringify(result)).not.toContain("transactionBase64");
  expect(JSON.stringify(result)).not.toContain("capabilityHash");
  return result;
}
function found(commitment: "processed" | "confirmed" | "finalized" = "finalized", err: string | null = null): SignatureLookup {
  return { kind: "found", commitment, slot: 40n, err };
}
beforeEach(async () => {
  [payer, merchant, sponsor] = await Promise.all([generateKeyPairSigner(), generateKeyPairSigner(), generateKeyPairSigner()]);
  payment = await paymentAddress(LOCAL_PROGRAM_ID, payer.address, salt);
  const stored = { programId: LOCAL_PROGRAM_ID, payment, payer: payer.address, server: merchant.address, mint: NATIVE_MINT };
  partial = await buildTransaction({ feePayer: sponsor.address, signers: [merchant],
    instructions: [await captureInstruction(stored, 40_000_000n, false, 100_000_000n, 0n)],
    lifetime: { blockhash: BLOCKHASH as any, lastValidBlockHeight: 10n } });
  signed = await partiallySignTransaction([sponsor.keyPair], partial); signature = getSignatureFromTransaction(signed);
  const unsigned = await buildTransaction({ feePayer: sponsor.address, signers: [], instructions: [await authorizeInstruction({
    programId: LOCAL_PROGRAM_ID, payer: payer.address, server: merchant.address, mint: NATIVE_MINT, funder: sponsor.address,
    salt, maximum: 100_000_000n, captureDeadline: 1000n, refundDeadline: 1100n,
  })], lifetime: { blockhash: BLOCKHASH as any, lastValidBlockHeight: 10n } });
  root = mkdtempSync(join(tmpdir(), "restaurant-reconcile-synthetic-")); orders = join(root, "orders"); journal = join(root, "journal");
  mkdirSync(orders); mkdirSync(journal); path = join(orders, ID + ".json"); lockPath = path + ".beer.lock"; busyPath = path + ".busy";
  event = { action: "beer", amount: "40000000", status: "prepared", transaction: "", transactionBase64: encodeTransaction(partial), label: PRIVATE, at: "synthetic" };
  order = { id: ID, status: "pending", payer: payer.address, payment, capabilityHash: PRIVATE, scenario: "normal",
    unsigned: encodeTransaction(unsigned), events: [{ ...event }],
    required: { resource: { url: "https://example.invalid/" + PRIVATE }, accepts: [{
      network: NETWORK, payTo: merchant.address, asset: NATIVE_MINT, amount: "100000000", extra: { captureDeadline: 1000, refundDeadline: 1100 },
    }] } };
  entry = { signature, transactionBase64: encodeTransaction(signed), messageHash: messageHash(partial.messageBytes), blockhash: BLOCKHASH,
    operation: "capture", payment, payer: payer.address, expectedHeld: "100000000", expectedRefundable: "0",
    attempts: [{ preparedAt: "synthetic", outcome: { result: "unresolved", recordedAt: "synthetic", detail: PRIVATE } }] };
  reader = {
    getSignatureStatus: vi.fn(async () => found()),
    findSignaturesByMessage: vi.fn(async () => ({ kind: "ok" as const, signatures: [], truncated: false })),
    isBlockhashValid: vi.fn(async () => ({ kind: "ok" as const, valid: false, slot: 41n })),
    getAccountAtLeast: vi.fn(async () => ({ kind: "ok" as const, slot: 42n, account: account(60_000_000n, 40_000_000n) })),
  };
  // Trap every economic capability, including ones not present in ChainReader.
  for (const name of ["submit", "simulate", "sign", "prepare", "resolve", "unlock"]) {
    Object.defineProperty(reader, name, { get: () => { throw new Error("forbidden mutation " + name); } });
  }
  options = { ordersDir: orders, orderId: ID, programId: LOCAL_PROGRAM_ID, network: NETWORK, reader, journalDirs: [journal] };
  persist();
});

describe("crash boundaries preserve durable evidence", () => {
  test("before preparation: draft without an attempt is unknown", async () => {
    order.status = "draft"; order.events = []; writeFileSync(path, JSON.stringify(order)); unlinkSync(lockPath); unlinkSync(busyPath);
    const report = await inspect(); expect(report.actions).toEqual([]); expect(report.conclusion).toBe("unknown");
  });
  test("reservation saved before preparation: busy has no wire", async () => {
    order.status = "active"; order.events = []; writeFileSync(path, JSON.stringify(order)); unlinkSync(lockPath);
    const report = await inspect(); expect(report.busy).toMatchObject({ present: true, action: "beer" });
    expect(report.issues).toContain("busy reservation has no prepared action"); expect(report.conclusion).toBe("unknown");
  });
  test("lock persisted but order replacement failed: inspect the lock-only message", async () => {
    order.events = []; writeFileSync(path, JSON.stringify(order)); persistJournal();
    const report = await inspect(); expect(report.actions[0]).toMatchObject({ sources: ["action-lock"], messageHash: entry.messageHash, signature });
    expect(report.actions[0]!.issues).toContain("prepared action missing from order"); expect(report.conclusion).toBe("unknown");
  });
  test("order saved before journal: empty history and expired-looking blockhash stay unknown", async () => {
    const report = await inspect(); expect(report.actions[0]!.verdict).toBe("unknown");
    expect(reader.findSignaturesByMessage).toHaveBeenCalledWith(payment, new Uint8Array(partial.messageBytes));
  });
  test("journal prepared before possible broadcast: valid blockhash may still land", async () => {
    persistJournal(); vi.mocked(reader.getSignatureStatus).mockResolvedValue({ kind: "not-found" });
    vi.mocked(reader.isBlockhashValid).mockResolvedValue({ kind: "ok", valid: true, slot: 41n });
    const report = await inspect(); expect(report.actions[0]!.verdict).toBe("may-still-land"); expect(report.conclusion).toBe("unknown");
  });
  test.each(["broadcast response lost", "journal outcome replacement failed", "receipt persistence failed"])("%s: original finalized signature remains attributable", async () => {
    entry.attempts[0]!.outcome = undefined; persistJournal();
    const report = await inspect(); expect(report.actions[0]).toMatchObject({ signature, signatureSource: "submission-journal", verdict: "finalized-succeeded" });
    expect(report.order.status).toBe("pending"); expect(report.busy.present).toBe(true); expect(report.conclusion).toBe("definitive");
    expect(reader.findSignaturesByMessage).not.toHaveBeenCalled();
  });
  test("receipt saved before unlock: finalized outcome does not clear busy or locks", async () => {
    persistJournal(); order.status = "active"; Object.assign(order.events[0], { status: "finalized", transaction: signature, receipt: { success: true, transaction: signature } }); persist();
    const report = await inspect(); expect(report.conclusion).toBe("definitive"); expect(report.busy.present).toBe(true);
    expect(report.actions[0]).toMatchObject({ orderStatus: "finalized", lockStatus: "prepared" });
  });
  test("after unlock: action lock is retained and reported", async () => {
    persistJournal(); order.status = "active"; Object.assign(order.events[0], { status: "finalized", transaction: signature }); persist(); unlinkSync(busyPath);
    const report = await inspect(); expect(report.conclusion).toBe("definitive"); expect(report.busy.present).toBe(false);
  });
  test("finalized failure is attributed without copying RPC execution error text", async () => {
    persistJournal(); vi.mocked(reader.getSignatureStatus).mockResolvedValue(found("finalized", PRIVATE));
    order.events[0].status = "rejected"; order.events[0].transaction = signature; persist();
    const report = await inspect(); expect(report.actions[0]!.verdict).toBe("finalized-failed"); expect(report.conclusion).toBe("definitive");
  });
});

describe("uncertainty and authentication", () => {
  test.each(["processed", "confirmed"] as const)("%s is never finalized", async commitment => {
    persistJournal(); vi.mocked(reader.getSignatureStatus).mockResolvedValue(found(commitment));
    const report = await inspect(); expect(report.actions[0]!.verdict).toBe("not-final"); expect(report.conclusion).toBe("unknown");
  });
  test.each([100_000_000n, 60_000_000n, 0n])("missing original history with held=%s does not infer execution", async held => {
    persistJournal(); vi.mocked(reader.getSignatureStatus).mockResolvedValue({ kind: "not-found" });
    vi.mocked(reader.getAccountAtLeast).mockResolvedValue({ kind: "ok", slot: 42n, account: account(held) });
    const report = await inspect(); expect(report.actions[0]!.verdict).toBe("unknown"); expect(report.conclusion).toBe("unknown");
  });
  test("authenticated exact-message fallback discovers a lost signature", async () => {
    vi.mocked(reader.findSignaturesByMessage).mockResolvedValue({ kind: "ok", signatures: [signature], truncated: false });
    const report = await inspect(); expect(report.actions[0]).toMatchObject({ signature, signatureSource: "exact-message-history", verdict: "finalized-succeeded" });
  });
  test.each(["unavailable", "absent", "truncated"] as const)("%s history retains unknown", async mode => {
    const history = mode === "unavailable" ? { kind: "unavailable" as const, detail: PRIVATE } :
      { kind: "ok" as const, signatures: mode === "truncated" ? [signature] : [], truncated: mode === "truncated" };
    vi.mocked(reader.findSignaturesByMessage).mockResolvedValue(history);
    const report = await inspect(); expect(report.conclusion).toBe("unknown");
  });
  test("multiple history matches are ambiguous", async () => {
    vi.mocked(reader.findSignaturesByMessage).mockResolvedValue({ kind: "ok", signatures: [signature, signature], truncated: false });
    expect((await inspect()).conclusion).toBe("unknown");
  });
  test("a receipt alone cannot authenticate a partially signed original", async () => {
    order.events[0].transaction = signature; persist();
    const report = await inspect(); expect(reader.getSignatureStatus).not.toHaveBeenCalled();
    expect(report.actions[0]!.issues).toContain("receipt signature not bound to original message");
  });
  test("wrong receipt signature cannot substitute a successful transaction", async () => {
    persistJournal(); order.events[0].transaction = getSignatureFromTransaction(await partiallySignTransaction([sponsor.keyPair], await buildTransaction({
      feePayer: sponsor.address, signers: [], instructions: [], lifetime: { blockhash: BLOCKHASH as any, lastValidBlockHeight: 10n },
    }))); persist();
    const report = await inspect(); expect(report.actions[0]!.verdict).toBe("unknown");
    expect(reader.getSignatureStatus).toHaveBeenCalledWith(signature);
  });
  test("fully signed original wire identifies its own signature without a journal", async () => {
    event.transactionBase64 = encodeTransaction(signed); order.events[0].transactionBase64 = event.transactionBase64; persist();
    const report = await inspect(); expect(report.actions[0]).toMatchObject({ signature, signatureSource: "signed-wire", verdict: "finalized-succeeded" });
  });
  test.each(["wire", "signature", "messageHash", "payment", "payer", "operation", "blockhash", "expectedHeld", "expectedRefundable"])("mismatched journal %s stays unknown", async field => {
    if (field === "wire") entry.transactionBase64 = encodeTransaction(partial);
    else if (field === "signature") {
      const tx = getTransactionDecoder().decode(getBase64Encoder().encode(entry.transactionBase64));
      entry.transactionBase64 = encodeTransaction({ ...tx, signatures: { ...tx.signatures, [sponsor.address]: new Uint8Array(64).fill(1) as any } });
    } else if (field === "messageHash") entry.messageHash = "0".repeat(64);
    else if (field === "payment") entry.payment = sponsor.address;
    else if (field === "payer") entry.payer = merchant.address;
    else if (field === "operation") entry.operation = "void";
    else if (field === "expectedHeld") entry.expectedHeld = "42";
    else if (field === "expectedRefundable") entry.expectedRefundable = "42";
    else entry.blockhash = sponsor.address;
    persistJournal(); expect((await inspect()).conclusion).toBe("unknown");
  });
  test("conflicting order/lock messages retain both wire hashes", async () => {
    const other = await buildTransaction({ feePayer: sponsor.address, signers: [merchant],
      instructions: [await captureInstruction({ programId: LOCAL_PROGRAM_ID, payment, payer: payer.address, server: merchant.address, mint: NATIVE_MINT }, 40_000_000n, false, 60_000_000n, 0n)],
      lifetime: { blockhash: BLOCKHASH as any, lastValidBlockHeight: 10n } });
    event.transactionBase64 = encodeTransaction(other); persist(); persistJournal();
    const report = await inspect(); expect(report.actions[0]!.wireSha256).toHaveLength(2);
    expect(report.actions[0]!.issues).toContain("order and lock disagree"); expect(report.conclusion).toBe("unknown");
  });
  test("malformed action lock does not erase the order's attempt", async () => {
    persistJournal(); writeFileSync(lockPath, "{");
    const report = await inspect(); expect(report.actions).toHaveLength(1); expect(report.conclusion).toBe("unknown");
  });
  test("malformed journal storage is unavailable, never silently empty", async () => {
    writeFileSync(join(journal, "broken.json"), "{");
    const report = await inspect(); expect(report.issues).toContain("submission journal unavailable or invalid");
  });
  test("missing journal directory is not created", async () => {
    options.journalDirs = [join(root, "missing")]; const report = await inspect(); expect(report.conclusion).toBe("unknown");
    expect(readdirSync(root)).not.toContain("missing");
  });
  test("orphan submission for this payment is explicitly unresolved", async () => {
    order.events = []; writeFileSync(path, JSON.stringify(order)); unlinkSync(lockPath); persistJournal();
    const report = await inspect(); expect(report.issues).toContain("submission journal operation missing from order and locks");
  });
  test("RPC throws and returned diagnostics never leak credentials", async () => {
    persistJournal(); vi.mocked(reader.getSignatureStatus).mockRejectedValue(new Error(PRIVATE));
    vi.mocked(reader.isBlockhashValid).mockResolvedValue({ kind: "unavailable", detail: PRIVATE });
    vi.mocked(reader.getAccountAtLeast).mockRejectedValue(new Error(PRIVATE)); expect((await inspect()).conclusion).toBe("unknown");
  });
  test("history exceptions remain unknown", async () => {
    vi.mocked(reader.findSignaturesByMessage).mockRejectedValue(new Error(PRIVATE)); expect((await inspect()).conclusion).toBe("unknown");
  });
  test("snapshot minContextSlot covers all signature and blockhash observations", async () => {
    persistJournal(); await inspect(); expect(reader.getAccountAtLeast).toHaveBeenCalledWith(payment, 40n);
    vi.mocked(reader.getSignatureStatus).mockResolvedValue({ kind: "not-found" }); await inspect();
    expect(reader.getAccountAtLeast).toHaveBeenLastCalledWith(payment, 41n);
  });
  test.each(["wrong owner", "wrong identity", "stale", "malformed", "absent"])("%s finalized account cannot settle a missing signature", async failure => {
    persistJournal(); vi.mocked(reader.getSignatureStatus).mockResolvedValue({ kind: "not-found" });
    const value = account();
    if (failure === "wrong owner") value.owner = sponsor.address;
    if (failure === "wrong identity") value.data.set(getAddressEncoder().encode(sponsor.address), 40);
    if (failure === "malformed") value.data = new Uint8Array(1);
    vi.mocked(reader.getAccountAtLeast).mockResolvedValue({ kind: "ok", slot: failure === "stale" ? 0n : 42n, account: failure === "absent" ? null : value });
    expect((await inspect()).conclusion).toBe("unknown");
  });
  test("concurrent receipt replacement invalidates definitive local association", async () => {
    persistJournal(); vi.mocked(reader.getSignatureStatus).mockImplementation(async () => {
      order.status = "active"; writeFileSync(path, JSON.stringify(order)); return found();
    });
    const report = await reconcileRestaurantOrder(options);
    expect(report.issues).toContain("local evidence changed during reconciliation"); expect(report.conclusion).toBe("unknown");
  });
  test("BOM-prefixed JSON evidence hashes the exact stored bytes", async () => {
    persistJournal();
    const journalPath = join(journal, signature + ".json");
    for (const file of [path, lockPath, journalPath]) writeFileSync(file, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), readFileSync(file)]));
    const hash = (file: string) => createHash("sha256").update(readFileSync(file)).digest("hex");
    const report = await inspect();
    expect(report.conclusion).toBe("definitive");
    expect(report.order.sha256).toBe(hash(path));
    expect(report.actions[0]!.lockSha256).toBe(hash(lockPath));
    expect(report.actions[0]!.journals[0]!.sha256).toBe(hash(journalPath));
  });
  test.each(["order", "lock", "journal"])("prepending a BOM to %s during RPC invalidates local evidence", async kind => {
    persistJournal();
    expect((await inspect()).conclusion).toBe("definitive");
    const target = kind === "order" ? path : kind === "lock" ? lockPath : join(journal, signature + ".json");
    vi.mocked(reader.getSignatureStatus).mockImplementation(async () => {
      writeFileSync(target, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), readFileSync(target)])); return found();
    });
    const report = await reconcileRestaurantOrder(options);
    expect(report.issues).toContain("local evidence changed during reconciliation");
    expect(report.conclusion).toBe("unknown");
  });
  test("invalid ID cannot traverse paths or call RPC", async () => {
    await expect(reconcileRestaurantOrder({ ...options, orderId: "../" + PRIVATE })).rejects.toThrow("invalid order ID");
    expect(reader.getAccountAtLeast).not.toHaveBeenCalled();
  });
  test("missing order directory is never created", async () => {
    await expect(reconcileRestaurantOrder({ ...options, ordersDir: join(root, "absent") })).rejects.toThrow("restaurant order unavailable or invalid");
    expect(readdirSync(root)).not.toContain("absent");
  });
});

describe("restaurant action identities", () => {
  test.each((["authorize", "salmon", "finish", "void", "refund", "reclaim"] as const).flatMap(a =>
    (["succeeded", "failed", "missing", "conflict"] as const).map(result => ({ a, result }))))("$a with $result preserves three-way diagnosis", async ({ a, result }) => {
    const stored = { programId: LOCAL_PROGRAM_ID, payment, payer: payer.address, server: merchant.address, mint: NATIVE_MINT };
    const amount = a === "salmon" ? 25_000_000n : a === "refund" ? 40_000_000n : 100_000_000n;
    const ix = a === "authorize" ? await authorizeInstruction({ ...stored, funder: sponsor.address, salt, maximum: amount, captureDeadline: 1000n, refundDeadline: 1100n }) :
      a === "salmon" ? await captureInstruction(stored, amount, false, 100_000_000n, 0n) :
      a === "refund" ? await refundInstruction(stored, amount, 60_000_000n, 40_000_000n) :
      a === "reclaim" ? await reclaimInstruction(stored) : await voidInstruction(stored, amount, 0n);
    const economic = a === "authorize" || a === "reclaim" ? payer : merchant;
    partial = await buildTransaction({ feePayer: a === "reclaim" ? payer.address : sponsor.address, signers: [economic], instructions: [ix],
      lifetime: { blockhash: BLOCKHASH as any, lastValidBlockHeight: 10n } });
    signed = a === "reclaim" ? partial : await partiallySignTransaction([sponsor.keyPair], partial);
    if (a === "reclaim") order.reclaimUnsigned = encodeTransaction({ ...partial, signatures: { [payer.address]: null } });
    signature = getSignatureFromTransaction(signed);
    unlinkSync(lockPath); lockPath = path + "." + a + ".lock";
    event = { ...event, action: a, amount: amount.toString(), transactionBase64: encodeTransaction(partial) };
    order.events = [{ ...event }]; persist(); writeFileSync(busyPath, a);
    entry = { ...entry, signature, operation: a === "salmon" ? "capture" : a === "finish" ? "void" : a,
      transactionBase64: encodeTransaction(signed), messageHash: messageHash(partial.messageBytes),
      expectedHeld: a === "authorize" ? "0" : a === "refund" ? "60000000" : "100000000",
      expectedRefundable: a === "refund" ? "40000000" : "0" };
    vi.mocked(reader.getAccountAtLeast).mockResolvedValue({ kind: "ok", slot: 42n,
      account: result === "conflict" ? a === "authorize" ? null : account() :
        a === "salmon" ? account(75_000_000n, 25_000_000n) : a === "refund" ? account(60_000_000n, 0n) :
        a === "authorize" ? account() : account(0n, 0n) });
    if (result === "failed") vi.mocked(reader.getSignatureStatus).mockResolvedValue(found("finalized", PRIVATE));
    if (result === "missing") vi.mocked(reader.getSignatureStatus).mockResolvedValue({ kind: "not-found" });
    if (a === "reclaim") writeFileSync(join(journal, `reclaim-${payment}.lock`), signature);
    persistJournal(); const report = await inspect();
    expect(report.actions[0]).toMatchObject({ action: a, signature,
      verdict: result === "succeeded" ? "finalized-succeeded" : result === "failed" ? "finalized-failed" : "unknown" });
    expect(report.conclusion).toBe(result === "succeeded" || result === "failed" ? "definitive" : "unknown");
    if (a === "reclaim") expect(report.reclaimReservations).toEqual([{ sha256: expect.stringMatching(/^[a-f0-9]{64}$/), signature }]);
  });
  test("unsigned economic consent is unknown even with a successful journal signature claim", async () => {
    const unsigned = { ...partial, signatures: { ...partial.signatures, [merchant.address]: null } };
    event.transactionBase64 = encodeTransaction(unsigned); order.events[0].transactionBase64 = event.transactionBase64; persist(); persistJournal();
    const report = await inspect(); expect(report.conclusion).toBe("unknown"); expect(reader.getSignatureStatus).not.toHaveBeenCalled();
  });
  test("persisted finalized receipt with missing history stays unknown", async () => {
    persistJournal(); order.events[0] = { ...event, status: "finalized", transaction: signature, receipt: { success: true, transaction: signature } }; persist();
    vi.mocked(reader.getSignatureStatus).mockResolvedValue({ kind: "not-found" });
    expect((await inspect()).conclusion).toBe("unknown");
  });
  test("action lock amount cannot relabel a different signed capture", async () => {
    persistJournal(); event.amount = "25000000"; persist(); expect((await inspect()).conclusion).toBe("unknown");
  });
  test.each(["finalized-failed", "not-submitted"] as const)("journal %s cannot override conflicting finalized evidence", async result => {
    entry.attempts[0]!.outcome!.result = result; persistJournal();
    const report = await inspect(); expect(report.actions[0]!.issues).toContain("journal outcome disagrees with finalized evidence");
    expect(report.conclusion).toBe("unknown");
  });
});

describe("definitive reports require consistent finalized evidence", () => {
  test.each(["absent", "unchanged hold", "stale", "unavailable", "throws"])("successful capture with %s payment evidence stays blocked", async kind => {
    persistJournal();
    if (kind === "throws") vi.mocked(reader.getAccountAtLeast).mockRejectedValue(new Error(PRIVATE));
    else vi.mocked(reader.getAccountAtLeast).mockResolvedValue(kind === "unavailable" ? { kind: "unavailable", detail: PRIVATE } :
      { kind: "ok", slot: kind === "stale" ? 39n : 42n, account: kind === "absent" ? null : account() });
    const report = await inspect(); expect(report.conclusion).toBe("unknown");
    if (kind === "absent" || kind === "unchanged hold") expect(report.actions[0]!.verdict).toBe("unknown");
  });
  test("later refund and release do not contradict a proven capture", async () => {
    persistJournal(); vi.mocked(reader.getAccountAtLeast).mockResolvedValue({ kind: "ok", slot: 42n, account: account(0n, 0n) });
    expect((await inspect()).conclusion).toBe("definitive");
  });
  test("repeated reconciliation reports identical evidence and preserves every reservation", async () => {
    persistJournal(); const first = await inspect(); expect(await inspect()).toEqual(first); expect(await inspect()).toEqual(first);
  });
  test("earlier contradictory journal attempts cannot be hidden by a later unresolved attempt", async () => {
    entry.attempts.unshift({ preparedAt: "synthetic", outcome: { result: "finalized-failed", recordedAt: "synthetic" } });
    persistJournal(); expect((await inspect()).conclusion).toBe("unknown");
  });
  test("a successful-looking receipt with a rejected status stays unknown", async () => {
    persistJournal(); order.events[0] = { ...event, status: "rejected", transaction: signature, receipt: { success: true, transaction: signature } }; persist();
    expect((await inspect()).conclusion).toBe("unknown");
  });
  test("fully signed transaction with trailing message bytes is not authenticated restaurant evidence", async () => {
    const bytes = new Uint8Array([...partial.messageBytes, 0]);
    const changed = await partiallySignTransaction([merchant.keyPair, sponsor.keyPair], { ...partial, messageBytes: bytes as any });
    event.transactionBase64 = encodeTransaction(changed); order.events[0].transactionBase64 = event.transactionBase64; persist();
    expect((await inspect()).conclusion).toBe("unknown"); expect(reader.getSignatureStatus).not.toHaveBeenCalled();
  });
  test("extra spending instructions cannot be called a restaurant action", async () => {
    const changed = await buildTransaction({ feePayer: sponsor.address, signers: [merchant, sponsor],
      instructions: [await captureInstruction({ programId: LOCAL_PROGRAM_ID, payment, payer: payer.address, server: merchant.address, mint: NATIVE_MINT },
        40_000_000n, false, 100_000_000n, 0n), { programAddress: NATIVE_MINT, data: new Uint8Array([1]) }],
      lifetime: { blockhash: BLOCKHASH as any, lastValidBlockHeight: 10n } });
    event.transactionBase64 = encodeTransaction(changed); order.events[0].transactionBase64 = event.transactionBase64; persist();
    expect((await inspect()).conclusion).toBe("unknown"); expect(reader.getSignatureStatus).not.toHaveBeenCalled();
  });
  test("changing the authorization lifetime cannot substitute consent to the offered message", async () => {
    const changed = await buildTransaction({ feePayer: sponsor.address, signers: [payer, sponsor],
      instructions: [await authorizeInstruction({ programId: LOCAL_PROGRAM_ID, payer: payer.address, server: merchant.address,
        mint: NATIVE_MINT, funder: sponsor.address, salt, maximum: 100_000_000n, captureDeadline: 1000n, refundDeadline: 1100n })],
      lifetime: { blockhash: sponsor.address as any, lastValidBlockHeight: 10n } });
    unlinkSync(lockPath); lockPath = path + ".authorize.lock";
    event = { ...event, action: "authorize", amount: "100000000", transactionBase64: encodeTransaction(changed) };
    order.events = [{ ...event }]; persist(); writeFileSync(busyPath, "authorize");
    expect((await inspect()).conclusion).toBe("unknown"); expect(reader.getSignatureStatus).not.toHaveBeenCalled();
  });
  test("real RestaurantOrders reservation and preparation use the same read-only schema", async () => {
    unlinkSync(path); unlinkSync(lockPath); unlinkSync(busyPath);
    const store = new RestaurantOrders(orders); order.status = "active"; order.events = [];
    store.create(order); store.reserve(ID, "beer"); store.prepare(order, event); persistJournal();
    const report = await inspect(); expect(report.conclusion).toBe("definitive");
    expect(report.actions[0]!.sources).toEqual(["order", "action-lock"]); expect(store.busy(ID)).toBe(true);
  });
  test.each(["valid", "duplicate", "wrong accounts"])("%s compute instructions obey the historical wire allowlist", async mode => {
    const compute = demoComputeInstructions(20_000);
    if (mode === "duplicate") compute.push(compute[0]!);
    if (mode === "wrong accounts") compute[0] = { ...compute[0]!, accounts: [{ address: payer.address, role: 0 }] };
    const changed = await buildTransaction({ feePayer: sponsor.address, signers: [merchant, sponsor], instructions: [...compute,
      await captureInstruction({ programId: LOCAL_PROGRAM_ID, payment, payer: payer.address, server: merchant.address, mint: NATIVE_MINT },
        40_000_000n, false, 100_000_000n, 0n)], lifetime: { blockhash: BLOCKHASH as any, lastValidBlockHeight: 10n } });
    event.transactionBase64 = encodeTransaction(changed); order.events[0].transactionBase64 = event.transactionBase64; persist();
    expect((await inspect()).conclusion).toBe(mode === "valid" ? "definitive" : "unknown");
  });
  test("signed capture with a substituted destination is not an original restaurant operation", async () => {
    const ix = await captureInstruction({ programId: LOCAL_PROGRAM_ID, payment, payer: payer.address, server: merchant.address, mint: NATIVE_MINT },
      40_000_000n, false, 100_000_000n, 0n);
    const changed = await buildTransaction({ feePayer: sponsor.address, signers: [merchant, sponsor],
      instructions: [{ ...ix, accounts: ix.accounts!.map((a, i) => i === 4 ? { ...a, address: payment } : a) }],
      lifetime: { blockhash: BLOCKHASH as any, lastValidBlockHeight: 10n } });
    event.transactionBase64 = encodeTransaction(changed); order.events[0].transactionBase64 = event.transactionBase64; persist();
    expect((await inspect()).conclusion).toBe("unknown"); expect(reader.getSignatureStatus).not.toHaveBeenCalled();
  });
  test.each(["order", "lock", "journal"])("symlinked %s evidence is refused", async kind => {
    const replacement = join(root, "replacement.json");
    const target = kind === "order" ? path : kind === "lock" ? lockPath : join(journal, signature + ".json");
    if (kind === "journal") persistJournal();
    writeFileSync(replacement, readFileSync(target)); unlinkSync(target); symlinkSync(replacement, target);
    if (kind === "journal") expect((await reconcileRestaurantOrder(options)).conclusion).toBe("unknown");
    else await expect(reconcileRestaurantOrder(options)).rejects.toThrow("restaurant order unavailable or invalid");
    expect(reader.getSignatureStatus).not.toHaveBeenCalled();
  });
  test("journal replacement during RPC invalidates local evidence", async () => {
    persistJournal(); vi.mocked(reader.getSignatureStatus).mockImplementation(async () => {
      entry.attempts[0]!.outcome = { result: "finalized-failed", recordedAt: "synthetic" }; persistJournal(); return found();
    });
    const report = await reconcileRestaurantOrder(options); expect(report.conclusion).toBe("unknown");
    expect(report.issues).toContain("local evidence changed during reconciliation");
  });
  test.each(["orphan", "corrupt", "cycle"])("%s payer-reclaim reservation blocks a definitive order report", async mode => {
    persistJournal();
    const file = join(journal, `reclaim-${payment}.lock`);
    writeFileSync(file, mode === "corrupt" ? PRIVATE : signature);
    if (mode === "cycle") writeFileSync(join(journal, `reclaim-${payment}-after-${signature}.lock`), signature);
    const report = await inspect(); expect(report.conclusion).toBe("unknown");
    expect(report.issues.some(i => i.startsWith("reclaim reservation"))).toBe(true);
  });
  test.each(["missing", "wrong signature", "other directory", "missing successor", "valid successor", "invalid predecessor"])("reclaim journals require their own reservations: %s", async mode => {
    const ix = await reclaimInstruction({ programId: LOCAL_PROGRAM_ID, payment, payer: payer.address, server: merchant.address, mint: NATIVE_MINT });
    const original = await buildTransaction({ feePayer: payer.address, signers: [payer], instructions: [ix],
      lifetime: { blockhash: BLOCKHASH as any, lastValidBlockHeight: 10n } });
    const otherSignature = signature;
    signature = getSignatureFromTransaction(original);
    order.reclaimUnsigned = encodeTransaction({ ...original, signatures: { [payer.address]: null } });
    unlinkSync(lockPath); lockPath = path + ".reclaim.lock";
    event = { ...event, action: "reclaim", amount: "100000000", transactionBase64: encodeTransaction(original) };
    order.events = [{ ...event }]; persist(); writeFileSync(busyPath, "reclaim");
    entry = { ...entry, signature, operation: "reclaim", transactionBase64: encodeTransaction(original), messageHash: messageHash(original.messageBytes) };
    persistJournal();
    const reservationPath = join(journal, `reclaim-${payment}.lock`);
    writeFileSync(reservationPath, signature);
    vi.mocked(reader.getAccountAtLeast).mockResolvedValue({ kind: "ok", slot: 42n, account: account(0n, 0n) });
    expect((await inspect()).conclusion).toBe("definitive");
    if (mode === "wrong signature") writeFileSync(reservationPath, otherSignature);
    else if (mode === "missing" || mode === "other directory") {
      unlinkSync(reservationPath);
      if (mode === "other directory") {
        const other = join(root, "other-journal"); mkdirSync(other);
        writeFileSync(join(other, `reclaim-${payment}.lock`), signature); options.journalDirs = [journal, other];
      }
    } else if (mode === "invalid predecessor") {
      entry.retryAfter = PRIVATE; persistJournal();
    } else {
      entry.attempts[0]!.outcome!.result = "finalized-failed"; persistJournal();
      vi.mocked(reader.getSignatureStatus).mockResolvedValue(found("finalized", PRIVATE));
      const successor = await buildTransaction({ feePayer: payer.address, signers: [payer], instructions: [ix],
        lifetime: { blockhash: sponsor.address as any, lastValidBlockHeight: 20n } });
      const successorSignature = getSignatureFromTransaction(successor);
      writeFileSync(join(journal, successorSignature + ".json"), JSON.stringify({ ...entry,
        signature: successorSignature, retryAfter: signature, blockhash: sponsor.address,
        transactionBase64: encodeTransaction(successor), messageHash: messageHash(successor.messageBytes), attempts: [{ preparedAt: "synthetic" }] }));
      if (mode === "valid successor") writeFileSync(join(journal, `reclaim-${payment}-after-${signature}.lock`), successorSignature);
    }
    const report = await inspect();
    expect(report.conclusion).toBe("unknown");
    if (mode === "invalid predecessor") expect(report.issues).toContain("reclaim reservation predecessor invalid");
    else if (mode === "valid successor") {
      expect(report.issues.some(i => i.includes("reservation"))).toBe(false);
      expect(report.reclaimReservations).toHaveLength(2);
    } else expect(report.issues).toContain("reclaim submission journal lacks matching reservation");
    if (mode === "other directory") expect(report.issues).toContain("reclaim reservation lacks matching submission journal");
  });
});
