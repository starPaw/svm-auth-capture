// Explicit local CAPTURE result application. No economic or fulfillment capability is imported.
import { constants, closeSync, fsyncSync, lstatSync, openSync, unlinkSync } from "node:fs";
import { performance } from "node:perf_hooks";
import { join } from "node:path";
import type { ChainReader, SignatureLookup, SlotAccount } from "./reconciliation.ts";
import { reconcileRestaurantOrder, type RestaurantReconcileReport } from "./restaurant-reconciliation.ts";
import { createDurableFile } from "./durable-file.ts";
import { inode, replaceRecoveryOrder, verifyStagedOrder } from "./recovery-order.ts";
import { createRecoveryRecord } from "./recovery-record.ts";
import type { RecoveryDomain } from "./coordination.ts";
import { verifyRecoveryEnrollment, type RecoveryEnrollment, type RecoveryIdentity } from "./recovery-enrollment.ts";
import { recoveryHash, recoverySnapshot, sameRecoveryPins, readRecoveryRecord, type FilePin, type RecoverySnapshot } from "./recovery-snapshot.ts";
export type OutcomeReader = ChainReader & { verifyIdentity(deadline: number): Promise<RecoveryIdentity> };
export type OutcomeApplyOptions = { domain: RecoveryDomain; enrollment?: RecoveryEnrollment; identity: RecoveryIdentity;
  orderId: string; action: "beer" | "salmon"; signature: string; evidenceDigest: string; reader: OutcomeReader; timeoutMs?: number };
type RecordV1 = { applicationId: string; stageIdentity: string; recordIdentity?: string; version: 1; identity: RecoveryIdentity; orderId: string; action: string; signature: string; messageHash: string;
  evidenceDigest: string; pins: FilePin[]; preimage: string; originalEvent: unknown; originals: { name: string; base64: string }[];
  report: RestaurantReconcileReport; statuses: { signature: string; slot: string; observedSlot: string; err: string | null }[];
  payment: { slot: string; owner: string; executable: boolean; dataBase64: string }; intendedOrder: string };
function refuse(): never { throw new Error("outcome application refused: missing, conflicting, stale or changed proof"); }
const memberPath = (domain: RecoveryDomain, role: string) => domain.metadata.members.find(m => m.role === role)!.path;
function key(o: Pick<OutcomeApplyOptions,"identity"|"orderId"|"action"|"signature">) {
  return recoveryHash(JSON.stringify([o.identity.network,o.identity.genesisHash,o.identity.programId,o.orderId,o.action,o.signature]));
}
function recordName(o: Pick<OutcomeApplyOptions,"identity"|"orderId"|"action"|"signature">) { return `${o.orderId}.outcome-${key(o)}.record`; }
function sync(path: string, directory = false) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | (directory ? constants.O_DIRECTORY : 0));
  try { fsyncSync(fd); } finally { closeSync(fd); }
}
function canonicalJson(raw: string): any { const value = JSON.parse(raw); if (JSON.stringify(value) !== raw) refuse(); return value; }
function pinsWithout(pins: FilePin[], names: string[]) { return pins.filter(p => !names.includes(`${p.role}/${p.name}`)); }
function postimage(record: RecordV1, digest: string) {
  const order = canonicalJson(record.intendedOrder);
  const event = order.events.find((e: any) => e.action === record.action); if (!event) refuse();
  event.applicationRecordSha256 = digest;
  return JSON.stringify(order);
}
function state(snapshot: RecoverySnapshot, record: RecordV1, digest: string): "pre" | "post" {
  const orderName = `orders/${record.orderId}.json`, busyName = `${orderName}.busy`;
  const raw = snapshot.bytes.get(orderName)?.toString("utf8");
  // All original permanent files and the complete domain membership remain pinned.
  sameRecoveryPins(pinsWithout(record.pins,[orderName,busyName]),pinsWithout(snapshot.pins,[orderName,busyName]));
  if (raw === record.preimage) {
    sameRecoveryPins(record.pins,snapshot.pins); return "pre";
  }
  if (raw !== postimage(record,digest) || snapshot.pins.find(p => `${p.role}/${p.name}` === orderName)?.identity.split(":").slice(0,2).join(":") !== record.stageIdentity) refuse();
  const busy = snapshot.pins.filter(p => `orders/${p.name}` === busyName);
  if (busy.length) sameRecoveryPins(record.pins.filter(p => `orders/${p.name}` === busyName),busy);
  return "post";
}
function intended(preimage: string, report: RestaurantReconcileReport, action: string, signature: string, lock: Buffer): string {
  const order = canonicalJson(preimage);
  if (order.events.some((e: any) => e.applicationRecordSha256)) refuse();
  const evidence = report.actions.find(a => a.action === action)!;
  const original = order.events.find((e: any) => e.action === action) ?? canonicalJson(lock.toString("utf8"));
  if (!order.events.includes(original)) order.events.push(original);
  // Every OTHER relevant event must already carry its authenticated known local result. One
  // operation never silently records the outcomes of another action or adds another delivery.
  for (const a of report.actions.filter(a => a.action !== action)) {
    const e = order.events.find((e: any) => e.action === a.action);
    if (!e || e.status !== (a.verdict === "finalized-succeeded" ? "finalized" : "rejected") || e.transaction !== a.signature) refuse();
  }
  original.transaction = signature;
  original.status = evidence.verdict === "finalized-succeeded" ? "finalized" : "rejected";
  original.receipt = { success: original.status === "finalized", transaction: signature, network: reportIdentityNetwork(order) };
  order.status = order.events.some((e: any) => e.action === "authorize" && e.status === "rejected") ? "rejected" :
    report.payment.kind === "ok" && report.payment.exists && report.payment.held === "0" ? "closed" : "active";
  return JSON.stringify(order);
}
function reportIdentityNetwork(order: any): string { return order.required.accepts[0].network; }
/** Read-only digest for review, under the same admission/fence. This digest is NOT authority. */
export async function restaurantOutcomeEvidence(options: Omit<OutcomeApplyOptions,"evidenceDigest"|"reader">): Promise<string> {
  return options.domain.run("exclusive",async token => {
    verifyRecoveryEnrollment(options.enrollment,token,options.identity);
    return recoveryHash(JSON.stringify(recoverySnapshot(options.domain,recordName(options)).pins));
  });
}
/** One deadline begins before lock acquisition and includes verification, RPC and every write.
 * A timed-out RPC's late completion cannot reach persistence. No startup path imports this. */
export async function applyRestaurantOutcome(o: OutcomeApplyOptions): Promise<{ result: "applied" | "completed" | "already-applied"; recordSha256: string }> {
  if (!/^[a-f0-9]{32}$/.test(o.orderId) || !["beer","salmon"].includes(o.action) || !/^[1-9A-HJ-NP-Za-km-z]{64,88}$/.test(o.signature) || !/^[a-f0-9]{64}$/.test(o.evidenceDigest)) refuse();
  const timeout = o.timeoutMs ?? 10_000; if (!Number.isFinite(timeout) || timeout <= 0 || timeout > 60_000) refuse();
  const deadline = Date.now() + timeout, monotonicDeadline = performance.now() + timeout;
  const checkDeadline = () => { if (Date.now() >= deadline || performance.now() >= monotonicDeadline) refuse(); };
  async function bounded<T>(action: () => Promise<T>): Promise<T> {
    checkDeadline(); let timer: ReturnType<typeof setTimeout> | undefined;
    try { return await Promise.race([action(),new Promise<never>((_,reject) => { timer = setTimeout(() => reject(new Error("outcome application deadline exceeded")),Math.max(1,Math.min(deadline-Date.now(),monotonicDeadline-performance.now()))); })]); }
    finally { if (timer) clearTimeout(timer); }
  }
  return o.domain.run("exclusive",async token => {
    const guard = () => { checkDeadline(); verifyRecoveryEnrollment(o.enrollment,token,o.identity); };
    guard();
    if (JSON.stringify(await bounded(() => o.reader.verifyIdentity(deadline))) !== JSON.stringify(o.identity)) refuse();
    guard();
    const path = join(memberPath(o.domain,"orders"),`${o.orderId}.json`), name = recordName(o), recordPath = join(memberPath(o.domain,"orders"),name);
    const stagePath = recordPath.replace(/\.record$/, ".order");
    let snapshot = recoverySnapshot(o.domain,name), record: RecordV1 | undefined, recordRaw: string | undefined;
    try { lstatSync(recordPath); recordRaw = readRecoveryRecord(recordPath); record = canonicalJson(recordRaw);
      if (Object.keys(record!).sort().join() !== ["version","identity","orderId","action","signature","messageHash","evidenceDigest","pins","preimage","originalEvent","originals","report","statuses","payment","intendedOrder","recordIdentity","stageIdentity","applicationId"].sort().join()) refuse();
    }
    catch (e) { if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e; }
    if (!record) { try { lstatSync(stagePath); refuse(); } catch(e) { if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e; } }
    if (snapshot.pins.some(p => p.role === "orders" && p.name.startsWith(`${o.orderId}.outcome-`))) refuse();
    const preimage = record?.preimage ?? snapshot.bytes.get(`orders/${o.orderId}.json`)?.toString("utf8"); if (!preimage) refuse();
    if (record) {
      if (record.version !== 1 || JSON.stringify(record.identity) !== JSON.stringify(o.identity) || record.orderId !== o.orderId || record.action !== o.action || record.signature !== o.signature || record.evidenceDigest !== o.evidenceDigest || recoveryHash(JSON.stringify(record.pins)) !== o.evidenceDigest) refuse();
      if (recoveryHash(record.preimage) !== record.pins.find(p => p.role === "orders" && p.name === `${o.orderId}.json`)?.sha256) refuse();
      for (const original of record.originals) if (recoveryHash(Buffer.from(original.base64,"base64")) !== record.pins.find(p => `${p.role}/${p.name}` === original.name)?.sha256) refuse();
      state(snapshot,record,recoveryHash(recordRaw!));
    } else if (recoveryHash(JSON.stringify(snapshot.pins)) !== o.evidenceDigest || snapshot.bytes.get(`orders/${o.orderId}.json.busy`)?.toString("utf8") !== o.action) refuse();
    // Operations touching the same payment would be another application state machine; refuse.
    const order = canonicalJson(preimage);
    for (const [name,raw] of snapshot.bytes) if (name.startsWith("operations/")) {
      const operation = JSON.parse(raw.toString("utf8"));
      if (JSON.stringify(operation).includes(order.payment)) refuse();
    }
    const statuses = new Map<string,SignatureLookup>(); let paymentRead: SlotAccount | undefined;
    const reader: ChainReader = {
      getSignatureStatus: async signature => { const s = await bounded(() => o.reader.getSignatureStatus(signature)); if (s.kind !== "found" || typeof s.observedSlot !== "bigint" || s.observedSlot < s.slot || s.observedSlot < 0n || s.observedSlot > 0xffffffffffffffffn) refuse(); statuses.set(signature,s); return s; },
      findSignaturesByMessage: (address,bytes) => bounded(() => o.reader.findSignaturesByMessage(address,bytes)),
      isBlockhashValid: hash => bounded(() => o.reader.isBlockhashValid(hash)),
      getAccountAtLeast: async (address,slot) => { const observationFence = [...statuses.values()].reduce((maximum,s) => s.kind === "found" && s.observedSlot! > maximum ? s.observedSlot! : maximum,slot);
        paymentRead = await bounded(() => o.reader.getAccountAtLeast(address,observationFence));
        if (paymentRead.kind !== "ok" || paymentRead.slot < observationFence) refuse(); return paymentRead; },
    };
    const report = await bounded(() => reconcileRestaurantOrder({ ordersDir: memberPath(o.domain,"orders"), orderId:o.orderId,
      ...o.identity, reader, journalDirs:[memberPath(o.domain,"facilitator"),memberPath(o.domain,"reclaim")], recoveryPreimage:Buffer.from(preimage),allowLockOnly:true }));
    guard();
    if (report.conclusion !== "definitive" || report.actions.some(a => a.journals.length !== 1) || !report.actions.some(a => a.action === "authorize" && a.verdict === "finalized-succeeded") ||
        report.actions.find(a => a.action === o.action)?.signature !== o.signature || !paymentRead || paymentRead.kind !== "ok" || !paymentRead.account) refuse();
    const target = report.actions.find(a => a.action === o.action)!;
    const applicationId = recoveryHash(JSON.stringify([o.identity.network,o.identity.genesisHash,o.identity.programId,order.payment,o.orderId,o.action,o.signature,target.messageHash]));
    const freshStatuses = [...statuses].map(([signature,s]) => { if (s.kind !== "found" || s.commitment !== "finalized" || s.slot < 0n) refuse(); return { signature,slot:s.slot.toString(),observedSlot:s.observedSlot!.toString(),err:s.err }; });
    const account = paymentRead.account;
    const freshPayment = { slot:paymentRead.slot.toString(),owner:account.owner,executable:account.executable,dataBase64:Buffer.from(account.data).toString("base64") };
    const lock = snapshot.bytes.get(`orders/${o.orderId}.json.${o.action}.lock`); if (!lock) refuse();
    const intendedOrder = intended(preimage,report,o.action,o.signature,lock);
    if (record) {
      if (record.applicationId !== applicationId || record.messageHash !== target.messageHash || record.intendedOrder !== intendedOrder || JSON.stringify(record.originalEvent) !== JSON.stringify(order.events.find((e:any)=>e.action===o.action) ?? canonicalJson(lock.toString("utf8"))) ||
          record.statuses.length !== freshStatuses.length || record.statuses.some((s,i) => { const fresh = freshStatuses[i]!; return s.signature !== fresh.signature || s.slot !== fresh.slot || s.err !== fresh.err || BigInt(s.observedSlot) > BigInt(fresh.observedSlot); }) || BigInt(freshPayment.slot) < BigInt(record.payment.slot)) refuse();
      for (const original of record.originals) if (snapshot.bytes.get(original.name)?.toString("base64") !== original.base64 && original.name !== `orders/${o.orderId}.json` && original.name !== `orders/${o.orderId}.json.busy`) refuse();
    } else {
      guard(); sameRecoveryPins(snapshot.pins,recoverySnapshot(o.domain,name).pins);
      createDurableFile(stagePath,"");
      record = { applicationId,stageIdentity:inode(stagePath),version:1,identity:o.identity,orderId:o.orderId,action:o.action,signature:o.signature,messageHash:target.messageHash!,evidenceDigest:o.evidenceDigest,pins:snapshot.pins,preimage,
        originalEvent:order.events.find((e:any)=>e.action===o.action) ?? canonicalJson(lock.toString("utf8")),
        originals:[...snapshot.bytes].filter(([name]) => name.startsWith(`orders/${o.orderId}.json`) || report.actions.some(a => a.journals.some(j => name.endsWith(`/${j.signature}.json`))) || name.includes(`reclaim-${order.payment}`)).map(([name,raw]) => ({ name,base64:raw.toString("base64") })),
        report,statuses:freshStatuses,payment:freshPayment,intendedOrder };
      recordRaw = JSON.stringify(record);
    }
    if (Buffer.byteLength(recordRaw!) > 8 * 1048576 || Buffer.byteLength(postimage(record,recoveryHash(recordRaw!))) > 1048576) refuse();
    let digest = recoveryHash(recordRaw!);
    const unchanged = () => { guard(); sameRecoveryPins(snapshot.pins,recoverySnapshot(o.domain,name).pins); if (readRecoveryRecord(recordPath) !== recordRaw) refuse(); };
    // Create exclusively and flush before replacement; an incomplete record blocks repetition.
    if (!recordRaw || !record) refuse();
    const existed = (() => { try { lstatSync(recordPath); return true; } catch(e) { if ((e as NodeJS.ErrnoException).code === "ENOENT") return false; throw e; } })();
    if (!existed) { guard(); sameRecoveryPins(snapshot.pins,recoverySnapshot(o.domain,name).pins); recordRaw = createRecoveryRecord(recordPath,record); record = canonicalJson(recordRaw); digest = recoveryHash(recordRaw); }
    if (!record) refuse();
    unchanged(); sync(recordPath); sync(memberPath(o.domain,"orders"),true); unchanged();
    const previousState = state(snapshot,record,digest);
    if (previousState === "pre") {
      unchanged(); verifyStagedOrder(stagePath,record.stageIdentity,postimage(record,digest));
      replaceRecoveryOrder(stagePath,path,record.stageIdentity,postimage(record,digest));
      snapshot = recoverySnapshot(o.domain,name); if (state(snapshot,record,digest) !== "post") refuse();
    }
    if (previousState === "post") { try { lstatSync(stagePath); refuse(); } catch(e) { if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e; } }
    // Flush also when repeating a rename whose directory fsync previously failed.
    unchanged(); sync(path); sync(memberPath(o.domain,"orders"),true); unchanged();
    const busyName = `orders/${o.orderId}.json.busy`, busy = snapshot.bytes.has(busyName);
    if (busy) { unchanged(); if (state(snapshot,record,digest) !== "post") refuse(); unlinkSync(`${path}.busy`); }
    // A repeated post-state with absent busy still completes an uncertain directory flush.
    sync(memberPath(o.domain,"orders"),true);
    guard(); const finalSnapshot = recoverySnapshot(o.domain,name);
    if (state(finalSnapshot,record,digest) !== "post" || finalSnapshot.bytes.has(busyName) || readRecoveryRecord(recordPath) !== recordRaw) refuse();
    return { result:!existed ? "applied" : previousState === "pre" || busy ? "completed" : "already-applied",recordSha256:digest };
  },Math.min(60_000,Math.max(1,Math.min(deadline-Date.now(),monotonicDeadline-performance.now()))));
}
