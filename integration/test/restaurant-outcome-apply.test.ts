import { afterEach, expect, test, vi } from "vitest";
import { chmodSync, existsSync, lstatSync, readFileSync, readdirSync, renameSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { outcomeFixture } from "./fixtures/outcome-fixture.ts";
import { applyRestaurantOutcome, restaurantOutcomeEvidence } from "../src/restaurant-outcome-apply.ts";
import { restaurantOutcomeMain } from "../src/restaurant-outcome.ts";
const roots:string[] = [];
afterEach(() => { vi.restoreAllMocks(); for(const root of roots.splice(0)) rmSync(root,{ recursive:true,force:true }); });
async function fixture(failure=false,lockOnly=false) { const f = await outcomeFixture(failure,lockOnly);roots.push(f.root);return f; }
function originals(f:Awaited<ReturnType<typeof fixture>>) { return [f.paths.facilitator,f.paths.reclaim].flatMap(dir => readdirSync(dir).map(name => [name,readFileSync(join(dir,name)).toString("base64"),lstatSync(join(dir,name)).ino])); }
test.each([false,true])("original finalized capture applied exactly once; failure=%s",async failure => {
  const f = await fixture(failure),before = originals(f),lock = readFileSync(f.lockPath);
  expect((await f.apply()).result).toBe("applied"); const orderBytes = readFileSync(f.path);
  expect((await f.apply()).result).toBe("already-applied");expect(readFileSync(f.path)).toEqual(orderBytes);
  const order = JSON.parse(orderBytes.toString());expect(order.events).toHaveLength(2);expect(order.events[1]).toMatchObject({ transaction:f.signature,status:failure ? "rejected" : "finalized" });
  expect(order.status).toBe("active");expect(existsSync(f.busyPath)).toBe(false);expect(readFileSync(f.lockPath)).toEqual(lock);expect(originals(f)).toEqual(before);
  const recordName = readdirSync(f.paths.orders).find(n=>n.endsWith(".record"))!;
  const record = JSON.parse(readFileSync(join(f.paths.orders,recordName),"utf8"));expect(record.preimage).toContain('"status":"pending"');expect(record.statuses).toHaveLength(2);
  expect(lstatSync(join(f.paths.orders,recordName)).mode & 0o777).toBe(0o400);
});
test("reconstructs only authenticated lock-only capture once",async () => { const f = await fixture(false,true);await f.apply();await f.apply();expect(JSON.parse(readFileSync(f.path,"utf8")).events).toHaveLength(2); });
test.each(["unknown","unavailable","processed","confirmed","conflict","stale","missing-account","timeout","bad-genesis"])("refuses %s without outcome change/unlock",async mode => {
  const f = await fixture(),pre = readFileSync(f.path),before = originals(f);
  if(mode === "unknown") f.reader.getSignatureStatus = async () => ({ kind:"not-found" });
  if(mode === "unavailable") f.reader.getSignatureStatus = async () => ({ kind:"unavailable",detail:"private-url" });
  if(mode === "processed" || mode === "confirmed") f.reader.getSignatureStatus = async () => ({ kind:"found",slot:40n,commitment:mode,err:null });
  if(mode === "conflict") { const p=join(f.paths.facilitator,f.signature+".json"),e=JSON.parse(readFileSync(p,"utf8"));e.attempts[0].outcome.result="finalized-failed";f.persist(p,e);f.options.evidenceDigest=await restaurantOutcomeEvidence(f.options); }
  if(mode === "stale") f.reader.getAccountAtLeast = async () => ({ kind:"ok",slot:39n,account:f.account });
  if(mode === "missing-account") f.reader.getAccountAtLeast = async () => ({ kind:"ok",slot:42n,account:null });
  if(mode === "timeout") { f.options.timeoutMs=50;f.reader.getSignatureStatus = async () => new Promise(()=>{}); }
  if(mode === "bad-genesis") f.reader.verifyIdentity = async () => ({ ...f.identity,genesisHash:f.order.payer });
  const changedOriginals = originals(f);
  await expect(f.apply()).rejects.toThrow();expect(readFileSync(f.path)).toEqual(pre);expect(existsSync(f.busyPath)).toBe(true);expect(originals(f)).toEqual(changedOriginals);if(mode !== "conflict") expect(originals(f)).toEqual(before);
  expect(readdirSync(f.paths.orders).some(n=>n.endsWith(".record"))).toBe(false);
});
test.each(["inode","bytes","missing-lock","missing-busy","unexpected-file","journal-orphan"])("refuses substituted/incomplete evidence: %s",async mode => {
  const f=await fixture(),pre=readFileSync(f.path);
  if(mode === "inode") { renameSync(f.lockPath,join(f.root,"old-lock"));f.persist(f.lockPath,readFileSync(join(f.root,"old-lock"),"utf8")); }
  if(mode === "bytes") writeFileSync(f.lockPath,"{}");
  if(mode === "missing-lock") unlinkSync(f.lockPath);
  if(mode === "missing-busy") unlinkSync(f.busyPath);
  if(mode === "unexpected-file") f.persist(join(f.paths.reclaim,"hidden-writer"),"opaque");
  if(mode === "journal-orphan") { f.persist(join(f.paths.reclaim,`reclaim-${f.order.payment}.lock`),f.signature);f.options.evidenceDigest=await restaurantOutcomeEvidence(f.options); }
  await expect(f.apply()).rejects.toThrow();expect(readFileSync(f.path)).toEqual(pre);expect(existsSync(f.busyPath)).toBe(mode !== "missing-busy");
});
test("rechecks identities after RPC before recording",async () => {
  const f=await fixture(),pre=readFileSync(f.path),get=f.reader.getAccountAtLeast;
  f.reader.getAccountAtLeast=async (...args) => { const r=await get(...args);renameSync(f.lockPath,join(f.root,"old"));f.persist(f.lockPath,readFileSync(join(f.root,"old"),"utf8"));return r; };
  await expect(f.apply()).rejects.toThrow();expect(readFileSync(f.path)).toEqual(pre);expect(existsSync(f.busyPath)).toBe(true);
});
test("caller true, forged capability, wrong UID/domain/network never supply enrollment",async () => {
  const f=await fixture(),other=await fixture(),pre=readFileSync(f.path);
  for(const enrollment of [undefined,true,async()=>true,{ profile:"isolated-one-uid-fixture" },other.enrollment]) await expect(applyRestaurantOutcome({ ...f.options,enrollment:enrollment as never })).rejects.toThrow();
  const uid=process.getuid!;vi.spyOn(process,"getuid").mockImplementation(()=>uid()+1);await expect(f.apply()).rejects.toThrow();vi.restoreAllMocks();
  await expect(applyRestaurantOutcome({ ...f.options,identity:{ ...f.identity,network:"solana:live" } })).rejects.toThrow();
  expect(readFileSync(f.path)).toEqual(pre);expect(existsSync(f.busyPath)).toBe(true);
});
test("explicit CLI refuses unavailable live verifier without touching stores",async () => { const f=await fixture();await expect(restaurantOutcomeMain(["apply",f.id,"beer",f.signature,f.options.evidenceDigest])).rejects.toThrow(/no trusted live enrollment/);expect(existsSync(f.busyPath)).toBe(true); });
test.each(["inode","preimage","intended","outcome","original-bytes"])("repeat refuses tampered record %s and retains evidence",async mode => {
  const f=await fixture();await f.apply();const p=join(f.paths.orders,readdirSync(f.paths.orders).find(n=>n.endsWith(".record"))!),raw=readFileSync(p,"utf8"),order=readFileSync(f.path);
  if(mode === "inode") { renameSync(p,join(f.root,"old-record"));writeFileSync(p,raw,{ mode:0o400 }); }
  else { chmodSync(p,0o600);const r=JSON.parse(raw);if(mode === "preimage") r.preimage=r.preimage.replace("synthetic-only","changed");if(mode === "intended") r.intendedOrder="{}";if(mode === "outcome") r.statuses[1].err="fake";if(mode === "original-bytes") r.originals[0].base64="e30=";writeFileSync(p,JSON.stringify(r));chmodSync(p,0o400); }
  await expect(f.apply()).rejects.toThrow();expect(readFileSync(f.path)).toEqual(order);expect(existsSync(p)).toBe(true);expect(existsSync(f.lockPath)).toBe(true);
});

test.each(["wire-signature","lock-message","journal-message","missing-journal","missing-action-lock","unknown-other-action","incomplete-enrollment","missing-observation","stale-observation"])("authenticated admission refuses %s even with recomputed metadata digest",async mode=>{
  const f=await fixture(),pre=readFileSync(f.path);
  if(mode === "wire-signature") { const p=join(f.paths.facilitator,f.signature+".json"),e=JSON.parse(readFileSync(p,"utf8")),raw=Buffer.from(e.transactionBase64,"base64");raw[1]=raw[1]! ^ 1;e.transactionBase64=raw.toString("base64");f.persist(p,e); }
  if(mode === "lock-message") { const e=JSON.parse(readFileSync(f.lockPath,"utf8"));e.transactionBase64=f.order.unsigned;f.persist(f.lockPath,e); }
  if(mode === "journal-message") { const p=join(f.paths.facilitator,f.signature+".json"),e=JSON.parse(readFileSync(p,"utf8"));e.messageHash="0".repeat(64);f.persist(p,e); }
  if(mode === "missing-journal") unlinkSync(join(f.paths.facilitator,f.signature+".json"));
  if(mode === "missing-action-lock") unlinkSync(f.lockPath);
  if(mode === "unknown-other-action") { const get=f.reader.getSignatureStatus;f.reader.getSignatureStatus=async s=>s===f.authSignature ? { kind:"not-found" } : get(s); }
  if(mode === "incomplete-enrollment") unlinkSync(join(f.paths.reclaim,".coordination.lock"));
  if(mode === "missing-observation" || mode === "stale-observation") f.reader.getSignatureStatus=async()=>({ kind:"found",slot:40n,commitment:"finalized",err:null,...mode === "stale-observation" ? { observedSlot:39n } : {} });
  if(mode !== "incomplete-enrollment") f.options.evidenceDigest=await restaurantOutcomeEvidence(f.options);
  await expect(f.apply()).rejects.toThrow();expect(readFileSync(f.path)).toEqual(pre);expect(existsSync(f.busyPath)).toBe(true);
  expect(readdirSync(f.paths.orders).some(n=>n.endsWith(".record"))).toBe(false);
});
test("same-byte replacement of persisted order inode refuses repetition",async()=>{
  const f=await fixture();await f.apply();const post=readFileSync(f.path);renameSync(f.path,join(f.root,"old-order"));writeFileSync(f.path,post,{ mode:0o600 });
  await expect(f.apply()).rejects.toThrow();expect(readFileSync(f.path)).toEqual(post);expect(existsSync(f.lockPath)).toBe(true);
});
test("a common deadline covers identity, all statuses and account without resetting",async()=>{
  const f=await fixture(),pre=readFileSync(f.path),status=f.reader.getSignatureStatus;
  const wait=()=>new Promise<void>(r=>setTimeout(r,60));f.options.timeoutMs=150;
  f.reader.verifyIdentity=async()=>{ await wait();return f.identity; };
  f.reader.getSignatureStatus=async s=>{ await wait();return status(s); };
  const before=Date.now();await expect(f.apply()).rejects.toThrow();expect(Date.now()-before).toBeLessThan(500);
  await new Promise(r=>setTimeout(r,100)); // Late status cannot reach persistence.
  expect(readFileSync(f.path)).toEqual(pre);expect(existsSync(f.busyPath)).toBe(true);expect(readdirSync(f.paths.orders).some(n=>n.endsWith(".record"))).toBe(false);
});
test("two explicit applications serialize and produce one durable result",async()=>{
  const f=await fixture();const results=await Promise.all([f.apply(),f.apply()]);expect(results.map(r=>r.result)).toEqual(["applied","already-applied"]);
  expect(JSON.parse(readFileSync(f.path,"utf8")).events).toHaveLength(2);expect(readdirSync(f.paths.orders).filter(n=>n.endsWith(".record"))).toHaveLength(1);
});

test.each([false,true])("salmon CAPTURE also applies finalized success/failure once: %s",async failure=>{
  const f=await outcomeFixture(failure,false,"salmon");roots.push(f.root);await f.apply();expect((await f.apply()).result).toBe("already-applied");
  expect(JSON.parse(readFileSync(f.path,"utf8")).events[1]).toMatchObject({ action:"salmon",amount:"60000000",status:failure ? "rejected" : "finalized",transaction:f.signature });expect(existsSync(f.lockPath)).toBe(true);
});
test("a compatible finalized zero hold derives closed menu status",async()=>{
  const f=await fixture();new DataView(f.account.data.buffer).setBigUint64(160,0n,true);await f.apply();expect(JSON.parse(readFileSync(f.path,"utf8")).status).toBe("closed");
});

test("fabricated exclusive token cannot replace the actual kernel/async-context fence",async()=>{
  const f=await fixture(),{ CoordinationToken }=await import("../src/coordination.ts"),pre=readFileSync(f.path);
  f.domain.run=async(_mode,action)=>action(new CoordinationToken(f.domain,"exclusive"));
  await expect(f.apply()).rejects.toThrow();expect(readFileSync(f.path)).toEqual(pre);expect(existsSync(f.busyPath)).toBe(true);
});
test("fixture admission pins complete metadata instead of accepting changed enrollment assertions",async()=>{
  const f=await fixture(),pre=readFileSync(f.path);f.domain.metadata.writers.reverse();
  await expect(f.apply()).rejects.toThrow();expect(readFileSync(f.path)).toEqual(pre);expect(existsSync(f.busyPath)).toBe(true);
});
