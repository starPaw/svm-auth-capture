// A distinct, owner-scoped disposition of one expired UNKNOWN authorization.
// Excludes successful authorization effect, not execution/fees. No original is
// repaired, unlocked, retried, signed, submitted or classified as not-submitted.
import { constants, openSync, closeSync, fstatSync, readFileSync, existsSync, lstatSync, chmodSync, fsyncSync } from 'node:fs';
import { join,dirname } from 'node:path';
import { sha256, proveExpiredUnfundedAuthorize } from './authorize-abandon.ts';
import { reconcileRestaurantOrder } from './restaurant-reconciliation.ts';
import { createDurableFile } from './durable-file.ts';
import type { RestaurantOrders } from './restaurant.ts';
import type { RpcLedger } from './rpc-ledger.ts';
import type { ChainReader } from './reconciliation.ts';
import type { Address } from '@solana/kit';

export const PENDING_A_ISOLATION = Object.freeze({schema:1,sourceSha:'6fe82359ac6248d89e0925534d4acc75649abc16',
  order:'aa272e90f73ef3ebda10c88eefa7fd78',payment:'EKugyxGa4KG5TMzWi1ywEPWhvyyWaR4SZuLi9BhZKTrS',payer:'93PtawNdAfDn7oTjRrbrJJMSgaFTjGS3wjtkrZSNGn74',
  orderSha256:'0f92d25d1ee169b7325fbc9dfc3480893ee0fc57960834168aca6328d8c7a4c9',
  consentSha256:'213040e7eeefb81900ae66cedcc1f77dea796dd0726dd7519f64ee3597797a35',
  busySha256:'4a2dbd905287e75a5d2b659d2546fbab79abb21689e50f59492612df59bff460',
  actionSha256:'e62b9c5bd14e2482af134b176e7de1eeba7bc6614ef00fef0f04fe93e6e24e2c',
  journalSha256:'d038da4bc42b06995d037d1df6c65422f3b3549200b98cd6a2d2a9a93141d95f',
  signature:'Pqaq1o374VvkbQkS3k9EmPVLBM7DyhTDJNBGf2qkh4ui9TpQmcvtnPfZRHFE3Bi6id4W8UWzWU2J271EwFeM8q1',
  messageHash:'ce1a2fdf5de2897fb1efb3b5572aaff3130256881acc7598c96e6744ae46a1a1',
  signedWireSha256:'f091d3a83c5dcc077374c9ff40c6363ee167ddaa7eb1698574e8a94bb0e659a0'});
export type IsolationPolicy = {-readonly [K in keyof typeof PENDING_A_ISOLATION]:typeof PENDING_A_ISOLATION[K] extends string ? string : number};
export type InstalledIsolationPolicy=IsolationPolicy & {archiveSha256:string};
type Order=ReturnType<RestaurantOrders['read']>;
type Reader=ChainReader & Pick<RpcLedger,'getFinalizedBlockhashStatus'|'getClockAtLeast'>;
function fail():never {throw Error('Unknown authorization isolation proof/custody unavailable; originals remain stopped.');}
const policyHash=(p:IsolationPolicy)=>sha256(JSON.stringify(Object.fromEntries(Object.entries(p).sort(([a],[b])=>a<b?-1:a>b?1:0))));
const prepared=new WeakMap<object,{path:string;policyHash:string;raw:string;deadline:number;journalPath:string;journalRaw:string;journalPin:ReturnType<typeof pin>}>();
function rawFile(path:string,mode=0o600) {
  const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try {
    const s=fstatSync(fd);
    if(!s.isFile() || s.nlink!==1 || s.size>1048576 || (s.mode&0o777)!==mode || s.uid!==lstatSync(dirname(path)).uid)fail();
    return readFileSync(fd,'utf8');
  }finally{closeSync(fd);}
}
function pin(path:string) {const s=lstatSync(path);return {inode:s.ino,device:s.dev,uid:s.uid,gid:s.gid,mode:s.mode&0o777,nlink:s.nlink,size:s.size};}
function originalPins(path:string) {return {order:pin(path),consent:pin(`${path}.wallet-consent.lock`),busy:pin(`${path}.busy`),action:pin(`${path}.authorize.lock`)};}
function originals(policy:IsolationPolicy,order:Order,path:string) {
  if(policy.schema!==1 || !/^[a-f0-9]{40}$/.test(policy.sourceSha) || Object.keys(policy).sort().join()!==Object.keys(PENDING_A_ISOLATION).sort().join() ||
    !['orderSha256','consentSha256','busySha256','actionSha256','journalSha256','messageHash','signedWireSha256'].every(k=>/^[a-f0-9]{64}$/.test(String(policy[k as keyof IsolationPolicy]))))fail();
  if(order.id!==policy.order || order.payment!==policy.payment || order.payer!==policy.payer || order.status!=='pending' || order.events.length!==1 ||
    order.events[0]?.action!=='authorize' || order.events[0].status!=='pending' || order.events[0].transaction!==policy.signature)fail();
  const r={order:rawFile(path),consent:rawFile(`${path}.wallet-consent.lock`),busy:rawFile(`${path}.busy`),action:rawFile(`${path}.authorize.lock`)};
  if(sha256(r.order)!==policy.orderSha256 || sha256(r.consent)!==policy.consentSha256 || sha256(r.busy)!==policy.busySha256 || sha256(r.action)!==policy.actionSha256 || r.busy!=='authorize')fail();
  const consent=JSON.parse(r.consent);
  if(Object.keys(consent).sort().join()!=='order,unsignedSha256' || consent.order!==order.id || consent.unsignedSha256!==sha256(order.unsigned))fail();
  return r;
}
/** Operator preparation only. Caller uses the pinned accepted RpcLedger and
 * complete stopped-E2E inventory. This function reads evidence and returns a
 * proposed immutable record and short-lived publication capability. It grants no
 * economic writer enrollment, signature or outcome repair authority. */
export async function prepareUnknownAuthorizeIsolation(a:{policy:IsolationPolicy;ordersDir:string;journalDirs:readonly string[];
  programId:Address;server:Address;mint:Address;funder:Address;network:string;reader:Reader}) {
  const deadline=Date.now()+30_000;
  const path=join(a.ordersDir,`${a.policy.order}.json`),order=JSON.parse(rawFile(path)) as Order;
  const before=originals(a.policy,order,path),pins=originalPins(path);
  if(existsSync(`${path}.authorize-isolation.lock`) || existsSync(`${path}.authorize-successor.lock`))fail();
  const report=await reconcileRestaurantOrder({ordersDir:a.ordersDir,orderId:order.id,journalDirs:a.journalDirs,programId:a.programId,network:a.network,reader:a.reader});
  const target=report.actions[0];
  if(report.issues.length || report.actions.length!==1 || report.reclaimReservations.length || !report.busy.present || report.busy.action!=='authorize' ||
    !target || target.action!=='authorize' || target.issues.length || target.verdict!=='unknown' || target.signature!==a.policy.signature ||
    target.signatureSource!=='submission-journal' || target.messageHash!==a.policy.messageHash || target.journals.length!==1 ||
    target.journals[0]?.sha256!==a.policy.journalSha256 || target.journals[0].wireSha256!==a.policy.signedWireSha256 ||
    target.journals[0].attempts!==1 || target.journals[0].latestOutcome!=='unresolved' || report.payment.kind!=='ok' || report.payment.exists)fail();
  let journal:string|undefined,journalPin:ReturnType<typeof pin>|undefined,journalPath:string|undefined;
  for(const directory of a.journalDirs) {
    const file=join(directory,`${a.policy.signature}.json`);
    if(existsSync(file)){if(journal!==undefined)fail();journal=rawFile(file);journalPin=pin(file);journalPath=file;}
  }
  if(!journal || !journalPin || !journalPath || sha256(journal)!==a.policy.journalSha256)fail();
  const offer=order.required.accepts[0]!;
  if(offer.amount!=='100000000' || offer.asset!==a.mint || offer.payTo!==a.server || offer.extra?.feePayer!==a.funder || offer.extra.programId!==a.programId)fail();
  // The canonical unsigned representation authenticates the same message as the
  // fully signed journal above. Permanent v1 PDA absence excludes success only.
  const unsignedProof=await proveExpiredUnfundedAuthorize({order,programId:a.programId,server:a.server,mint:a.mint,funder:a.funder,network:a.network,
    maximum:100000000n,captureDeadline:BigInt(offer.extra.captureDeadline as number),refundDeadline:BigInt(offer.extra.refundDeadline as number),reader:a.reader});
  if(JSON.stringify(originals(a.policy,order,path))!==JSON.stringify(before) || JSON.stringify(originalPins(path))!==JSON.stringify(pins))fail();
  for(const directory of a.journalDirs) {const file=join(directory,`${a.policy.signature}.json`);if(existsSync(file)&&(rawFile(file)!==journal || JSON.stringify(pin(file))!==JSON.stringify(journalPin)))fail();}
  const record={schema:1,kind:'expired-no-successful-authorize-effect' as const,policySha256:policyHash(a.policy),originalOutcome:'unknown' as const,
    reserveDisposition:'retained' as const,originals:before,originalPins:pins,originalJournal:journal,originalJournalPin:journalPin,report,
    proof:{...unsignedProof,kind:'expired-no-successful-authorize-effect' as const}};
  if(Date.now()>=deadline)fail();
  prepared.set(record,{path,policyHash:policyHash(a.policy),raw:JSON.stringify(record),deadline,journalPath,journalRaw:journal,journalPin});
  return record;
}
export type IsolationRecord=Awaited<ReturnType<typeof prepareUnknownAuthorizeIsolation>>;
/** Only the separately authorized stopped-E2E operator calls this writer. */
export function persistUnknownAuthorizeIsolation(policy:IsolationPolicy,path:string,record:IsolationRecord) {
  const issued=prepared.get(record);
  if(!issued || issued.path!==path || issued.policyHash!==policyHash(policy) || issued.raw!==JSON.stringify(record) || Date.now()>=issued.deadline)fail();
  prepared.delete(record);
  if(rawFile(issued.journalPath)!==issued.journalRaw || JSON.stringify(pin(issued.journalPath))!==JSON.stringify(issued.journalPin))fail();
  const order=JSON.parse(rawFile(path)) as Order;
  if(JSON.stringify(originals(policy,order,path))!==JSON.stringify(record.originals) || JSON.stringify(originalPins(path))!==JSON.stringify(record.originalPins) || record.policySha256!==policyHash(policy))fail();
  const file=`${path}.authorize-isolation.lock`,raw=JSON.stringify(record);
  createDurableFile(file,raw);chmodSync(file,0o400);
  const fd=openSync(file,constants.O_RDONLY|constants.O_NOFOLLOW);try{fsyncSync(fd);}finally{closeSync(fd);}
  const parent=openSync(dirname(file),constants.O_RDONLY|constants.O_DIRECTORY);try{fsyncSync(parent);}finally{closeSync(parent);}
  return sha256(raw);
}
export function authorizeIsolationEvidence(policy:InstalledIsolationPolicy|undefined,order:Order,path:string) {
  const file=`${path}.authorize-isolation.lock`;
  if(!existsSync(file)){if(policy?.order===order.id)fail();return undefined;}
  if(!policy || !/^[a-f0-9]{64}$/.test(policy.archiveSha256))fail();
  const {archiveSha256,...scope}=policy,raw=rawFile(file,0o400),record=JSON.parse(raw) as IsolationRecord;
  const p=record.proof,numeric=(v:unknown)=>typeof v==='string'&&/^(0|[1-9][0-9]*)$/.test(v);
  if(sha256(raw)!==archiveSha256 || record.schema!==1 || record.kind!=='expired-no-successful-authorize-effect' || record.policySha256!==policyHash(scope) ||
    record.originalOutcome!=='unknown' || record.reserveDisposition!=='retained' || JSON.stringify(record.originals)!==JSON.stringify(originals(scope,order,path)) || JSON.stringify(record.originalPins)!==JSON.stringify(originalPins(path)) ||
    sha256(record.originalJournal)!==scope.journalSha256 || p?.kind!==record.kind || p.payment!==order.payment || p.unsignedSha256!==sha256(order.unsigned) ||
    !['originSlot','expirySlot','paymentSlot','clockSlot','clockUnixTimestamp'].every(k=>numeric(p[k as keyof typeof p])) ||
    p.originSlot!==order.authorizeLifetime?.contextSlot || BigInt(p.expirySlot)<=BigInt(p.originSlot) || BigInt(p.paymentSlot)<BigInt(p.expirySlot) || BigInt(p.clockSlot)<BigInt(p.paymentSlot) ||
    BigInt(p.clockUnixTimestamp)<BigInt(order.required.accepts[0]!.extra!.refundDeadline as number))fail();
  return {kind:record.kind,originalOutcome:record.originalOutcome,originalSignature:scope.signature,reserveRetained:true,proof:p};
}
