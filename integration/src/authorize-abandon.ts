// Owner-scoped classification of one expired, unfunded authorization. It never
// edits the draft, creates a payment, signs, submits, or expands admission.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { getBase64Encoder, getTransactionDecoder, getCompiledTransactionMessageDecoder, type Address, type Blockhash } from '@solana/kit';
import { decodeInstructionData, paymentAddress } from './program.ts';
import { authorizeInstruction, buildTransaction, encodeTransaction } from './transactions.ts';
import { COMPUTE_PROGRAM, demoComputeInstructions } from './demo-compute.ts';
import { messageHash } from './submission-journal.ts';
import type { LifetimeObservation } from './lifetime-provenance.ts';
import type { RpcLedger } from './rpc-ledger.ts';
export const sha256 = (s:string) => createHash('sha256').update(s).digest('hex');
export type AuthorizeAbandonPolicy = { schema:1; sourceSha:string; order:string; payment:string; payer:string; orderSha256:string; consentSha256:string };
export const EXPIRED_A_POLICY:AuthorizeAbandonPolicy = Object.freeze({schema:1,sourceSha:'16efce98bf2347e21d7883ce997998dc4564e178',
  order:'c0cb6e3f3adc7709a29f542578800b7a',payment:'CrMkRKeJakv8e7SV8qzo7ssDZize5dYUGsFrV8x1ZScV',payer:'93PtawNdAfDn7oTjRrbrJJMSgaFTjGS3wjtkrZSNGn74',
  orderSha256:'b8abf60bb11c10f3b2b78d06ee0e2b148fd86bad98ffa1c1906ccdfe724ad2e0',consentSha256:'48f7b0a5d11ba850e40b2630ac68e831bece0f1c59150f4a8f1fb3a839ba4073'});
type Draft = {id:string;payment:Address;payer:Address;status:string;unsigned:string;authorizeLifetime?:LifetimeObservation;events:unknown[]};
export function abandonmentCustody(policy:AuthorizeAbandonPolicy|undefined, order:Draft, path:string) {
  if(!policy || policy.schema!==1 || !/^[a-f0-9]{40}$/.test(policy.sourceSha) || policy.order!==order.id || policy.payment!==order.payment || policy.payer!==order.payer ||
    order.status!=='draft' || order.events.length || existsSync(`${path}.authorize.lock`)) return undefined;
  const originalOrder=readFileSync(path,'utf8');
  const consentPath=`${path}.wallet-consent.lock`;
  if(!existsSync(consentPath) || sha256(originalOrder)!==policy.orderSha256) return undefined;
  const originalConsent=readFileSync(consentPath,'utf8'),consent=JSON.parse(originalConsent);
  if(sha256(originalConsent)!==policy.consentSha256 || Object.keys(consent).sort().join()!=='order,unsignedSha256' || consent.order!==order.id || consent.unsignedSha256!==sha256(order.unsigned)) return undefined;
  return {originalOrder,originalConsent};
}
export function abandonmentEvidence(policy:AuthorizeAbandonPolicy|undefined, order:Draft, path:string) {
  const file=`${path}.authorize-abandon.lock`;
  if(!existsSync(file)) return undefined;
  const custody=abandonmentCustody(policy,order,path),a=JSON.parse(readFileSync(file,'utf8'));
  const numeric=(v:unknown)=>typeof v==='string' && /^(0|[1-9][0-9]*)$/.test(v);
  if(!custody || a.schema!==1 || a.policySha256!==sha256(JSON.stringify(policy)) || a.originalOrder!==custody.originalOrder || a.originalConsent!==custody.originalConsent ||
    a.proof?.kind!=='expired-unfunded-authorize' || a.proof.unsignedSha256!==sha256(order.unsigned) || a.proof.payment!==order.payment ||
    !['originSlot','expirySlot','paymentSlot','clockSlot','clockUnixTimestamp'].every(k=>numeric(a.proof[k])) || a.proof.originSlot!==order.authorizeLifetime?.contextSlot || BigInt(a.proof.expirySlot)<=BigInt(a.proof.originSlot) ||
    BigInt(a.proof.paymentSlot)<BigInt(a.proof.expirySlot) || BigInt(a.proof.clockSlot)<BigInt(a.proof.paymentSlot)) throw Error('Partial authorize abandonment remains blocked.');
  return {order:order.id,payment:order.payment,kind:'expired-unfunded-authorize' as const,proof:a.proof};
}
export async function proveExpiredUnfundedAuthorize(a:{order:Draft; programId:Address; server:Address; mint:Address; funder:Address; network:string;
  maximum:bigint;captureDeadline:bigint;refundDeadline:bigint;reader:Pick<RpcLedger,'getFinalizedBlockhashStatus'|'getAccountAtLeast'|'getClockAtLeast'>}) {
  const fail=()=>new Error('Exact expired unfunded authorization proof unavailable.');
  const tx=getTransactionDecoder().decode(getBase64Encoder().encode(a.order.unsigned));
  const m=getCompiledTransactionMessageDecoder().decode(tx.messageBytes),t=a.order.authorizeLifetime;
  if(m.version!=='legacy' || m.header.numSignerAccounts!==2 || m.staticAccounts[0]!==a.funder || m.staticAccounts[1]!==a.order.payer || m.instructions.length!==3 ||
    !t || t.version!==1 || t.commitment!=='finalized' || t.network!==a.network || !/^(0|[1-9][0-9]*)$/.test(t.contextSlot ?? '') || !/^(0|[1-9][0-9]*)$/.test(t.lastValidBlockHeight) ||
    t.messageHash!==messageHash(tx.messageBytes) || t.blockhash!==m.lifetimeToken) throw fail();
  const limit=m.instructions[0],ix=m.instructions[2];
  if(!limit?.data || limit.data.length!==5 || limit.data[0]!==2 || m.staticAccounts[limit.programAddressIndex]!==COMPUTE_PROGRAM || !ix?.data || m.staticAccounts[ix.programAddressIndex]!==a.programId) throw fail();
  const decoded=decodeInstructionData(new Uint8Array(ix.data));
  if(!decoded || decoded.op!=='authorize' || decoded.maximum!==a.maximum || decoded.captureDeadline!==a.captureDeadline || decoded.refundDeadline!==a.refundDeadline ||
    await paymentAddress(a.programId,a.order.payer,decoded.salt)!==a.order.payment) throw fail();
  const units=new DataView(limit.data.buffer,limit.data.byteOffset,limit.data.byteLength).getUint32(1,true);
  const canonical=await buildTransaction({feePayer:a.funder,signers:[],lifetime:{blockhash:t.blockhash as Blockhash,lastValidBlockHeight:BigInt(t.lastValidBlockHeight)},
    instructions:[...demoComputeInstructions(units),await authorizeInstruction({programId:a.programId,payer:a.order.payer,server:a.server,mint:a.mint,funder:a.funder,salt:decoded.salt,maximum:a.maximum,captureDeadline:a.captureDeadline,refundDeadline:a.refundDeadline})]});
  if(encodeTransaction(canonical)!==a.order.unsigned) throw fail(); // Reject signed/noncanonical wires, nonce or alternate account/terms.
  const deadline=Date.now()+10_000,originSlot=BigInt(t.contextSlot!);
  const expiry=await a.reader.getFinalizedBlockhashStatus(t.blockhash,originSlot,deadline);
  if(expiry.kind!=='ok' || expiry.valid || expiry.slot<=originSlot) throw fail();
  const p=await a.reader.getAccountAtLeast(a.order.payment,expiry.slot,deadline);
  if(p.kind!=='ok' || p.slot<expiry.slot || p.account!==null) throw fail();
  const clock=await a.reader.getClockAtLeast(p.slot,deadline);
  if(clock.kind!=='ok' || clock.commitment!=='finalized' || clock.slot<p.slot || clock.unixTimestamp<a.captureDeadline || clock.unixTimestamp<a.refundDeadline) throw fail();
  // v1 never closes a successfully authorized PDA. Its absence after the exact
  // canonical wire has expired excludes successful authorization, without history inference.
  return {kind:'expired-unfunded-authorize' as const,payment:a.order.payment,unsignedSha256:sha256(a.order.unsigned),originSlot:originSlot.toString(),
    expirySlot:expiry.slot.toString(),paymentSlot:p.slot.toString(),clockSlot:clock.slot.toString(),clockUnixTimestamp:clock.unixTimestamp.toString()};
}
