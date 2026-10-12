// Explicit preparation after expiry of an initial consent or unused custody-bound draft.
// Null consent means no consent existed; the caller must authenticate durable custody.
// Preserve the old draft/consent; canonical expiry plus positive monotone H proves no
// successful reclaim effect. Missing signature/history is never the expiry proof.
import { createHash } from 'node:crypto';
import { type Address, type Blockhash, getBase64Encoder, getTransactionDecoder, getCompiledTransactionMessageDecoder } from '@solana/kit';
import { decodePayment } from './program.ts';
import { buildTransaction, encodeTransaction, reclaimInstruction } from './transactions.ts';
import { demoComputeInstructions, COMPUTE_PROGRAM } from './demo-compute.ts';
import type { RpcLedger } from './rpc-ledger.ts';
const hash = (s: string | Uint8Array) => createHash('sha256').update(s).digest('hex');
export async function proveExpiredReclaimConsent(a: {
  unsigned: string; consent: string | null; order: string; payment: Address; payer: Address;
  server: Address; mint: Address; programId: Address; captureDeadline: bigint; refundDeadline: bigint;
  maximum: bigint; lifetime: {blockhash:string;blockhashSlot?:string;lastValidBlockHeight:string};
  minContextSlot: bigint;
  reader: Pick<RpcLedger,'getAccountAtLeast'|'getFinalizedBlockhashStatus'|'getClockAtLeast'>;
}) {
  const blocked = () => new Error('Expired reclaim consent lacks canonical no-effect proof.');
  if (a.consent !== null) {
    const consent = JSON.parse(a.consent);
    if (Object.keys(consent).sort().join() !== 'order,unsignedSha256' || consent.order !== a.order || consent.unsignedSha256 !== hash(a.unsigned)) throw blocked();
  }
  if (!/^(0|[1-9][0-9]*)$/.test(a.lifetime.blockhashSlot ?? '') || !/^(0|[1-9][0-9]*)$/.test(a.lifetime.lastValidBlockHeight)) throw blocked();
  const tx = getTransactionDecoder().decode(getBase64Encoder().encode(a.unsigned));
  const m = getCompiledTransactionMessageDecoder().decode(tx.messageBytes);
  if(m.version!=='legacy') throw blocked();
  const limit=m.instructions[0];
  if (m.version !== 'legacy' || m.header.numSignerAccounts !== 1 || m.staticAccounts[0] !== a.payer || m.lifetimeToken !== a.lifetime.blockhash ||
      m.instructions.length !== 3 || !limit?.data || limit.data.length !== 5 || limit.data[0] !== 2 || m.staticAccounts[limit.programAddressIndex] !== COMPUTE_PROGRAM) throw blocked();
  const units = new DataView(limit.data.buffer,limit.data.byteOffset,limit.data.byteLength).getUint32(1,true);
  const canonical = await buildTransaction({feePayer:a.payer,signers:[],lifetime:{blockhash:a.lifetime.blockhash as Blockhash,lastValidBlockHeight:BigInt(a.lifetime.lastValidBlockHeight)},
    instructions:[...demoComputeInstructions(units),await reclaimInstruction({programId:a.programId,payment:a.payment,payer:a.payer,server:a.server,mint:a.mint})]});
  // Exact canonical unsigned wire rejects signatures, transfers, nonce and alternate accounts.
  if (encodeTransaction(canonical) !== a.unsigned) throw blocked();
  const deadline = Date.now()+10_000;
  const originSlot=BigInt(a.lifetime.blockhashSlot!);
  const expiry=await a.reader.getFinalizedBlockhashStatus(a.lifetime.blockhash,originSlot,deadline);
  if(expiry.kind!=='ok' || expiry.valid || expiry.slot<=originSlot || expiry.slot<a.minContextSlot) throw blocked();
  const read=await a.reader.getAccountAtLeast(a.payment,expiry.slot,deadline);
  if(read.kind!=='ok' || read.slot<expiry.slot || !read.account || read.account.owner!==a.programId) throw blocked();
  const p=decodePayment(read.account.data);
  if(!p || p.payer!==a.payer || p.server!==a.server || p.mint!==a.mint || p.maximum!==a.maximum || p.captureDeadline!==a.captureDeadline ||
      p.refundDeadline!==a.refundDeadline || p.held<=0n) throw blocked();
  const clock=await a.reader.getClockAtLeast(read.slot,deadline);
  if(clock.kind!=='ok' || clock.commitment!=='finalized' || clock.slot<read.slot || clock.unixTimestamp<p.captureDeadline) throw blocked();
  // On this one-use PDA H cannot increase; a successful old reclaim would make H=0.
  return {kind:'expired-no-reclaim-effect' as const,unsignedSha256:hash(a.unsigned),consentSha256:a.consent === null ? null : hash(a.consent),originSlot:originSlot.toString(),
    expirySlot:expiry.slot.toString(),paymentSlot:read.slot.toString(),clockSlot:clock.slot.toString(),clockUnixTimestamp:clock.unixTimestamp.toString(),paymentDataSha256:hash(read.account.data),held:p.held.toString(),refundable:p.refundable.toString()};
}
