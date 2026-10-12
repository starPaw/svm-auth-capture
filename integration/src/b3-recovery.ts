// A single owner-reviewed legacy HTTP refusal. This is new recovery evidence, never a
// replacement for a historical settlement receipt. No lock deletion or capture retry.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import type { Address } from '@solana/kit';
export type B3Recovery = { schema:1; order:string; payment:Address; payer:Address; sourceSha:string;
  orderSha256:string; authorizeSignature:string; originalEvidenceSha256:string;
  classification:'source-bound-pre-dispatch-refusal'; action:'beer' };
export function b3RecoveryEvidence(policy: B3Recovery | undefined, order: {id:string;payment:Address;payer:Address;status:string;events:{action:string;status:string;transaction:string}[]},
  orderPath: string, busy: boolean) {
  if (!policy || policy.schema !== 1 || policy.classification !== 'source-bound-pre-dispatch-refusal' || policy.action !== 'beer' ||
    policy.sourceSha !== '4e570a1adc14e1c5477d4a6270df02884cd58b88' || !/^[a-f0-9]{64}$/.test(policy.originalEvidenceSha256) ||
    policy.order !== order.id || policy.payment !== order.payment || policy.payer !== order.payer || busy || order.status === 'pending' ||
    existsSync(`${orderPath}.beer.lock`) || order.events.some(e => e.action !== 'authorize' && e.action !== 'reclaim') ||
    order.events.filter(e => e.action === 'authorize').length !== 1 ||
    !order.events.some(e => e.action === 'authorize' && e.status === 'finalized' && e.transaction === policy.authorizeSignature)) return undefined;
  const continued = order.events.some(e => e.action === 'reclaim' && e.status === 'finalized');
  // Reclaim preparation/result appends only reclaim fields/events. Reconstruct and bind
  // the original exact compact order, so unrelated edits or stale provenance fail closed.
  const original = JSON.parse(readFileSync(orderPath,'utf8'));
  delete original.reclaimUnsigned; delete original.reclaimLifetime;
  original.events = original.events.filter((e:{action:string}) => e.action !== 'reclaim');
  original.status = 'active';
  if (createHash('sha256').update(JSON.stringify(original)).digest('hex') !== policy.orderSha256) return undefined;
  return {order:order.id,payer:order.payer,payment:order.payment,policySha256:createHash('sha256').update(JSON.stringify(policy)).digest('hex'),
    originalEvidenceSha256:policy.originalEvidenceSha256,classification:policy.classification,continued};
}
