// Only exact HTTP response evidence can release a newly-created request latch.
// Historical recovery is a separate explicit operation and never fabricates this receipt.
export function definitiveReceipt(receipt, header, network, payer) {
  if (!receipt || !header || JSON.stringify(receipt) !== JSON.stringify(header) || receipt.network !== network || receipt.payer !== payer || typeof receipt.success !== 'boolean') return false;
  return receipt.success === false && receipt.errorReason === 'settlement_not_submitted' && receipt.transaction === '';
}
export function recoveryMatches(recovery, order, latch) {
  return !!recovery && latch === order.id && recovery.order === order.id && recovery.payer === order.payer && recovery.payment === order.payment &&
    recovery.classification === 'source-bound-pre-dispatch-refusal' && /^[a-f0-9]{64}$/.test(recovery.policySha256) && /^[a-f0-9]{64}$/.test(recovery.originalEvidenceSha256);
}
export function authorizeIsolationMatches(isolation,order) {
  const p=isolation?.proof,numeric=v=>typeof v==='string'&&/^(0|[1-9][0-9]*)$/.test(v);
  return !!order && order.status==='pending' && isolation?.kind==='expired-no-successful-authorize-effect' && isolation.originalOutcome==='unknown' && isolation.reserveRetained===true &&
    Number.isSafeInteger(order.refundDeadline) && order.refundDeadline>=0 && /^[1-9A-HJ-NP-Za-km-z]{80,90}$/.test(isolation.originalSignature) &&
    p?.kind===isolation.kind && p.payment===order.payment && /^[a-f0-9]{64}$/.test(p.unsignedSha256) &&
    ['originSlot','expirySlot','paymentSlot','clockSlot','clockUnixTimestamp'].every(k=>numeric(p[k])) &&
    BigInt(p.expirySlot)>BigInt(p.originSlot) && BigInt(p.paymentSlot)>=BigInt(p.expirySlot) && BigInt(p.clockSlot)>=BigInt(p.paymentSlot) &&
    BigInt(p.clockUnixTimestamp)>=BigInt(order.refundDeadline) && order.events?.length===1 && order.events[0].action==='authorize' &&
    order.events[0].status==='pending' && order.events[0].signature===isolation.originalSignature;
}
