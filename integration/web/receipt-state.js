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
