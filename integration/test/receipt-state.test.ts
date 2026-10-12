import { expect,test } from 'vitest';
// @ts-expect-error browser module has intentionally no Node dependency or TS declaration.
import { definitiveReceipt,recoveryMatches } from '../web/receipt-state.js';
const receipt={success:false,errorReason:'settlement_not_submitted',transaction:'',network:'devnet',payer:'payer'};
test('only matching exact pre-dispatch response evidence is definitive',()=>{
  expect(definitiveReceipt(receipt,{...receipt},'devnet','payer')).toBe(true);
  for(const other of [undefined,{}, {...receipt,payer:'wrong'}, {...receipt,network:'wrong'}, {...receipt,transaction:'original'}, {...receipt,errorReason:'settlement_pending'}, {...receipt,success:true}]) expect(definitiveReceipt(other,other,'devnet','payer')).toBe(false);
  expect(definitiveReceipt(receipt,{...receipt,payer:'stale'},'devnet','payer')).toBe(false);
});
test('legacy recovery cannot use another/stale order, payer, payment or provenance',()=>{
  const order={id:'id',payer:'payer',payment:'payment'},proof={order:'id',payer:'payer',payment:'payment',classification:'source-bound-pre-dispatch-refusal',policySha256:'a'.repeat(64),originalEvidenceSha256:'b'.repeat(64)};
  expect(recoveryMatches(proof,order,'id')).toBe(true);
  for(const patch of [{order:'other'},{payer:'other'},{payment:'other'},{classification:'balance-only'},{policySha256:'stale'},{originalEvidenceSha256:''}]) expect(recoveryMatches({...proof,...patch},order,'id')).toBe(false);
  expect(recoveryMatches(proof,order,'other')).toBe(false);
});
