import { expect,test } from 'vitest';
// @ts-expect-error browser module has intentionally no Node dependency or TS declaration.
import { definitiveReceipt,recoveryMatches,authorizeIsolationMatches } from '../web/receipt-state.js';
const receipt={success:false,errorReason:'settlement_not_submitted',transaction:'',network:'devnet',payer:'payer'};
test('only matching exact pre-dispatch response evidence is definitive',()=>{
  expect(definitiveReceipt(receipt,{...receipt},'devnet','payer')).toBe(true);
  for(const other of [undefined,{}, {...receipt,payer:'wrong'}, {...receipt,network:'wrong'}, {...receipt,transaction:'original'}, {...receipt,errorReason:'settlement_pending'}, {...receipt,success:true}]) expect(definitiveReceipt(other,other,'devnet','payer')).toBe(false);
  expect(definitiveReceipt(receipt,{...receipt,payer:'stale'},'devnet','payer')).toBe(false);
});
test('a distinct offer requires the exact UNKNOWN effect exclusion and retained reserve',()=>{
  const sig='3'.repeat(88),order={id:'old',payment:'payment',status:'pending',refundDeadline:180,events:[{action:'authorize',status:'pending',signature:sig}]};
  const isolation={kind:'expired-no-successful-authorize-effect',originalOutcome:'unknown',originalSignature:sig,reserveRetained:true,
    proof:{kind:'expired-no-successful-authorize-effect',payment:'payment',unsignedSha256:'a'.repeat(64),originSlot:'1',expirySlot:'2',paymentSlot:'3',clockSlot:'4',clockUnixTimestamp:'180'}};
  expect(authorizeIsolationMatches(isolation,order)).toBe(true);
  for(const patch of [{originalOutcome:'failed'},{originalSignature:'4'.repeat(88)},{reserveRetained:false},{kind:'history-empty'}])expect(authorizeIsolationMatches({...isolation,...patch},order)).toBe(false);
  for(const patch of [{payment:'other'},{expirySlot:'1'},{paymentSlot:'1'},{clockSlot:'2'},{clockUnixTimestamp:'179'},{originSlot:'-1'},{unsignedSha256:''}])expect(authorizeIsolationMatches({...isolation,proof:{...isolation.proof,...patch}},order)).toBe(false);
  for(const patch of [{status:'active'},{events:[]},{events:[...order.events,...order.events]},{refundDeadline:null}])expect(authorizeIsolationMatches(isolation,{...order,...patch})).toBe(false);
});
test('legacy recovery cannot use another/stale order, payer, payment or provenance',()=>{
  const order={id:'id',payer:'payer',payment:'payment'},proof={order:'id',payer:'payer',payment:'payment',classification:'source-bound-pre-dispatch-refusal',policySha256:'a'.repeat(64),originalEvidenceSha256:'b'.repeat(64)};
  expect(recoveryMatches(proof,order,'id')).toBe(true);
  for(const patch of [{order:'other'},{payer:'other'},{payment:'other'},{classification:'balance-only'},{policySha256:'stale'},{originalEvidenceSha256:''}]) expect(recoveryMatches({...proof,...patch},order,'id')).toBe(false);
  expect(recoveryMatches(proof,order,'other')).toBe(false);
});
