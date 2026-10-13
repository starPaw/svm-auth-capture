import {test,expect} from 'vitest';
import {E2E_MERCHANT_DEMO_POLICY,validateMerchantDemoPolicy} from '../src/merchant-demo.ts';
const policy={...E2E_MERCHANT_DEMO_POLICY,reference:'explicit-owner-e2e-demo'};
test('only the fixed bounded E2E campaign can enable public merchant delegation',()=>{
  expect(()=>validateMerchantDemoPolicy(policy)).not.toThrow();
  for(const [key,value] of Object.entries(policy)) {
    expect(()=>validateMerchantDemoPolicy({...policy,[key]:typeof value==='number'?value+1:key==='reference'?'':value+'changed'})).toThrow();
    const missing={...policy} as Record<string,unknown>;delete missing[key];
    expect(()=>validateMerchantDemoPolicy(missing)).toThrow();
  }
  for(const bad of [null,[],{},true,{...policy,enableProduction:true}])expect(()=>validateMerchantDemoPolicy(bad)).toThrow();
});
