// Official SDK connection/serialization tests. No extension approval, RPC or transaction relay.
import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { getBase64Encoder, getTransactionDecoder, partiallySignTransaction } from '@solana/kit';
import { createHarness, type Harness } from './fixture.js';
import { encodeTransaction } from '../src/transactions.js';
import { demoComputeInstructions } from "../src/demo-compute.js";
let h: Harness, standard: any, bridge: any;
beforeAll(async () => {
  h = await createHarness();
  Object.assign(globalThis,{localStorage:{getItem:()=>null},window:Object.assign(new EventTarget(),{location:{origin:'https://capture402.xyz'},localStorage:{getItem:()=>null}})});
  const standardPath='../web/wallet.js', bridgePath='../browser/solflare.js';
  standard=await import(standardPath); bridge=await import(bridgePath);
});
afterAll(async () => { await h.close(); Reflect.deleteProperty(globalThis,'window'); Reflect.deleteProperty(globalThis,'document'); Reflect.deleteProperty(globalThis,'localStorage'); });
const account=()=>({address:h.payer.address,chains:['solana:devnet'],features:['solana:signTransaction']});
describe('Devnet signing context',()=>{
  test('the actual pinned Solflare SDK connection URL explicitly selects Devnet rather than its Mainnet default',()=>{
    let markup='';
    Object.assign(globalThis,{document:{title:'Capture402',getElementsByClassName:()=>[],body:{appendChild:()=>{}},createElement:()=>({set innerHTML(value:string){markup=value;},querySelector:()=>({style:{}}),remove:()=>{}})}});
    const sdk=bridge.createSolflareDevnet();
    try {
      sdk._injectElement();
      const src=markup.match(/src='([^']+)'/)![1]!;
      const url=new URL(src);expect(url.origin).toBe('https://connect.solflare.com');
      expect(url.searchParams.get('cluster')).toBe('devnet');expect(src).not.toContain('mainnet');
    } finally { sdk._removeElement(); }
  });
  test('a Mainnet config is rejected before connect or any wallet signing call',async()=>{
    let calls=0;
    const wallet={name:'Fixture',features:{'standard:connect':{connect:async()=>{calls++;return{accounts:[account()]};}},'solana:signTransaction':{signTransaction:async()=>{calls++;return[];}}}};
    const bad={...standard.DEVNET_POLICY,walletChain:'solana:mainnet'};
    await expect(standard.connect(wallet,()=>{},bad)).rejects.toThrow('restricted');
    const unsigned=encodeTransaction(await h.signedAuthorize({salt:h.newSalt(),signers:[],extra:demoComputeInstructions(200_000)}));
    await expect(standard.walletSign({wallet,account:account()},unsigned,bad)).rejects.toThrow('restricted');
    for(const policy of [{...standard.DEVNET_POLICY,cluster:'mainnet-beta'},{...standard.DEVNET_POLICY,network:'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp'}])
      await expect(standard.walletSign({wallet,account:account()},unsigned,policy)).rejects.toThrow('restricted');
    expect(calls).toBe(0);expect(h.ledger.submissions).toHaveLength(0);
  });
  test('configured Devnet forwarding carries the exact Devnet chain and preserves only payer signature insertion',async()=>{
    const unsigned=encodeTransaction(await h.signedAuthorize({salt:h.newSalt(),signers:[],extra:demoComputeInstructions(200_000)}));
    const calls:any[]=[];
    const connection={account:account(),wallet:{name:'Solflare',features:{'solana:signTransaction':{signTransaction:()=>{throw new Error('injected bridge must not be used');}}}},signTransaction:async(input:any)=>{
      calls.push({chain:input.chain,account:input.account.address});
      const tx=await partiallySignTransaction([h.payer.keyPair],getTransactionDecoder().decode(input.transaction));
      return[{signedTransaction:getBase64Encoder().encode(encodeTransaction(tx))}];
    }};
    await standard.walletSign(connection,unsigned,standard.DEVNET_POLICY);
    expect(calls).toEqual([{chain:'solana:devnet',account:h.payer.address}]);
    expect(standard.signingReport()).toMatchObject({messageEqual:true,changedFields:[]});
    expect(h.ledger.submissions).toHaveLength(0);
  });
  test('the Solflare serialization class round-trips the offered legacy message without replacing the blockhash',async()=>{
    const {VersionedTransaction}=await import('@solana/web3.js');
    const unsigned=encodeTransaction(await h.signedAuthorize({salt:h.newSalt(),signers:[],extra:demoComputeInstructions(200_000)}));
    const original=getBase64Encoder().encode(unsigned);
    expect(Array.from(VersionedTransaction.deserialize(new Uint8Array(original)).serialize())).toEqual(Array.from(original));
  });
});
