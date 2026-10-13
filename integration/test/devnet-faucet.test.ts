// Real local classic-SPL execution and cryptographic wallet consent. No Devnet sends.
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { mkdirSync, mkdtempSync, writeFileSync, renameSync, chmodSync, rmSync, openSync, closeSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { getCompiledTransactionMessageDecoder, getSignatureFromTransaction, signBytes, type Address } from '@solana/kit';
import { getCreateAssociatedTokenIdempotentInstruction, getMintToInstruction, getTokenDecoder, getTransferCheckedInstruction } from '@solana-program/token';
import { createHarness, type Harness } from './fixture.ts';
import { ata, TOKEN_PROGRAM_ADDRESS } from '../src/program.ts';
import { encodeTransaction } from '../src/transactions.ts';
import { CampaignBudget } from '../src/campaign-budget.ts';
import { AdmissionJournal } from '../src/admission-journal.ts';
import { SponsorshipGuard } from '../src/sponsorship.ts';
import { DevnetFaucetStore, type FaucetPolicy } from '../src/devnet-faucet-store.ts';
import { DevnetFaucet, createDevnetFaucetApp, type FaucetConfig } from '../src/devnet-faucet.ts';
import type { FinalizedTransaction } from '../src/campaign-proof.ts';
import { createGatewayApp } from '../src/gateway.ts';
import { devnetFaucetProxy } from '../src/devnet-faucet-proxy.ts';

let h:Harness,dir:string,c:FaucetConfig,service:DevnetFaucet,policy:FaucetPolicy;
let proofs:Map<string,FinalizedTransaction>,available:boolean;
const network='solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1',genesis='EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG';
const bearer='local-faucet-only-bearer-credential-0123456789';
const now=()=>Math.floor(Date.now()/1000);
const balance=async(owner:Address)=>getTokenDecoder().decode((await h.ledger.getAccount(await ata(owner,h.mint)))!.data).amount;
beforeEach(async()=>{
  h=await createHarness();h.setTime(BigInt(now()));Reflect.set(h.ledger,'network',network);
  dir=mkdtempSync(join(tmpdir(),'capture402-faucet-'));proofs=new Map();available=true;
  const pool=await ata(h.facilitatorKey.address,h.mint);
  h.ok(await h.direct([getCreateAssociatedTokenIdempotentInstruction({payer:h.setup,ata:pool,owner:h.facilitatorKey.address,mint:h.mint,tokenProgram:TOKEN_PROGRAM_ADDRESS}),
    getMintToInstruction({mint:h.mint,token:pool,mintAuthority:h.setup,amount:100_000_000_000n})]));
  policy={schema:1,reference:'local-faucet-fixture',network,genesisHash:genesis,mint:h.mint,sponsor:h.facilitatorKey.address,pool,origin:'https://demo.test',maximumClaims:100,amount:'1000000000',cooldownSeconds:86400};
  for(const sub of ['faucet','budget','admission'])mkdirSync(join(dir,sub),{mode:0o700});
  DevnetFaucetStore.initialize(join(dir,'faucet'),policy);
  const campaign={schema:1 as const,reference:'local-faucet-budget',genesisHash:genesis,sponsor:h.facilitatorKey.address,browser:h.payer.address,spendLimit:'1000000000' as const};
  CampaignBudget.initialize(join(dir,'budget'),campaign);
  AdmissionJournal.initialize(join(dir,'admission'),{schema:1,kind:'relay-attempts',reference:'local-faucet-admission',maximum:600,carryForward:21,historicalActual:null,sourceSha256:'a'.repeat(64)});
  const original=h.ledger.submit.bind(h.ledger);
  vi.spyOn(h.ledger,'submit').mockImplementation(async tx=>{
    const message=getCompiledTransactionMessageDecoder().decode(tx.messageBytes),keys=message.staticAccounts;
    const readBalance=(a:Address)=>{const account=h.svm.getAccount(a);return account.exists?account.lamports:0n;};
    const pre=keys.map(readBalance);
    const result=await original(tx),post=keys.map(readBalance);
    const record=h.ledger.submissions.at(-1)!;
    if(record.status!=='unknown') {
      const nonFee=keys.slice(1).reduce((n,_,i)=>n+(post[i+1]!>pre[i+1]!?post[i+1]!-pre[i+1]!:0n),0n);
      proofs.set(getSignatureFromTransaction(tx),{slot:10n,wire:encodeTransaction(tx),error:record.status==='failed'?{local:'failed'}:null,
        fee:pre[0]!-post[0]!-nonFee,preBalances:pre,postBalances:post});
    }
    return result;
  });
  c={store:new DevnetFaucetStore(join(dir,'faucet'),policy),sponsor:h.facilitatorKey,ledger:h.ledger,
    backend:{fee:async()=>25_000n,rent:async()=>h.svm.minimumBalanceForRentExemption(165n),finalized:async signature=>available?proofs.get(signature)??null:null},
    budget:new CampaignBudget(join(dir,'budget'),campaign),
    admission:new SponsorshipGuard({ledger:h.ledger,feePayer:h.facilitatorKey.address,maxAttempts:600,minLamportsBalance:10_000_000n,admission:new AdmissionJournal(join(dir,'admission'),'relay-attempts',600)}),
    latest:async()=>h.lifetime(),challengeKey:bearer,bearerToken:bearer};
  service=new DevnetFaucet(c);
});
afterEach(async()=>{vi.restoreAllMocks();vi.unstubAllGlobals();await h.close();rmSync(dir,{recursive:true,force:true});});
async function intent(recipient=h.payer) {
  const challenge=await service.challenge(recipient.address);
  const signature=Buffer.from(await signBytes(recipient.keyPair.privateKey,new TextEncoder().encode(challenge.message))).toString('base64');
  return {...challenge,signature};
}
test('1000 existing tokens, sponsor-paid ATA/fee, one signer and one transfer; no mint or escrow instruction',async()=>{
  const i=await intent();const poolBefore=await balance(h.facilitatorKey.address),payerBefore=await balance(h.payer.address);
  const receipt=await service.claim(i.token,i.signature);expect(receipt).toMatchObject({status:'finalized',amount:1000,recipient:h.payer.address,finalizedSlot:'10'});
  expect(await balance(h.payer.address)-payerBefore).toBe(1_000_000_000n);expect(poolBefore-await balance(h.facilitatorKey.address)).toBe(1_000_000_000n);
  expect(h.ledger.submissions).toHaveLength(1);
  const tx=h.ledger.submissions[0]!.transaction,m=getCompiledTransactionMessageDecoder().decode(tx.messageBytes);
  if(m.version!=='legacy')throw Error('expected legacy');
  expect(m.staticAccounts.slice(0,m.header.numSignerAccounts)).toEqual([h.facilitatorKey.address]);
  expect(m.instructions).toHaveLength(4);expect(m.staticAccounts).not.toContain(h.facilitator.programId);
  expect(c.budget.summary().reserved).toBe(0n);expect(c.budget.summary().committed).toBeGreaterThan(0n);expect(c.admission.attemptCount).toBe(22);
  expect(c.store.get(i.id)?.consent).toMatchObject({message:i.message,signature:i.signature});
});
test('replay reads only the original; daily refusal and reconstruction cannot spend again',async()=>{
  const i=await intent(),receipt=await service.claim(i.token,i.signature),before=c.budget.summary();
  c.store=new DevnetFaucetStore(join(dir,'faucet'),policy);service=new DevnetFaucet(c);
  expect(await service.claim(i.token,i.signature)).toEqual(receipt);expect(h.ledger.submissions).toHaveLength(1);expect(c.budget.summary()).toEqual(before);
  await expect(service.challenge(h.payer.address)).rejects.toThrow(/24 hours/);
});
test('atomic wallet cooldown permits a distinct next-day request only after 24 hours',async()=>{
  const i=await intent();await service.claim(i.token,i.signature);
  const t=c.store.nextEligibleAt(h.payer.address);
  expect(()=>c.store.reserve('b'.repeat(64),h.payer.address,t-1,c.store.get(i.id)!.consent)).toThrow(/24 hours/);
  expect(c.store.reserve('b'.repeat(64),h.payer.address,t,c.store.get(i.id)!.consent).requestedAt).toBe(t);
});
test.each(['wrong-wallet','message-change','token-change','expiry','wrong-mint','mainnet'])('invalid %s cannot reserve/sign/send',async fault=>{
  const i=await intent();let token=i.token,signature=i.signature;
  if(fault==='wrong-wallet')signature=Buffer.from(await signBytes(h.outsider.keyPair.privateKey,new TextEncoder().encode(i.message))).toString('base64');
  if(fault==='message-change')signature=Buffer.from(await signBytes(h.payer.keyPair.privateKey,new TextEncoder().encode(i.message+'changed'))).toString('base64');
  if(fault==='token-change')token=token.slice(0,-1)+(token.endsWith('a')?'b':'a');
  if(fault==='expiry')h.setTime(BigInt(i.expiresAt));
  if(fault==='wrong-mint'){const other={...policy,mint:h.outsider.address};mkdirSync(join(dir,'other'),{mode:0o700});DevnetFaucetStore.initialize(join(dir,'other'),other);const changed=new DevnetFaucet({...c,store:new DevnetFaucetStore(join(dir,'other'),other)});await expect(changed.claim(token,signature)).rejects.toThrow();}
  if(fault==='mainnet')expect(()=>new DevnetFaucet({...c,ledger:{...c.ledger,network:'solana:mainnet'} as any})).toThrow();
  if(!['wrong-mint','mainnet'].includes(fault))await expect(service.claim(token,signature)).rejects.toThrow();
  expect(c.store.summary().used).toBe(0);expect(h.ledger.submissions).toHaveLength(0);
});
test('concurrent valid claims admit one global original, including across store instances',async()=>{
  const a=await intent(),b=await intent(h.outsider);
  const other=new DevnetFaucet({...c,store:new DevnetFaucetStore(join(dir,'faucet'),policy)});
  const results=await Promise.allSettled([service.claim(a.token,a.signature),other.claim(b.token,b.signature)]);
  expect(results.filter(r=>r.status==='fulfilled')).toHaveLength(1);expect(h.ledger.submissions).toHaveLength(1);expect(c.store.summary().used).toBe(1);
});
test('lost finality retains original signed wire/full reserve across restart; read-only observation resolves it',async()=>{
  available=false;const i=await intent(),result=await service.claim(i.token,i.signature);
  expect(result.status).toBe('unknown');expect(service.blocked()).toBe(true);expect(c.budget.summary().reserved).toBeGreaterThan(0n);
  const original=c.store.get(i.id)!;expect(original.signed).toBe(encodeTransaction(h.ledger.submissions[0]!.transaction));
  const restarted=new DevnetFaucet({...c,store:new DevnetFaucetStore(join(dir,'faucet'),policy)});
  await expect(restarted.challenge(h.outsider.address)).rejects.toThrow(/pending or unknown/);
  expect((await restarted.claim(i.token,i.signature)).status).toBe('unknown');expect(h.ledger.submissions).toHaveLength(1);
  available=true;expect((await restarted.observe(i.id)).status).toBe('finalized');expect(restarted.blocked()).toBe(false);expect(c.budget.summary().reserved).toBe(0n);
});
test('submission throw does not retry or release the ceiling',async()=>{
  vi.mocked(h.ledger.submit).mockRejectedValue(new Error('private-provider-secret'));
  const i=await intent();expect((await service.claim(i.token,i.signature)).status).toBe('unknown');
  expect(c.store.get(i.id)?.stage).toBe('signed');expect(c.budget.summary().reserved).toBeGreaterThan(0n);
  expect((await service.claim(i.token,i.signature)).status).toBe('unknown');expect(h.ledger.submit).toHaveBeenCalledTimes(1);
});
test('crash at signing stage freezes new claims without any regenerated transaction',async()=>{
  const i=await intent();vi.spyOn(c.store,'signed').mockImplementation(()=>{throw Error('fsync failure');});
  expect((await service.claim(i.token,i.signature)).status).toBe('unknown');expect(c.store.get(i.id)?.stage).toBe('signing');
  expect(h.ledger.submit).not.toHaveBeenCalled();
  const restarted=new DevnetFaucet({...c,store:new DevnetFaucetStore(join(dir,'faucet'),policy)});
  await expect(restarted.challenge(h.outsider.address)).rejects.toThrow(/pending or unknown/);expect((await restarted.observe(i.id)).status).toBe('unknown');
});
test('exhausted shared budget refuses before signing and preserves its unrelated UNKNOWN',async()=>{
  const i=await intent();c.budget.reserve('existing-unknown','sponsorship','a'.repeat(64),{fees:1_000_000_000n,rent:0n,browserAllocation:0n});
  await expect(service.claim(i.token,i.signature)).rejects.toThrow(/exhausted/);expect(c.store.get(i.id)?.stage).toBe('refused');expect(h.ledger.submit).not.toHaveBeenCalled();
  expect(c.budget.summary().reserved).toBe(1_000_000_000n);
});
test('empty dedicated pool refuses without taking tokens from merchant or loading mint authority',async()=>{
  const pool=await ata(h.facilitatorKey.address,h.mint),target=await ata(h.server.address,h.mint);
  h.ok(await h.direct([getTransferCheckedInstruction({source:pool,mint:h.mint,destination:target,authority:h.facilitatorKey,amount:100_000_000_000n,decimals:6})],[h.facilitatorKey]));
  const merchantBefore=await balance(h.server.address),i=await intent();
  await expect(service.claim(i.token,i.signature)).rejects.toThrow(/supply/);
  expect(c.store.get(i.id)?.stage).toBe('refused');expect(await balance(h.server.address)).toBe(merchantBefore);expect(h.ledger.submit).not.toHaveBeenCalled();
});
test('inconsistent finalized original proof cannot release UNKNOWN reserve',async()=>{
  available=false;const i=await intent(),r=await service.claim(i.token,i.signature);available=true;
  const proof=proofs.get(r.signature!)!;proof.postBalances[0]=proof.preBalances[0]!-1n;
  await expect(service.observe(i.id)).rejects.toThrow();expect(service.blocked()).toBe(true);expect(c.budget.summary().reserved).toBeGreaterThan(0n);
  expect(h.ledger.submissions).toHaveLength(1);
});
test('finalized SPL failure charges only fee and consumes quota without a replacement transaction',async()=>{
  h.ledger.beforeSubmit=async()=>{h.ok(await h.direct([getTransferCheckedInstruction({source:policy.pool,mint:h.mint,destination:await ata(h.server.address,h.mint),authority:h.facilitatorKey,amount:100_000_000_000n,decimals:6})],[h.facilitatorKey]));};
  const i=await intent(),r=await service.claim(i.token,i.signature);
  expect(r.status).toBe('failed');expect(c.budget.summary().reserved).toBe(0n);expect(c.budget.summary().committed).toBeGreaterThan(0n);
  expect(await service.claim(i.token,i.signature)).toEqual(r);expect(h.ledger.submissions).toHaveLength(1);
});
test('global100 quota, partial init, replaced lock and native concurrency fail closed without resets',async()=>{
  const i=await intent(),consent={message:i.message,signature:i.signature,tokenSha256:'a'.repeat(64),issuedAt:now(),expiresAt:now()+600};
  for(let n=0;n<100;n++){const id=n.toString(16).padStart(64,'0');c.store.reserve(id,h.payer.address,now()+n*86400,consent);c.store.refuseBeforeSigning(id);}
  expect(c.store.summary()).toEqual({used:100,maximum:100});expect(()=>c.store.reserve('f'.repeat(64),h.payer.address,now()+100*86400,consent)).toThrow(/total/);
  expect(()=>DevnetFaucetStore.initialize(join(dir,'faucet'),policy)).toThrow(/existing/);
  renameSync(join(dir,'faucet','.lock'),join(dir,'faucet','.old'));writeFileSync(join(dir,'faucet','.lock'),'replacement',{mode:0o600});
  expect(()=>c.store.summary()).toThrow(/custody drift/);
});
test('native flock and unsafe state mode prevent any new claim',async()=>{
  const fd=openSync(join(dir,'faucet','.lock'),'r+'),flock=createRequire(import.meta.url)('fs-ext').flockSync;
  try{flock(fd,'exnb');expect(()=>c.store.summary()).toThrow();}finally{flock(fd,'un');closeSync(fd);}
  chmodSync(join(dir,'faucet','state.json'),0o644);expect(()=>c.store.summary()).toThrow(/unsafe/);
});
test('private routes require bearer, refuse extra fields and redact provider errors; public config cannot expose a key',async()=>{
  const app=createDevnetFaucetApp(service,bearer);
  expect((await app.request('/challenge',{method:'POST',body:JSON.stringify({recipient:h.payer.address})})).status).toBe(401);
  const headers={Authorization:`Bearer ${bearer}`,'Content-Type':'application/json'};
  expect((await app.request('/challenge',{method:'POST',headers,body:JSON.stringify({recipient:h.payer.address,amount:1})})).status).toBe(400);
  const i=await intent();vi.spyOn(c.ledger,'now').mockRejectedValue(new Error('https://provider/private-secret'));
  const r=await app.request('/claim',{method:'POST',headers,body:JSON.stringify({token:i.token,signature:i.signature})});
  expect(await r.text()).not.toMatch(/private-secret|provider\//);expect(h.ledger.submit).not.toHaveBeenCalled();
});
test('faucet UNKNOWN stops facilitator settle before economic signing or shared admission',async()=>{
  available=false;const i=await intent();await service.claim(i.token,i.signature);
  const app=createGatewayApp(h.facilitator,{bearerToken:bearer,sponsorship:c.admission,allowlist:{merchant:h.server.address,mint:h.mint},faucet:service});
  const count=c.admission.attemptCount;
  const r=await app.request('/settle',{method:'POST',headers:{Authorization:`Bearer ${bearer}`,'Content-Type':'application/json'},body:'{}'});
  expect(r.status).toBe(409);expect(c.admission.attemptCount).toBe(count);expect(h.ledger.submissions).toHaveLength(1);
});
test('proxy fixes loopback routes, no redirects, private bearer header only',async()=>{
  expect(()=>devnetFaucetProxy('https://external.test',bearer)).toThrow(/loopback/);
  const fetch=vi.fn(async()=>new Response('{}'));vi.stubGlobal('fetch',fetch);
  const proxy=devnetFaucetProxy('http://127.0.0.1:28887/',bearer);
  await proxy.request('/challenge','POST',{recipient:h.payer.address});
  const [url,init]=fetch.mock.calls[0] as any;expect(String(url)).toBe('http://127.0.0.1:28887/faucet/challenge');expect(init.redirect).toBe('error');expect(init.headers.Authorization).toBe(`Bearer ${bearer}`);
  await expect(proxy.request('/settle','POST',{})).rejects.toThrow(/route/);await expect(proxy.request('/claims/'+'a'.repeat(64),'POST',{})).rejects.toThrow(/method/);
});
