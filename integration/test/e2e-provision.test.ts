import { CampaignBudget } from '../src/campaign-budget.ts';
import { afterEach, expect, test } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, symlinkSync, chmodSync, statSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { generateKeyPairSigner, getCompiledTransactionMessageDecoder, getSignatureFromTransaction, lamports, type Address, type Transaction } from '@solana/kit';
import { getTransferSolInstruction } from '@solana-program/system';
import { getMintDecoder, getTokenDecoder } from '@solana-program/token';
import { FailedTransactionMetadata, LiteSVM } from 'litesvm';
import { E2E_APPLICATION_RELEASE, E2E_BUDGET, E2EProvisioner, ProvisionStore, validatePlan, type ProvisionBackend, type FinalizedTransaction } from '../operators/e2e-provisioning.ts';
import { provisionArguments } from '../operators/e2e-provision.ts';
import { buildTransaction, encodeTransaction } from '../src/transactions.ts';
import { ata } from '../src/program.ts';
const directories: string[] = [];
afterEach(() => { directories.splice(0).forEach(d => rmSync(d, { recursive: true, force: true })); });
async function fixture() {
  const [sponsor, merchant, payer, mint, browser, faucet] = await Promise.all(Array.from({length: 6}, () => generateKeyPairSigner()));
  const plan = { applicationRelease: E2E_APPLICATION_RELEASE, approvalReference: 'test-approved-campaign', sponsor: sponsor!.address,
    merchant: merchant!.address, payer: payer!.address, mint: mint!.address, browser: browser!.address, externalFunding: [] as {signature:string;amount:string}[] };
  const directory = mkdtempSync(join(tmpdir(), 'capture402-e2e-provision-')); directories.push(directory);
  const store = new ProvisionStore(directory), svm = new LiteSVM();
  svm.airdrop(faucet!.address, lamports(20_000_000_000n));
  const proofs = new Map<string, FinalizedTransaction>();
  let requests = 0, sends = 0, signerLoads = 0;
  const backend: ProvisionBackend = {
    async genesis() { return 'synthetic-devnet'; },
    async snapshot(addresses, minSlot=0n) {
      return { slot: minSlot+1n, accounts: addresses.map(address => { const a=svm.getAccount(address); return a.exists ? { owner: a.programAddress, data: new Uint8Array(a.data), lamports: a.lamports, executable: a.executable } : null; }) };
    },
    async rent(size) { return svm.minimumBalanceForRentExemption(BigInt(size)); },
    async latest() { return { blockhash: svm.latestBlockhash(), lastValidBlockHeight: 1000n }; },
    async fee() { return 10_000n; },
    async submit(tx) { sends++; await execute(tx, 3n); return {kind:'submitted',outcome:{status:'succeeded',commitment:'finalized'}}; },
    async finalized(signature) { return proofs.get(signature)??null; },
  };
  async function execute(tx: Transaction, slot: bigint) {
    const message = getCompiledTransactionMessageDecoder().decode(tx.messageBytes);
    const balances = () => message.staticAccounts.map(a=>{const account=svm.getAccount(a); return account.exists?account.lamports:0n;});
    const preBalances=balances(), result=svm.sendTransaction(tx), postBalances=balances();
    if(result instanceof FailedTransactionMetadata) throw Error(result.toString());
    const signature=getSignatureFromTransaction(tx);
    const nonFee = slot < 3n ? 5_000_000_000n : svm.minimumBalanceForRentExemption(82n)+2n*svm.minimumBalanceForRentExemption(165n)+10_000_000n;
    proofs.set(signature,{slot,wire:encodeTransaction(tx),error:null,fee:preBalances[0]!-postBalances[0]!-nonFee,preBalances,postBalances});
    return signature;
  }
  for(let i=0;i<2;i++) {
    const tx=await buildTransaction({feePayer:faucet!.address,signers:[faucet!],lifetime:await backend.latest(),instructions:[getTransferSolInstruction({source:faucet!,destination:plan.sponsor,amount:lamports(5_000_000_000n)})]});
    plan.externalFunding.push({signature:await execute(tx,BigInt(i+1)),amount:'5000000000'}); svm.expireBlockhash();
  }
  const budgetDirectory=join(directory,'budget');mkdirSync(budgetDirectory,{mode:0o700});
  const policy={schema:1 as const,reference:plan.approvalReference,genesisHash:'synthetic-devnet',sponsor:plan.sponsor,browser:plan.browser,spendLimit:'1000000000' as const};
  CampaignBudget.initialize(budgetDirectory,policy); const budget=new CampaignBudget(budgetDirectory,policy);
  const provisioner = new E2EProvisioner(plan,store,backend,'synthetic-devnet',budget);
  const load = async () => { signerLoads++; return { sponsor:sponsor!,mint:mint! }; };
  return { plan,store,svm,proofs,backend,budget,provisioner,load,directory, browser:browser!, counters:()=>({requests,sends,signerLoads}) };
}
test('real local SVM setup creates exact browser allocation, merchant ATA and original finalized receipts',async()=>{
  const f=await fixture(); await f.provisioner.acceptFunding(); await f.provisioner.assets(f.load);
  const mint=f.svm.getAccount(f.plan.mint), browser=f.svm.getAccount(await ata(f.plan.browser,f.plan.mint)), merchant=f.svm.getAccount(await ata(f.plan.merchant,f.plan.mint)), wallet=f.svm.getAccount(f.plan.browser);
  if (!mint.exists || !browser.exists || !merchant.exists || !wallet.exists) throw Error('setup accounts missing');
  expect(getMintDecoder().decode(mint.data).supply).toBe(E2E_BUDGET.tokens);
  expect(getTokenDecoder().decode(browser.data).amount).toBe(600_000_000n);
  expect(getTokenDecoder().decode(merchant.data).amount).toBe(0n);
  expect(wallet.lamports).toBe(10_000_000n);
  expect(f.store.read('assets-receipt.json')?.status).toBe('FINALIZED_SUCCEEDED');
  expect(f.counters()).toEqual({requests:0,sends:1,signerLoads:1});
  expect(statSync(join(f.directory,'assets-signed.json')).mode&0o777).toBe(0o600);
});
test('concurrent asset calls and a restarted process cannot sign or submit a second setup',async()=>{
  const f=await fixture(); await f.provisioner.acceptFunding();
  const outcomes=await Promise.allSettled([f.provisioner.assets(f.load),f.provisioner.assets(f.load)]);
  expect(outcomes.filter(o=>o.status==='fulfilled')).toHaveLength(1);
  const restarted=new E2EProvisioner(f.plan,new ProvisionStore(f.directory),f.backend,'synthetic-devnet',f.budget);
  const before=readFileSync(join(f.directory,'assets-signed.json'));
  await expect(restarted.assets(f.load)).rejects.toThrow();
  expect(f.counters()).toEqual({requests:0,sends:1,signerLoads:1});
  expect(readFileSync(join(f.directory,'assets-signed.json'))).toEqual(before);
});
test('missing original external funding is UNKNOWN; read-only acceptance never sends or requests funds',async()=>{
 const f=await fixture();f.proofs.delete(f.plan.externalFunding[0]!.signature);
 expect(await f.provisioner.acceptFunding()).toMatchObject({status:'UNKNOWN'});
 expect(await f.provisioner.acceptFunding()).toMatchObject({status:'UNKNOWN'});
 expect(f.counters()).toEqual({requests:0,sends:0,signerLoads:0});
 expect(f.store.read('external-funding-receipt.json')).toBeNull();
});
test('lost setup response is reconciled only by the same finalized signature, without loading keys again',async()=>{
  const f=await fixture(); await f.provisioner.acceptFunding(); const send=f.backend.submit;
  f.backend.submit=async t=>{await send(t);throw Error('socket lost');};
  await expect(f.provisioner.assets(f.load)).rejects.toThrow();
  const signed=f.store.read('assets-signed.json')!;
  const restarted=new E2EProvisioner(f.plan,new ProvisionStore(f.directory),f.backend,'synthetic-devnet',f.budget);
  expect(await restarted.observe('assets')).toMatchObject({status:'FINALIZED_SUCCEEDED',signature:signed.signature});
  await expect(restarted.assets(f.load)).rejects.toThrow();
  expect(f.counters()).toEqual({requests:0,sends:1,signerLoads:1});
});
test.each(['assets-intent.json','assets-signed.json','assets-broadcast.json'] as const)('failed durable %s write prevents broadcast and replacement',async record=>{
  const f=await fixture(); await f.provisioner.acceptFunding(); const write=f.store.write.bind(f.store);
  f.store.write=(name,value)=>{write(name,value);if(name===record)throw Error('injected fsync failure after creation');};
  await expect(f.provisioner.assets(f.load)).rejects.toThrow();
  expect(f.counters().sends).toBe(0);
  f.store.write=write;
  await expect(f.provisioner.assets(f.load)).rejects.toThrow();
  expect(f.counters().sends).toBe(0);
  if(record==='assets-intent.json')expect(f.counters().signerLoads).toBe(0);
});
test('unavailable finalized history remains UNKNOWN and never rebroadcasts',async()=>{
  const f=await fixture();await f.provisioner.acceptFunding();const lookup=f.backend.finalized;
  const funding=f.plan.externalFunding[0]!.signature;
  f.backend.finalized=async signature=>f.plan.externalFunding.some(x=>x.signature===signature)?lookup(signature):null;
  await f.provisioner.assets(f.load);
  expect(await f.provisioner.observe('assets')).toMatchObject({status:'UNKNOWN'});
  await expect(f.provisioner.assets(f.load)).rejects.toThrow();expect(f.counters().sends).toBe(1);
});
test.each(['wire','signature','slot','mint','browser-sol','sponsor-balance','error'])('rejects invalid/changed finalized %s evidence',async fault=>{
  const f=await fixture();await f.provisioner.acceptFunding();await f.provisioner.assets(f.load);
  const signed=f.store.read('assets-signed.json')!,proof=f.proofs.get(signed.signature)!;
  if(fault==='wire')proof.wire=f.plan.externalFunding[0]!.signature; // malformed bytes
  if(fault==='signature')proof.wire=f.proofs.get(f.plan.externalFunding[0]!.signature)!.wire;
  if(fault==='slot'){const original=f.backend.snapshot;f.backend.snapshot=async(...a)=>({...await original(...a),slot:0n});}
  if(fault==='mint') {const a=f.svm.getAccount(f.plan.mint); if(!a.exists)throw Error();f.svm.setAccount({...a,data:new Uint8Array(1)});}
  if(fault==='browser-sol')f.svm.airdrop(f.plan.browser,lamports(1_000_000n));
  if(fault==='sponsor-balance')f.svm.airdrop(f.plan.sponsor,lamports(1_000_000n));
  if(fault==='error')proof.error={failure:true};
  await expect(f.provisioner.observe('assets')).rejects.toThrow();
  expect(f.counters().sends).toBe(1);
});
test('wrong genesis stops before reservations or faucet calls',async()=>{
  const f=await fixture();f.backend.genesis=async()=>'other-network';
  await expect(f.provisioner.acceptFunding()).rejects.toThrow(/genesis/);
  expect(f.store.read('external-funding-intent.json')).toBeNull();expect(f.counters().requests).toBe(0);
});
test('fee ceiling refusal freezes assets before signing/broadcast',async()=>{
  const f=await fixture();await f.provisioner.acceptFunding();f.backend.fee=async()=>100_001n;
  await expect(f.provisioner.assets(f.load)).rejects.toThrow(/quote/);
  expect(f.store.read('assets-signed.json')).toBeNull();expect(f.counters().sends).toBe(0);
  await expect(f.provisioner.assets(f.load)).rejects.toThrow();
});
test('changed approved browser cannot reuse original funding intent',async()=>{
  const f=await fixture();await f.provisioner.acceptFunding(); const other=await generateKeyPairSigner();
  expect(()=>new E2EProvisioner({...f.plan,browser:other.address},f.store,f.backend,'synthetic-devnet',f.budget)).toThrow(/policy/);
});
test('receipt without funding proof is not a setup prerequisite',async()=>{
  const f=await fixture();await expect(f.provisioner.assets(f.load)).rejects.toThrow(/funding proof/);
  expect(f.counters().signerLoads).toBe(0);
});
test('private store rejects symlinked records and permissive directories',async()=>{
  const f=await fixture();symlinkSync('/dev/null',join(f.directory,'external-funding-intent.json'));
  expect(()=>f.store.read('external-funding-intent.json')).toThrow();
  chmodSync(f.directory,0o755);expect(()=>new ProvisionStore(f.directory)).toThrow();
});
test('entry point requires explicit E2E and rejects legacy profiles and extra input',()=>{
  expect(provisionArguments(['assets','--profile','e2e'])).toBe('assets');
  for(const args of [[],['fund'],['fund','--profile','dev'],['fund','--profile','e2e','--amount','2'],['keys','--profile','e2e']]) expect(()=>provisionArguments(args)).toThrow();
});
test('duplicate roles or wrong application release fail before execution',async()=>{
  const f=await fixture();expect(()=>validatePlan({...f.plan,browser:f.plan.payer})).toThrow();
  expect(()=>validatePlan({...f.plan,applicationRelease:'other'})).toThrow();
});
test('a fabricated funding receipt without original intent/transaction cannot enable setup',async()=>{
  const f=await fixture(); const hash= (await import('node:crypto')).createHash('sha256').update(JSON.stringify(f.plan,null,2)).digest('hex');
  f.store.write('external-funding-receipt.json',{status:'FINALIZED_SUCCEEDED',planHash:hash});
  await expect(f.provisioner.assets(f.load)).rejects.toThrow();expect(f.counters()).toEqual({requests:0,sends:0,signerLoads:0});
});
test('external transfer metadata and duplicate signatures cannot prove funding',async()=>{
 const f=await fixture();f.proofs.get(f.plan.externalFunding[0]!.signature)!.postBalances[1]! += 1n;
 await expect(f.provisioner.acceptFunding()).rejects.toThrow();expect(f.store.read('external-funding-receipt.json')).toBeNull();
 expect(()=>validatePlan({...f.plan,externalFunding:[f.plan.externalFunding[0]!,f.plan.externalFunding[0]!]})).toThrow();
});
test('current balance is separate from proved external funding and cannot reset spending cap',async()=>{
 const f=await fixture();f.svm.airdrop(f.plan.sponsor,lamports(50_000_000n));
 expect(await f.provisioner.acceptFunding()).toMatchObject({provedExternalFunding:'10000000000',currentBalance:{lamports:'10050000000'},spending:{limit:1_000_000_000n}});
 expect(f.counters().requests).toBe(0);expect((()=>{try{return f.store.read('funding-response.json')}catch{return null}})()).toBeNull();
});
test('oversized rent quote freezes setup before signing',async()=>{
  const f=await fixture();await f.provisioner.acceptFunding();f.backend.rent=async()=>500_000_000n;
  await expect(f.provisioner.assets(f.load)).rejects.toThrow();expect(f.counters().sends).toBe(0);expect(f.store.read('assets-signed.json')).toBeNull();
});
test('unexpected mint signer cannot sign or broadcast',async()=>{
  const f=await fixture();await f.provisioner.acceptFunding(); const wrong=await generateKeyPairSigner();
  await expect(f.provisioner.assets(async()=>({...await f.load(),mint:wrong}))).rejects.toThrow(/signer/);
  expect(f.counters().sends).toBe(0);expect(f.store.read('assets-signed.json')).toBeNull();
});
test('missing browser token authority/incorrect amount is not accepted despite finalized transaction',async()=>{
  const f=await fixture();await f.provisioner.acceptFunding();await f.provisioner.assets(f.load);
  const address=await ata(f.plan.browser,f.plan.mint), account=f.svm.getAccount(address);
  if(!account.exists)throw Error();
  const token=getTokenDecoder().decode(account.data);const {getTokenEncoder}=await import('@solana-program/token');
  f.svm.setAccount({...account,data:getTokenEncoder().encode({...token,amount:token.amount-1n})});
  await expect(f.provisioner.observe('assets')).rejects.toThrow(/token account/);expect(f.counters().sends).toBe(1);
});
test.each(['missing-slot','missing-accounts'])('malformed finalized %s snapshot cannot pass',async fault=>{
  const f=await fixture();await f.provisioner.acceptFunding();await f.provisioner.assets(f.load);
  const original=f.backend.snapshot;
  f.backend.snapshot=async(...a)=>{const value=await original(...a);return fault==='missing-slot'?{...value,slot:undefined as unknown as bigint}:{...value,accounts:[]};};
  await expect(f.provisioner.observe('assets')).rejects.toThrow();expect(f.counters().sends).toBe(1);
});
test('budget persistence failure after reserving blocks signing/send and keeps the full UNKNOWN ceiling',async()=>{
 const f=await fixture();await f.provisioner.acceptFunding();const reserve=f.budget.reserve.bind(f.budget);
 f.budget.reserve=(...args)=>{reserve(...args);throw Error('injected post-persist budget fsync failure');};
 await expect(f.provisioner.assets(f.load)).rejects.toThrow(/fsync/);
 expect(f.store.read('assets-signed.json')).toBeNull();expect(f.counters().sends).toBe(0);expect(f.budget.summary().reserved).toBeGreaterThan(10_000_000n);
 await expect(f.provisioner.assets(f.load)).rejects.toThrow();
});
test('read-only assets plan carries both signer identities without loading/signing or reserving',async()=>{
 const f=await fixture();const q=await f.provisioner.quoteAssets();
 expect(getCompiledTransactionMessageDecoder().decode(q.unsigned.messageBytes).header.numSignerAccounts).toBe(2);
 expect(Object.values(q.unsigned.signatures).every(x=>x===null)).toBe(true);
 expect(f.counters()).toEqual({requests:0,sends:0,signerLoads:0});expect(f.budget.summary().reserved).toBe(0n);expect(f.store.read('assets-intent.json')).toBeNull();
});
