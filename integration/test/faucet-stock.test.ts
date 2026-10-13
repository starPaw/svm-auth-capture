import { afterEach, expect, test } from 'vitest';
import { chmodSync, linkSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { generateKeyPairSigner, getCompiledTransactionMessageDecoder, getSignatureFromTransaction, lamports, type Transaction } from '@solana/kit';
import { getCreateAccountInstruction } from '@solana-program/system';
import { getCreateAssociatedTokenIdempotentInstruction, getInitializeMint2Instruction, getMintDecoder, getMintToInstruction, getTokenDecoder, getTokenEncoder } from '@solana-program/token';
import { FailedTransactionMetadata, LiteSVM } from 'litesvm';
import { FaucetStockOperator, STOCK_AMOUNT, STOCK_GENESIS, StockStore, type StockPlan } from '../operators/faucet-stock.ts';
import { stockArguments, stockCredentialDirectory, validateStockApproval, validateStockCredential } from '../operators/faucet-stock-operator.ts';
import { AdmissionJournal } from '../src/admission-journal.ts';
import { CampaignBudget } from '../src/campaign-budget.ts';
import type { FinalizedTransaction } from '../src/campaign-proof.ts';
import { ata, TOKEN_PROGRAM_ADDRESS } from '../src/program.ts';
import { buildTransaction, encodeTransaction } from '../src/transactions.ts';
import type { ProvisionBackend } from '../operators/e2e-provisioning.ts';
const directories: string[] = [];
afterEach(()=>directories.splice(0).forEach(d=>rmSync(d,{recursive:true,force:true})));
async function fixture() {
  const [sponsor,mint,browser] = await Promise.all(Array.from({length:3},()=>generateKeyPairSigner()));
  const svm = new LiteSVM(); svm.airdrop(sponsor!.address,lamports(10_000_000_000n));
  const browserAta = await ata(browser!.address,mint!.address);
  const initial = await buildTransaction({feePayer:sponsor!.address,signers:[sponsor!,mint!],lifetime:{blockhash:svm.latestBlockhash(),lastValidBlockHeight:1000n},instructions:[
    getCreateAccountInstruction({payer:sponsor!,newAccount:mint!,lamports:svm.minimumBalanceForRentExemption(82n),space:82n,programAddress:TOKEN_PROGRAM_ADDRESS}),
    getInitializeMint2Instruction({mint:mint!.address,decimals:6,mintAuthority:mint!.address,freezeAuthority:null}),
    getCreateAssociatedTokenIdempotentInstruction({payer:sponsor!,owner:browser!.address,mint:mint!.address,ata:browserAta}),
    getMintToInstruction({mint:mint!.address,token:browserAta,mintAuthority:mint!,amount:600_000_000n}),
  ]});
  const setup = svm.sendTransaction(initial);if (setup instanceof FailedTransactionMetadata) throw Error(setup.toString());svm.expireBlockhash();
  const directory = mkdtempSync(join(tmpdir(),'capture402-stock-'));directories.push(directory);
  const budgetDir = join(directory,'budget'),admissionDir = join(directory,'admission'),storeDir = join(directory,'stock');
  for (const p of [budgetDir,admissionDir,storeDir]) mkdirSync(p,{mode:0o700});
  const plan: StockPlan = {schema:1,sourceRevision:'a'.repeat(40),approvalReference:'specific-stock-approval',campaignReference:'test-campaign',
    sponsor:sponsor!.address,mint:mint!.address,browser:browser!.address,genesisHash:STOCK_GENESIS};
  const policy = {schema:1 as const,reference:plan.campaignReference,sponsor:plan.sponsor,browser:plan.browser,genesisHash:STOCK_GENESIS,spendLimit:'1000000000' as const};
  CampaignBudget.initialize(budgetDir,policy);const budget = new CampaignBudget(budgetDir,policy);
  AdmissionJournal.initialize(admissionDir,{schema:1,kind:'relay-attempts',reference:'synthetic-stock',maximum:600,carryForward:43,historicalActual:null,sourceSha256:'b'.repeat(64)});
  const admission = new AdmissionJournal(admissionDir,'relay-attempts',600), store = new StockStore(storeDir);
  const proofs = new Map<string,FinalizedTransaction>();let sends = 0,loads = 0;
  const backend: ProvisionBackend = {
    async genesis() {return STOCK_GENESIS;},
    async snapshot(addresses,minSlot=0n) {return {slot:minSlot+1n,accounts:addresses.map(address=>{const a=svm.getAccount(address);return a.exists?{owner:a.programAddress,data:new Uint8Array(a.data),lamports:a.lamports,executable:a.executable}:null;})};},
    async rent(size) {return svm.minimumBalanceForRentExemption(BigInt(size));},
    async latest() {return {blockhash:svm.latestBlockhash(),lastValidBlockHeight:1000n};},
    async fee() {return 10_000n;},
    async submit(tx) {
      sends++;const message = getCompiledTransactionMessageDecoder().decode(tx.messageBytes);
      const balances = ()=>message.staticAccounts.map(address=>{const a=svm.getAccount(address);return a.exists?a.lamports:0n;});
      const preBalances = balances(),result = svm.sendTransaction(tx),postBalances = balances();
      const failed = result instanceof FailedTransactionMetadata;
      const fee = preBalances[0]!-postBalances[0]!-(failed?0n:svm.minimumBalanceForRentExemption(165n));
      proofs.set(getSignatureFromTransaction(tx),{slot:50n,wire:encodeTransaction(tx),error:failed?{error:result.toString()}:null,fee,preBalances,postBalances});
      return failed?{kind:'submitted',outcome:{status:'failed',commitment:'finalized',error:'synthetic execution failure',logs:[]}}:
        {kind:'submitted',outcome:{status:'succeeded',commitment:'finalized'}};
    },
    async finalized(signature) {return proofs.get(signature)??null;},
  };
  const operator = new FaucetStockOperator(plan,store,backend,budget,admission);
  const load = async()=>{loads++;return {sponsor:sponsor!,mint:mint!};};
  return {plan,operator,store,backend,budget,admission,proofs,svm,sponsor:sponsor!,mint:mint!,load,directory,storeDir,budgetDir,admissionDir,browserAta,counters:()=>({sends,loads})};
}
test('unsigned stock quote preserves all native/history files and requires exactly two signers',async()=>{
  const f=await fixture();f.budget.reserve('historical-unknown','sponsorship','f'.repeat(64),{fees:100_000n,rent:2_949_760n,browserAllocation:0n});
  const before = [f.budgetDir,f.admissionDir].map(d=>readFileSync(join(d,'state.json')));
  const q = await f.operator.quote(),message = getCompiledTransactionMessageDecoder().decode(q.unsigned.messageBytes);
  if(message.version!=='legacy')throw Error('expected legacy stock');
  expect(message.header.numSignerAccounts).toBe(2);expect(message.instructions).toHaveLength(2);
  expect(Object.values(q.unsigned.signatures).every(s=>s===null)).toBe(true);
  expect(f.counters()).toEqual({sends:0,loads:0});expect(f.store.read('intent')).toBeNull();
  expect([f.budgetDir,f.admissionDir].map(d=>readFileSync(join(d,'state.json')))).toEqual(before);
  expect(f.budget.summary().reserved).toBe(3_049_760n);
});
test('real classic SPL execution adds exactly 100,000 tokens to sponsor stock, preserving browser funds and original UNKNOWN reserve',async()=>{
  const f=await fixture();f.budget.reserve('historical-unknown','sponsorship','f'.repeat(64),{fees:100_000n,rent:2_949_760n,browserAllocation:0n});
  const budgetLock=statSync(join(f.budgetDir,'.lock')).ino,admissionLock=statSync(join(f.admissionDir,'.lock')).ino;
  expect(await f.operator.issue(f.load)).toMatchObject({status:'FINALIZED_SUCCEEDED',minted:String(STOCK_AMOUNT)});
  const pool=f.svm.getAccount(await ata(f.plan.sponsor,f.plan.mint)),mint=f.svm.getAccount(f.plan.mint),browser=f.svm.getAccount(f.browserAta);
  if (!pool.exists || !mint.exists || !browser.exists)throw Error('missing initialized account');
  expect(getTokenDecoder().decode(pool.data).amount).toBe(STOCK_AMOUNT);expect(getMintDecoder().decode(mint.data).supply).toBe(600_000_000n+STOCK_AMOUNT);
  expect(getTokenDecoder().decode(browser.data).amount).toBe(600_000_000n);expect(f.admission.summary().used).toBe(44);
  expect(f.budget.summary()).toMatchObject({reserved:3_049_760n,committed:f.svm.minimumBalanceForRentExemption(165n)+10_000n});
  expect(f.counters()).toEqual({sends:1,loads:1});
  expect([statSync(join(f.budgetDir,'.lock')).ino,statSync(join(f.admissionDir,'.lock')).ino]).toEqual([budgetLock,admissionLock]);
  expect(statSync(join(f.budgetDir,'state.json')).uid).toBe(statSync(f.budgetDir).uid);
});
test('concurrent callers and restart preserve one logical stock intent, one load and one submission',async()=>{
  const f=await fixture(),results=await Promise.allSettled([f.operator.issue(f.load),f.operator.issue(f.load)]);
  expect(results.filter(r=>r.status==='fulfilled')).toHaveLength(1);
  const original=readFileSync(join(f.storeDir,'signed.json'));
  const restarted=new FaucetStockOperator(f.plan,new StockStore(f.storeDir),f.backend,f.budget,f.admission);
  await expect(restarted.issue(f.load)).rejects.toThrow();
  expect(await restarted.observe()).toMatchObject({status:'FINALIZED_SUCCEEDED'});
  expect(readFileSync(join(f.storeDir,'signed.json'))).toEqual(original);expect(f.counters()).toEqual({sends:1,loads:1});
});
test.each(['intent','signed','broadcast'] as const)('failed durable %s flush never submits and blocks every successor',async name=>{
  const f=await fixture(),write=f.store.write.bind(f.store);f.store.write=(n,v)=>{write(n,v);if(n===name)throw Error('injected post-write fsync failure');};
  await expect(f.operator.issue(f.load)).rejects.toThrow();expect(f.counters().sends).toBe(0);
  if(name==='intent')expect(f.counters().loads).toBe(0);
  f.store.write=write;await expect(f.operator.issue(f.load)).rejects.toThrow();expect(f.counters().sends).toBe(0);
});
test.each(['budget','admission','signer'])('failed %s step retains intent and reservations before any broadcast',async fault=>{
  const f=await fixture();
  if(fault==='budget'){const reserve=f.budget.reserve.bind(f.budget);f.budget.reserve=(...a)=>{reserve(...a);throw Error('budget fsync');};}
  if(fault==='admission'){const reserve=f.admission.reserve.bind(f.admission);f.admission.reserve=()=>{reserve();throw Error('admission fsync');};}
  await expect(f.operator.issue(fault==='signer'?async()=>{throw Error('signer unavailable');}:f.load)).rejects.toThrow();
  expect(f.store.read('intent')).not.toBeNull();expect(f.budget.summary().reserved).toBe(2_139_280n);
  expect(f.counters()).toEqual({sends:0,loads:0});await expect(f.operator.issue(f.load)).rejects.toThrow();
});
test('lost response observes only original finalized bytes and cannot replenish stock',async()=>{
  const f=await fixture(),submit=f.backend.submit;f.backend.submit=async tx=>{await submit(tx);throw Error('response lost');};
  await expect(f.operator.issue(f.load)).rejects.toThrow(/lost/);expect(f.budget.summary().reserved).toBe(2_139_280n);
  expect(await f.operator.observe()).toMatchObject({status:'FINALIZED_SUCCEEDED'});await expect(f.operator.issue(f.load)).rejects.toThrow();
  expect(f.counters()).toEqual({sends:1,loads:1});expect(f.admission.summary().used).toBe(44);
});
test('missing original finalized history retains the full ceiling and single consumed admission',async()=>{
  const f=await fixture();f.backend.finalized=async()=>null;
  expect(await f.operator.issue(f.load)).toMatchObject({status:'UNKNOWN'});expect(await f.operator.observe()).toMatchObject({status:'UNKNOWN'});
  expect(f.budget.summary().reserved).toBe(2_139_280n);expect(f.admission.summary().used).toBe(44);
  await expect(f.operator.issue(f.load)).rejects.toThrow();expect(f.counters()).toEqual({sends:1,loads:1});
});
test('no retained signed original stays UNKNOWN and never reloads credentials',async()=>{
  const f=await fixture();await expect(f.operator.issue(async()=>{throw Error('crash before key access');})).rejects.toThrow();
  expect(await f.operator.observe()).toMatchObject({status:'UNKNOWN'});await expect(f.operator.issue(f.load)).rejects.toThrow();
  expect(f.counters()).toEqual({sends:0,loads:0});expect(f.budget.summary().reserved).toBe(2_139_280n);
});
test.each(['genesis','rent','fee','admission','budget','pool','authority','wrong-signer'])('refuses %s before submission',async fault=>{
  const f=await fixture();let load=f.load;
  if(fault==='genesis')f.backend.genesis=async()=>'foreign-genesis';
  if(fault==='rent')f.backend.rent=async()=>2_039_281n;
  if(fault==='fee')f.backend.fee=async()=>100_001n;
  if(fault==='admission')for(let i=43;i<600;i++)f.admission.reserve();
  if(fault==='budget')f.budget.reserve('full','sponsorship','b'.repeat(64),{fees:1_000_000_000n,rent:0n,browserAllocation:0n});
  if(fault==='pool'){const q=await f.operator.quote();const browser=f.svm.getAccount(f.browserAta);if(!browser.exists)throw Error();f.svm.setAccount({...browser,address:q.pool});}
  if(fault==='authority'){const a=f.svm.getAccount(f.plan.mint);if(!a.exists)throw Error();const {getMintEncoder}=await import('@solana-program/token');f.svm.setAccount({...a,data:getMintEncoder().encode({...getMintDecoder().decode(a.data),mintAuthority:null})});}
  if(fault==='wrong-signer'){const other=await generateKeyPairSigner();load=async()=>({...await f.load(),mint:other});}
  await expect(f.operator.issue(load)).rejects.toThrow();expect(f.counters().sends).toBe(0);
  if(fault!=='wrong-signer')expect(f.counters().loads).toBe(0);
});
test.each(['wire','delta','slot','pool-amount','message'])('rejects mismatched original finalized %s and retains reserve',async fault=>{
  const f=await fixture();const finalized=f.backend.finalized;f.backend.finalized=async()=>null;await f.operator.issue(f.load);f.backend.finalized=finalized;
  const original=f.store.read('signed')!,proof=f.proofs.get(original.signature)!;
  if(fault==='wire')proof.wire=proof.wire.slice(0,-4)+'AAAA';
  if(fault==='delta')proof.postBalances[0]!-=1n;
  if(fault==='slot'){const snapshot=f.backend.snapshot;f.backend.snapshot=async(...a)=>({...await snapshot(...a),slot:0n});}
  if(fault==='pool-amount'){const a=f.svm.getAccount(await ata(f.plan.sponsor,f.plan.mint));if(!a.exists)throw Error();f.svm.setAccount({...a,data:getTokenEncoder().encode({...getTokenDecoder().decode(a.data),amount:1n})});}
  if(fault==='message'){const intent=f.store.read('intent')!;intent.messageHash='0'.repeat(64);writeFileSync(join(f.storeDir,'intent.json'),JSON.stringify(intent));}
  await expect(f.operator.observe()).rejects.toThrow();expect(f.budget.summary().reserved).toBe(2_139_280n);expect(f.counters().sends).toBe(1);
});
test('finalized failure charges only original fee, retains used admission and forbids replacement',async()=>{
  const f=await fixture(),submit=f.backend.submit;
  f.backend.submit=async tx=>{const account=f.svm.getAccount(f.plan.mint);if(!account.exists)throw Error();
    const {getMintEncoder}=await import('@solana-program/token');
    f.svm.setAccount({...account,data:getMintEncoder().encode({...getMintDecoder().decode(account.data),mintAuthority:null})});return submit(tx);};
  expect(await f.operator.issue(f.load)).toMatchObject({status:'FINALIZED_FAILED',minted:'0'});
  expect(f.budget.summary()).toMatchObject({reserved:0n,committed:10_000n});expect(f.admission.summary().used).toBe(44);
  expect(f.svm.getAccount(await ata(f.plan.sponsor,f.plan.mint)).exists).toBe(false);
  await expect(f.operator.issue(f.load)).rejects.toThrow();expect(f.counters().sends).toBe(1);
});
test('source revision drift cannot reinterpret a retained stock original',async()=>{
  const f=await fixture();await f.operator.issue(f.load);
  const changed=new FaucetStockOperator({...f.plan,sourceRevision:'c'.repeat(40)},f.store,f.backend,f.budget,f.admission);
  await expect(changed.observe()).rejects.toThrow(/source-bound/);await expect(changed.issue(f.load)).rejects.toThrow();
});
async function workerInput(f:Awaited<ReturnType<typeof fixture>>) {
  const snapshot=await f.backend.snapshot([f.plan.sponsor,f.plan.mint,await ata(f.plan.sponsor,f.plan.mint)]);
  writeFileSync(join(f.directory,'worker-input.json'),JSON.stringify({plan:f.plan,budgetPolicy:f.budget.policy,lifetime:await f.backend.latest(),
    accounts:snapshot.accounts.map(a=>a?{...a,data:Array.from(a.data)}:null)},(_k,v)=>typeof v==='bigint'?String(v):v),{mode:0o600});
}
function stockWorker(directory:string,mode='stop') {
  const child=spawn(process.execPath,['--experimental-strip-types',new URL('./fixtures/faucet-stock-worker.ts',import.meta.url).pathname,directory,mode],{stdio:['ignore','pipe','pipe']});
  let diagnostic='';child.stderr?.on('data',chunk=>{diagnostic+=String(chunk);});
  return Object.assign(child,{diagnostic:()=>diagnostic});
}
test('separate OS processes consume exactly one stock admission before signer access',async()=>{
  const f=await fixture();await workerInput(f);
  const workers=[stockWorker(f.directory),stockWorker(f.directory)];await Promise.all(workers.map(p=>once(p,'exit')));
  expect(workers.some(p=>p.exitCode===2),workers.map(p=>p.diagnostic()).join('\n')).toBe(true);
  expect(f.admission.summary().used).toBe(44);expect(f.budget.summary().reserved).toBe(2_139_280n);
  expect(readFileSync(join(f.directory,'signer-access.json'),'utf8')).toBe('SYNTHETIC_NO_KEY_ACCESS');
  expect(await f.operator.observe()).toMatchObject({status:'UNKNOWN'});
});
test('SIGKILL after durable budget/admission consumes the action forever without a signed original',async()=>{
  const f=await fixture();await workerInput(f);const worker=stockWorker(f.directory,'wait');
  try {
    const first=await Promise.race([once(worker.stdout!,'data'),once(worker,'exit').then(()=>{throw Error('worker exited before signer boundary: '+worker.diagnostic());})]);
    expect(String(first[0])).toContain('BEFORE_SIGNER');
    const exited=once(worker,'exit');worker.kill('SIGKILL');await exited;
  } finally {worker.kill('SIGKILL');}
  await expect(f.operator.issue(f.load)).rejects.toThrow();expect(await f.operator.observe()).toMatchObject({status:'UNKNOWN'});
  expect(f.admission.summary().used).toBe(44);expect(f.budget.summary().reserved).toBe(2_139_280n);expect(f.counters()).toEqual({sends:0,loads:0});
},15_000);
test('symlink, hardlink, permissive record and replaced store directory fail closed',async()=>{
  const f=await fixture();symlinkSync('/dev/null',join(f.storeDir,'intent.json'));expect(()=>f.store.read('intent')).toThrow();rmSync(join(f.storeDir,'intent.json'));
  f.store.write('intent',{});linkSync(join(f.storeDir,'intent.json'),join(f.directory,'hardlink'));expect(()=>f.store.read('intent')).toThrow();rmSync(join(f.directory,'hardlink'));
  chmodSync(join(f.storeDir,'intent.json'),0o644);expect(()=>f.store.read('intent')).toThrow();
  renameSync(f.storeDir,f.storeDir+'-old');mkdirSync(f.storeDir,{mode:0o700});expect(()=>f.store.read('intent')).toThrow(/custody/);
});
test('stock CLI rejects implicit profiles, amounts, retries and foreign credential units',()=>{
  expect(stockArguments(['quote','--profile','e2e'])).toBe('quote');
  for(const args of [[],['issue'],['issue','--profile','dev'],['issue','--profile','e2e','--amount','1'],['retry','--profile','e2e']])expect(()=>stockArguments(args)).toThrow();
  const path='/run/credentials/capture402-e2e-stock-57070b79-1663-4cff-b39b-12c5c765a625.service';expect(stockCredentialDirectory(path)).toBe(path);
  for(const value of [undefined,path.replace('.service',''),path+'/../keys',path.replace('stock','p2'),path+'\n'])expect(()=>stockCredentialDirectory(value)).toThrow();
});
test.each(['amount','maximumSpend','sponsor','sourceRevision','actions'])('stock action approval rejects changed %s before key access',field=>{
  const source='a'.repeat(40),a:Record<string,any>={schema:1,sourceRevision:source,sponsor:'5mkvwgKeWMYrFppGm8ugLzQC9Wff4vduqWphsGhQNigX',mint:'91wxVDcTEf5kRRRFmkUKohdNLFRAh5tw9YqWxV8FYvJp',browser:'93PtawNdAfDn7oTjRrbrJJMSgaFTjGS3wjtkrZSNGn74',genesisHash:STOCK_GENESIS,campaignReference:'owner-policy-2026-10-12-existing-10-sol-spend-cap-1-sol',amount:'100000000000',maximumSpend:'2139280',admissionMaximum:600,issueApprovalReference:'specific-stock-consent',actions:{issue:'specific-action'}};
  expect(()=>validateStockApproval(a,source,'issue')).not.toThrow();a[field]=field==='actions'?{quote:'quote-only'}:'changed';expect(()=>validateStockApproval(a,source,'issue')).toThrow();
});
test('accepts actual systemd255 root-owned read-only ACL credential and rejects writable/foreign custody',()=>{
  const actual={isFile:()=>true,isSymbolicLink:()=>false,nlink:1,uid:0,gid:0,mode:0o440};
  expect(()=>validateStockCredential(actual)).not.toThrow();
  expect(()=>validateStockCredential({...actual,uid:989,gid:986,mode:0o400})).not.toThrow();
  for(const change of [{mode:0o640},{mode:0o444},{uid:988},{gid:986},{nlink:2},{isSymbolicLink:()=>true}])expect(()=>validateStockCredential({...actual,...change})).toThrow();
});
