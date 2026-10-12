import {afterEach,expect,test} from 'vitest';
import {mkdtempSync,rmSync,readFileSync,writeFileSync,chmodSync,renameSync,openSync,closeSync,symlinkSync} from 'node:fs';
import {createRequire} from 'node:module';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {generateKeyPairSigner,getSignatureFromTransaction,getCompiledTransactionMessageDecoder,lamports,type KeyPairSigner} from '@solana/kit';
import {getTransferSolInstruction} from '@solana-program/system';
import {CampaignBudget,CAMPAIGN_SPEND_LIMIT} from '../src/campaign-budget.ts';
import {messageDigest,type FinalizedTransaction} from '../src/campaign-proof.ts';
import {campaignSponsorship} from '../src/campaign-sponsorship.ts';
import {buildTransaction,encodeTransaction} from '../src/transactions.ts';
const dirs:string[]=[];afterEach(()=>dirs.splice(0).forEach(d=>rmSync(d,{recursive:true,force:true})));
const digest='a'.repeat(64), spend=(fees:bigint,rent=0n,browserAllocation=0n)=>({fees,rent,browserAllocation});
async function fixture(){
 const sponsor=await generateKeyPairSigner(),browser=await generateKeyPairSigner();
 const dir=mkdtempSync(join(tmpdir(),'capture402-budget-'));dirs.push(dir);
 const policy={schema:1 as const,reference:'test-campaign',genesisHash:'synthetic',sponsor:sponsor.address,browser:browser.address,spendLimit:'1000000000' as const};
 CampaignBudget.initialize(dir,policy); const budget=new CampaignBudget(dir,policy);
 return {dir,policy,budget,sponsor,browser,restart:()=>new CampaignBudget(dir,policy)};
}
async function proof(payer:KeyPairSigner,destination:KeyPairSigner,amount:bigint,failed=false){
 const tx=await buildTransaction({feePayer:payer.address,signers:[payer],lifetime:{blockhash:'11111111111111111111111111111111' as any,lastValidBlockHeight:100n},instructions:[getTransferSolInstruction({source:payer,destination:destination.address,amount:lamports(amount)})]});
 const message=getCompiledTransactionMessageDecoder().decode(tx.messageBytes);
 const pre=message.staticAccounts.map(()=>0n);pre[0]=10_000_000_000n;
 const post=[...pre];post[0]!-=5_000n+(failed?0n:amount);if(!failed)post[message.staticAccounts.indexOf(destination.address)]!+=amount;
 return {tx,signature:getSignatureFromTransaction(tx),hash:messageDigest(tx.messageBytes),proof:{slot:10n,wire:encodeTransaction(tx),error:failed?{InstructionError:[0,'Custom']}:null,fee:5_000n,preBalances:pre,postBalances:post} satisfies FinalizedTransaction};
}
test('ten SOL balance cannot expand cap; unresolved reservations survive reconstruction and process death',async()=>{
 const f=await fixture();f.budget.reserve('unknown','sponsorship',digest,spend(600_000_000n));
 expect(f.restart().summary()).toMatchObject({reserved:600_000_000n,available:400_000_000n});
 expect(()=>f.restart().reserve('over','sponsorship',digest,spend(400_000_001n))).toThrow(/exhausted/);
 const worker=join(f.dir,'worker.mjs');
 writeFileSync(worker,`import {CampaignBudget} from ${JSON.stringify(new URL('../src/campaign-budget.ts',import.meta.url).pathname)};new CampaignBudget(${JSON.stringify(f.dir)},${JSON.stringify(f.policy)}).reserve('crashed','sponsorship','${digest}',{fees:100000000n,rent:0n,browserAllocation:0n});process.exit(75);`);
 expect(spawnSync(process.execPath,['--experimental-strip-types',worker]).status).toBe(75);
 expect(f.restart().summary().reserved).toBe(700_000_000n);
 expect(()=>f.restart().reserve('crashed','sponsorship',digest,spend(1n))).toThrow(/original/);
});
test('browser allocation counted once; browser spending uses finalized pool with no global double charge',async()=>{
 const f=await fixture(),p=await proof(f.sponsor,f.browser,10_000_000n);
 f.budget.reserve('assets','assets',p.hash,spend(10_000n,0n,10_000_000n));
 expect(()=>f.budget.reserve('early-browser','browser',digest,spend(1n))).toThrow(/exhausted/);
 await f.budget.finalize('assets',p.signature,p.proof);
 f.budget.reserve('browser-fee','browser',digest,spend(5_000n,100_000n));
 expect(f.restart().summary()).toMatchObject({committed:10_005_000n,reserved:0n,browserCredit:10_000_000n,browserUsed:105_000n,available:989_995_000n});
 expect(()=>f.budget.reserve('browser-over','browser',digest,spend(9_900_001n))).toThrow(/exhausted/);
 await f.budget.finalize('assets',p.signature,p.proof); // same proof is idempotent
 expect(f.budget.summary().committed).toBe(10_005_000n);
});
test('successful original sponsor proof charges fees and rent; finalized failure charges only fee',async()=>{
 for(const failed of [false,true]){
 const f=await fixture(),p=await proof(f.sponsor,f.browser,100_000n,failed);
 f.budget.reserve('original','sponsorship',p.hash,spend(10_000n,100_000n));
 await f.budget.finalize('original',p.signature,p.proof);
 expect(f.restart().summary()).toMatchObject({committed:failed?5_000n:105_000n,reserved:0n});
 expect(()=>f.restart().reserve('original','sponsorship',p.hash,spend(1n))).toThrow(/original/);
 }
});
test.each(['message','payer','fee','delta','signature','allocation'])('inconsistent finalized %s cannot release UNKNOWN ceiling',async fault=>{
 const f=await fixture(),other=await generateKeyPairSigner(),p=await proof(fault==='payer'?other:f.sponsor,fault==='allocation'?other:f.browser,100_000n);
 f.budget.reserve('original',fault==='allocation'?'assets':'sponsorship',fault==='message'?digest:p.hash,spend(10_000n,fault==='allocation'?0n:100_000n,fault==='allocation'?100_000n:0n));
 if(fault==='fee')p.proof.fee=10_001n;
 if(fault==='delta')p.proof.postBalances[0]=9_999_999_999n;
 if(fault==='signature')p.proof.wire=Buffer.from(Buffer.from(p.proof.wire,'base64').map((n,i)=>i===1?n^1:n)).toString('base64');
 await expect(f.budget.finalize('original',p.signature,p.proof)).rejects.toThrow();
 expect(f.restart().summary().reserved).toBe(110_000n);
});
test.each(['missing','corrupt','mode','symlink','policy','lock'])('unsafe %s state blocks admission without initialization or clearing',async fault=>{
 const f=await fixture();f.budget.reserve('held','sponsorship',digest,spend(10n));const state=join(f.dir,'state.json');
 if(fault==='missing')rmSync(state);if(fault==='corrupt')writeFileSync(state,'{');if(fault==='mode')chmodSync(state,0o644);
 if(fault==='symlink'){renameSync(state,state+'.saved');symlinkSync(state+'.saved',state);}
 if(fault==='policy')writeFileSync(join(f.dir,'policy.json'),'{}');
 if(fault==='lock'){renameSync(join(f.dir,'.lock'),join(f.dir,'.old-lock'));writeFileSync(join(f.dir,'.lock'),'replacement',{mode:0o600});}
 expect(()=>f.budget.reserve('new','sponsorship',digest,spend(10n))).toThrow();
 expect(()=>CampaignBudget.initialize(f.dir,f.policy)).toThrow(/existing/);
});
test('native process flock excludes concurrent writers and cannot be replaced in an existing instance',async()=>{
 const f=await fixture(),fsExt=createRequire(import.meta.url)('fs-ext'),fd=openSync(join(f.dir,'.lock'),'r+');
 try{fsExt.flockSync(fd,'exnb');expect(()=>f.budget.reserve('raced','sponsorship',digest,spend(10n))).toThrow();}
 finally{fsExt.flockSync(fd,'un');closeSync(fd);}
 f.budget.reserve('after-lock','sponsorship',digest,spend(10n));expect(f.restart().summary().reserved).toBe(10n);
});
test('sponsorship includes authorize payment/vault rents and retains reservation on missing history',async()=>{
 const f=await fixture(),p=await proof(f.sponsor,f.browser,100n);const sizes:number[]=[];
 const adapter=campaignSponsorship(f.budget,{fee:async()=>5_000n,rent:async(size)=>{sizes.push(size);return 100_000n;},finalized:async()=>null});
 const id=await adapter.reserve(p.tx,'authorize');await adapter.observe(id,p.signature);
 expect(sizes).toEqual([176,165]);expect(f.restart().summary().reserved).toBe(205_000n);
 await expect(adapter.reserve(p.tx,'authorize')).rejects.toThrow(/original/);
});
test('no cap credit for incoming SOL/refunds and no duplicate charge by two logical ids',async()=>{
 const f=await fixture(),p=await proof(f.sponsor,f.browser,100n);
 f.budget.reserve('one','sponsorship',p.hash,spend(5_000n,100n));f.budget.reserve('two','sponsorship',p.hash,spend(5_000n,100n));
 await f.budget.finalize('one',p.signature,p.proof);await expect(f.budget.finalize('two',p.signature,p.proof)).rejects.toThrow(/another/);
 expect(f.budget.summary().reserved).toBe(5_100n);
});
