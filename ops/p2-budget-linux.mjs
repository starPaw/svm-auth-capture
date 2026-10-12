// Run only in the marked disposable VM after staging the P2 snapshot.
import {readFileSync,mkdtempSync,writeFileSync,openSync,closeSync} from 'node:fs';
import {hostname} from 'node:os';
import {spawnSync} from 'node:child_process';
import {createRequire} from 'node:module';
import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
if(hostname()!=='capture402-p2-disposable'||readFileSync('/etc/capture402-p2-disposable','utf8').trim()!=='DISPOSABLE_SYNTHETIC_P2_TEST_ONLY')throw Error('disposable VM required');
const root=process.argv[2];if(root!=='/opt/capture402-e2e/p2/test')throw Error('fixed fixture snapshot required');
const kit=await import(pathToFileURL(root+'/integration/node_modules/@solana/kit/dist/index.node.mjs'));
const system=await import(pathToFileURL(root+'/integration/node_modules/@solana-program/system/dist/src/index.mjs'));
const {CampaignBudget}=await import(pathToFileURL(root+'/integration/src/campaign-budget.ts'));
const {buildTransaction,encodeTransaction}=await import(pathToFileURL(root+'/integration/src/transactions.ts'));
const {messageDigest}=await import(pathToFileURL(root+'/integration/src/campaign-proof.ts'));
const [sponsor,browser]=await Promise.all([kit.generateKeyPairSigner(),kit.generateKeyPairSigner()]);
const policy={schema:1,reference:'linux-synthetic-journal',genesisHash:'synthetic',sponsor:sponsor.address,browser:browser.address,spendLimit:'1000000000'};
const hash='a'.repeat(64);const tests=[];
function check(name,fn){fn();tests.push({name,result:'PASS'});}
const dir=mkdtempSync('/root/p2-budget-linux-');CampaignBudget.initialize(dir,policy);let budget=new CampaignBudget(dir,policy);
const worker=dir+'/worker.mjs';writeFileSync(worker,`import {CampaignBudget} from '${root}/integration/src/campaign-budget.ts';new CampaignBudget(${JSON.stringify(dir)},${JSON.stringify(policy)}).reserve('killed','sponsorship','${hash}',{fees:500000000n,rent:0n,browserAllocation:0n});process.kill(process.pid,'SIGKILL');`);
const killed=spawnSync(root+'/node/bin/node',['--experimental-strip-types',worker]);
check('SIGKILL releases native process lock but retains durable UNKNOWN ceiling',()=>{assert.equal(killed.signal,'SIGKILL');budget=new CampaignBudget(dir,policy);assert.equal(budget.summary().reserved,500000000n);assert.throws(()=>budget.reserve('over','sponsorship',hash,{fees:500000001n,rent:0n,browserAllocation:0n}));});
const fsExt=createRequire(root+'/integration/src/campaign-budget.ts')('fs-ext'),fd=openSync(dir+'/.lock','r+');
try{fsExt.flockSync(fd,'exnb');check('actual Linux flock blocks a competing budget writer',()=>assert.throws(()=>budget.reserve('raced','sponsorship',hash,{fees:1n,rent:0n,browserAllocation:0n})));}finally{fsExt.flockSync(fd,'un');closeSync(fd);}
const d2=mkdtempSync('/root/p2-budget-finalized-');CampaignBudget.initialize(d2,policy);const b2=new CampaignBudget(d2,policy);
const tx=await buildTransaction({feePayer:sponsor.address,signers:[sponsor],lifetime:{blockhash:'11111111111111111111111111111111',lastValidBlockHeight:100n},instructions:[system.getTransferSolInstruction({source:sponsor,destination:browser.address,amount:kit.lamports(10000000n)})]});
const message=kit.getCompiledTransactionMessageDecoder().decode(tx.messageBytes);const pre=message.staticAccounts.map(()=>0n);pre[0]=10000000000n;const post=[...pre];post[0]-=10005000n;post[message.staticAccounts.indexOf(browser.address)]+=10000000n;
b2.reserve('assets','assets',messageDigest(tx.messageBytes),{fees:10000n,rent:0n,browserAllocation:10000000n});
await b2.finalize('assets',kit.getSignatureFromTransaction(tx),{slot:1n,wire:encodeTransaction(tx),error:null,fee:5000n,preBalances:pre,postBalances:post});
b2.reserve('browser-fee','browser',hash,{fees:5000n,rent:0n,browserAllocation:0n});
check('native finalized signature/metadata charges browser allocation once across restart',()=>{const s=new CampaignBudget(d2,policy).summary();assert.equal(s.committed,10005000n);assert.equal(s.browserUsed,5000n);assert.equal(s.reserved,0n);});
console.log(JSON.stringify({scope:'DISPOSABLE_SYNTHETIC_NATIVE_LINUX_NOT_VPS',tests,counts:{PASS:tests.length,FAIL:0}},null,2));
