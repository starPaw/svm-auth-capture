// Synthetic process/crash boundary; deliberately never loads or signs any key.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { StockStore, FaucetStockOperator } from '../../operators/faucet-stock.ts';
import { CampaignBudget } from '../../src/campaign-budget.ts';
import { AdmissionJournal } from '../../src/admission-journal.ts';
import { createDurableFile } from '../../src/durable-file.ts';
import type { ProvisionBackend } from '../../operators/e2e-provisioning.ts';
const directory=process.argv[2]!,input=JSON.parse(readFileSync(join(directory,'worker-input.json'),'utf8'));
const backend:ProvisionBackend={
  async genesis(){return input.plan.genesisHash;},
  async snapshot(){return {slot:1n,accounts:input.accounts.map((a:any)=>a?{...a,lamports:BigInt(a.lamports),data:new Uint8Array(a.data)}:null)};},
  async rent(){return 2_039_280n;},async fee(){return 10_000n;},
  async latest(){return {...input.lifetime,lastValidBlockHeight:BigInt(input.lifetime.lastValidBlockHeight)};},
  async finalized(){return null;},async submit(){throw Error('synthetic worker must not submit');},
};
const budget=new CampaignBudget(join(directory,'budget'),input.budgetPolicy);
const admission=new AdmissionJournal(join(directory,'admission'),'relay-attempts',600);
const operator=new FaucetStockOperator(input.plan,new StockStore(join(directory,'stock')),backend,budget,admission);
await operator.issue(async()=>{
  createDurableFile(join(directory,'signer-access.json'),'SYNTHETIC_NO_KEY_ACCESS');
  process.stdout.write('BEFORE_SIGNER\n');
  if(process.argv[3]==='wait')await new Promise(()=>{setInterval(()=>{},1000);});
  throw Error('synthetic stop before signer');
}).catch(()=>{process.exitCode=2;});
