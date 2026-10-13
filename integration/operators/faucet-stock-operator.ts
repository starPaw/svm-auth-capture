// Fixed E2E CLI; action approval is checked outside the compartment before credentials.
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { AdmissionJournal } from '../src/admission-journal.ts';
import { CampaignBudget, type CampaignPolicy } from '../src/campaign-budget.ts';
import { loadDeploymentRecord } from '../src/deployment-record.ts';
import { rpcBackend } from './e2e-provision.ts';
import { loadKeypair } from './lib.ts';
import { FaucetStockOperator, STOCK_GENESIS, StockStore, type StockPlan } from './faucet-stock.ts';
const BUDGET = '/var/lib/capture402-e2e/facilitator/campaign-budget';
const ADMISSION = '/var/lib/capture402-e2e/facilitator/b3-admission';
const STOCK = '/var/lib/capture402-e2e/facilitator/faucet-stock-setup';
export function stockArguments(args: string[]) {
  if (args.length !== 3 || !['quote','issue','observe'].includes(args[0]!) || args[1] !== '--profile' || args[2] !== 'e2e') throw Error('expected quote|issue|observe --profile e2e');
  return args[0] as 'quote' | 'issue' | 'observe';
}
export function stockCredentialDirectory(value: unknown): string {
  if (typeof value !== 'string' || !/^\/run\/credentials\/capture402-e2e-stock-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\.service$/.test(value)) throw Error('stock unit credentials required');
  return value;
}
export function validateStockApproval(approved: Record<string,any>, sourceRevision: string, action: string) {
  if (approved.schema !== 1 || approved.sourceRevision !== sourceRevision || !/^[a-f0-9]{40}$/.test(sourceRevision) ||
    approved.sponsor !== '5mkvwgKeWMYrFppGm8ugLzQC9Wff4vduqWphsGhQNigX' ||
    approved.mint !== '91wxVDcTEf5kRRRFmkUKohdNLFRAh5tw9YqWxV8FYvJp' ||
    approved.browser !== '93PtawNdAfDn7oTjRrbrJJMSgaFTjGS3wjtkrZSNGn74' || approved.genesisHash !== STOCK_GENESIS ||
    approved.campaignReference !== 'owner-policy-2026-10-12-existing-10-sol-spend-cap-1-sol' || approved.amount !== '100000000000' ||
    approved.maximumSpend !== '2139280' || approved.admissionMaximum !== 600 || !['quote','issue','observe'].includes(action) ||
    typeof approved.actions?.[action] !== 'string' || !approved.actions[action].trim() ||
    typeof approved.issueApprovalReference !== 'string' || !approved.issueApprovalReference.trim()) throw Error('fixed source/identity/action approval required');
}
const hash = (path: string) => createHash('sha256').update(readFileSync(path)).digest('hex');
export async function stockOperatorMain(args = process.argv.slice(2)) {
  const action = stockArguments(args), directory = stockCredentialDirectory(process.env.CREDENTIALS_DIRECTORY);
  if (process.getuid?.() !== 989 || process.getgid?.() !== 986 || !/^[a-f0-9]{32}$/.test(process.env.INVOCATION_ID ?? '') ||
    !/^CapEff:\s+0+$/m.test(readFileSync('/proc/self/status','utf8'))) throw Error('existing E2E UID/GID and zero-capability unit required');
  const credential = (name: string) => {
    const path = `${directory}/${name}`, s = lstatSync(path);
    if (!s.isFile() || s.isSymbolicLink() || s.nlink !== 1 || s.uid !== 989 || (s.mode & 0o777) !== 0o400) throw Error('unsafe unit credential');
    return path;
  };
  const approved = JSON.parse(readFileSync(credential('stock-approval'),'utf8'));
  const root = realpathSync(new URL('../..',import.meta.url));
  const manifest = JSON.parse(readFileSync(`${root}/snapshot-manifest.json`,'utf8'));
  validateStockApproval(approved,manifest.sourceRevision,action);
  if (approved.snapshotPath !== root || approved.snapshotManifestSha256 !== hash(`${root}/snapshot-manifest.json`)) throw Error('approved snapshot identity mismatch');
  const policy = JSON.parse(readFileSync(`${BUDGET}/policy.json`,'utf8')) as CampaignPolicy;
  if (hash(`${BUDGET}/policy.json`) !== approved.budgetPolicySha256 || hash(`${ADMISSION}/policy.json`) !== approved.admissionPolicySha256) throw Error('existing policy approval drift');
  const budget = new CampaignBudget(BUDGET,policy), admission = new AdmissionJournal(ADMISSION,'relay-attempts',600);
  const plan: StockPlan = {schema:1,sourceRevision:approved.sourceRevision,approvalReference:approved.issueApprovalReference,
    campaignReference:approved.campaignReference,sponsor:approved.sponsor,mint:approved.mint,browser:approved.browser,genesisHash:STOCK_GENESIS};
  const record = loadDeploymentRecord(`${root}/docs/evidence/sac-007/deployment-identity.v1.json`);
  const operator = new FaucetStockOperator(plan,new StockStore(STOCK),rpcBackend(record),budget,admission);
  if (action === 'quote') {
    const q = await operator.quote();
    return {status:'UNSIGNED_PLAN_ONLY',sourceRevision:plan.sourceRevision,pool:q.pool,preSlot:q.preSlot,supplyBefore:q.supplyBefore,
      amount:'100000000000',fee:q.fee,rent:q.rent,reservationCeiling:q.ceiling,maximumSpend:'2139280',spending:budget.summary(),admission:admission.summary().used};
  }
  if (action === 'observe') return operator.observe();
  return operator.issue(async()=>({sponsor:await loadKeypair(credential('sponsor-key')),mint:await loadKeypair(credential('mint-key'))}));
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) stockOperatorMain()
  .then(result=>{console.log(JSON.stringify(result,(_k,v)=>typeof v==='bigint'?String(v):v));if ('status' in result && result.status!=='UNSIGNED_PLAN_ONLY' && result.status!=='FINALIZED_SUCCEEDED') process.exitCode=2;})
  .catch(()=>{console.error('E2E stock operator stopped. Preserve original records, reservations and counters; observe only, never repeat issuance.');process.exitCode=1;});
