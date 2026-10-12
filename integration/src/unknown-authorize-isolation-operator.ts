// Selected E2E operator only; no signer, economic submission or outcome repair.
import { execFileSync } from 'node:child_process';
import { readFileSync,existsSync,chownSync,chmodSync,openSync,closeSync,fsyncSync,constants } from 'node:fs';
import { fileURLToPath,pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { loadDeploymentRecord } from './deployment-record.ts';
import { requireE2eRuntimeRpc,trustedRuntimeFile } from './e2e-runtime-policy.ts';
import { RpcLedger } from './rpc-ledger.ts';
import { PENDING_A_ISOLATION,prepareUnknownAuthorizeIsolation,persistUnknownAuthorizeIsolation } from './unknown-authorize-isolation.ts';
import { sha256 } from './authorize-abandon.ts';
function fail():never{throw Error('Selected E2E isolation operator refused; originals and reserves preserved.');}
function envfile(role:string) {
  return Object.fromEntries(trustedRuntimeFile(`/etc/capture402-e2e/${role}.env`).split('\n').filter(l=>l && !l.startsWith('#') && l.includes('='))
    .map(l=>{const at=l.indexOf('=');return[l.slice(0,at),l.slice(at+1).trim().replace(/^(['"])(.*)\1$/,'$2')];}));
}
export async function isolationOperatorMain(argv=process.argv.slice(2)) {
  if(process.geteuid?.()!==0 || argv.length!==1 || !['prepare','apply'].includes(argv[0]!))fail();
  const restaurant=envfile('restaurant'),facilitator=envfile('facilitator');
  if(restaurant.SOLANA_RPC_URL!==facilitator.SOLANA_RPC_URL || restaurant.SAC006_STORE_DIR!=='/var/lib/capture402-e2e/restaurant/operation-store' ||
    !facilitator.SAC006_FACILITATOR_JOURNAL_DIR?.startsWith('/var/lib/capture402-e2e/facilitator/'))fail();
  if(argv[0]==='apply')for(const unit of ['capture402-e2e-restaurant.service','capture402-e2e-facilitator.service']) {
    const state=Object.fromEntries(execFileSync('systemctl',['show',unit,'--property=MainPID,ActiveState'],{encoding:'utf8'}).trim().split('\n').map(l=>l.split('=')));
    if(state.MainPID!=='0' || !['inactive','failed'].includes(state.ActiveState!))fail();
    const group=`/sys/fs/cgroup/system.slice/${unit}/cgroup.procs`;if(existsSync(group) && readFileSync(group,'utf8').trim())fail();
  }
  const deployment=loadDeploymentRecord(fileURLToPath(new URL('../../docs/evidence/sac-007/deployment-identity.v1.json',import.meta.url)));
  if(deployment.deployment.executableSha256!=='adee4e8f51fbc52b046c4d5a846c63ecdb63d392b1d16b559d3f6c2984b27415')fail();
  process.env.SAC006_E2E_RPC_POLICY_PATH=restaurant.SAC006_E2E_RPC_POLICY_PATH;
  requireE2eRuntimeRpc(restaurant.SOLANA_RPC_URL!,deployment);
  const ledger=new RpcLedger({deployment,network:deployment.network.caip2,genesisHash:deployment.network.genesisHash,rpcUrl:restaurant.SOLANA_RPC_URL!,rpcMinIntervalMs:250});
  await ledger.verifyGenesis();
  const record=await prepareUnknownAuthorizeIsolation({policy:PENDING_A_ISOLATION,ordersDir:`${restaurant.SAC006_STORE_DIR}-restaurant`,
    journalDirs:[facilitator.SAC006_FACILITATOR_JOURNAL_DIR!,restaurant.SAC006_RECLAIM_JOURNAL_DIR ?? `${restaurant.SAC006_STORE_DIR}-restaurant-reclaim`],
    programId:deployment.programId,network:deployment.network.caip2,server:'CbSG1T25CHcKqPGgu5nrd2b62yVdXMp2GK6UhWYocA1t' as never,
    mint:restaurant.SAC006_ASSET_MINT as never,funder:restaurant.SAC006_FEE_PAYER as never,reader:ledger.recoveryReader(Date.now()+30_000)});
  // Merchant address is public; never load its signing key to derive it here.
  if(argv[0]==='prepare')return{readOnly:true,proposalSha256:sha256(JSON.stringify(record)),proof:record.proof,originalOutcome:'unknown',reserveRetained:true};
  const path=`${restaurant.SAC006_STORE_DIR}-restaurant/${PENDING_A_ISOLATION.order}.json`,archiveSha256=persistUnknownAuthorizeIsolation(PENDING_A_ISOLATION,path,record);
  const file=`${path}.authorize-isolation.lock`;chownSync(file,988,986);chmodSync(file,0o400);
  const fd=openSync(file,constants.O_RDONLY|constants.O_NOFOLLOW);try{fsyncSync(fd);}finally{closeSync(fd);}
  return{archiveSha256,proof:record.proof,originalOutcome:'unknown',reserveRetained:true};
}
if(process.argv[1] && import.meta.url===pathToFileURL(resolve(process.argv[1])).href)isolationOperatorMain()
  .then(r=>console.log(JSON.stringify(r))).catch(()=>{console.error('Selected E2E isolation operator stopped; no original outcome or reserve was repaired.');process.exitCode=1;});
