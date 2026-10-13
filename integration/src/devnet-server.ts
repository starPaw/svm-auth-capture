import { CampaignBudget, type CampaignPolicy } from './campaign-budget.ts';
import { campaignSponsorship } from './campaign-sponsorship.ts';
import { rpcBackend } from '../operators/e2e-provision.ts';
// SAC-006 runnable facilitator entry point for Devnet. Wires `RpcLedger` to the HTTP
// `createGatewayApp` binding using the externally pinned, independently accepted SAC-007
// deployment record (see `deployment-record.ts`) and `SOLANA_RPC_URL`; refuses to start on a
// network/program mismatch or an unaccepted record. Binds to localhost only by default: the
// gateway applies bearer authentication, a merchant/mint allowlist, and a sponsorship
// attempt/balance cap in front of every facilitator route (`gateway.ts`), but it must still
// never be exposed publicly (ARCHITECTURE).
import { existsSync, readFileSync } from "node:fs";
import { serve } from "@hono/node-server";
import { type Address, createKeyPairSignerFromBytes, type KeyPairSigner } from "@solana/kit";
import { ACCEPTED_DEPLOYMENT_RECORD, loadDeploymentRecord } from "./deployment-record.ts";
import { demoSponsorComputeBounds } from "./demo-compute.ts";
import { Facilitator } from "./facilitator.ts";
import { createGatewayApp } from "./gateway.ts";
import { redactRpcUrl, RpcLedger } from "./rpc-ledger.ts";
import { SponsorshipGuard } from "./sponsorship.ts";
import { FileSubmissionJournal } from "./submission-journal.ts";
import { AdmissionJournal } from './admission-journal.ts';
import { requireE2eRuntimeRpc, trustedRuntimeFile } from './e2e-runtime-policy.ts';
import { DevnetFaucetStore, type FaucetPolicy } from './devnet-faucet-store.ts';
import { DevnetFaucet } from './devnet-faucet.ts';
import { ata } from './program.ts';

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`missing required environment variable ${name}`);
  return value;
}

async function loadFeePayer(path: string): Promise<KeyPairSigner> {
  const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (!Array.isArray(parsed) || parsed.length !== 64) {
    throw new Error(`${path} must be a solana-keygen 64-byte secret key JSON array`);
  }
  return createKeyPairSignerFromBytes(new Uint8Array(parsed as number[]));
}

async function main(): Promise<void> {
  const record = loadDeploymentRecord(requireEnv("SAC006_DEPLOYMENT_RECORD_PATH"));
  const rpcUrl = requireEnv("SOLANA_RPC_URL");
  const feePayer = await loadFeePayer(requireEnv("SAC006_FACILITATOR_KEYPAIR_PATH"));
  const e2e = feePayer.address === '5mkvwgKeWMYrFppGm8ugLzQC9Wff4vduqWphsGhQNigX' || requireEnv('SAC006_FACILITATOR_KEYPAIR_PATH').includes('/capture402-e2e/');
  if (e2e) requireE2eRuntimeRpc(rpcUrl,record);

  const ledger = new RpcLedger({ deployment: record, network: record.network.caip2, genesisHash: record.network.genesisHash, rpcUrl, rpcMinIntervalMs:e2e?250:0 });
  await ledger.verifyGenesis();

  // The exact co-signed bytes, signature, and blockhash of every broadcast are written here first.
  const journal = new FileSubmissionJournal(requireEnv("SAC006_FACILITATOR_JOURNAL_DIR"));
  // Binding to the E2E sponsor prevents a missing/renamed environment profile bypass.
  let sponsorBudget, admission, campaignBudget:CampaignBudget|undefined;
  if (e2e) {
    const directory = '/var/lib/capture402-e2e/facilitator/campaign-budget';
    const policy = JSON.parse(readFileSync(`${directory}/policy.json`,'utf8')) as CampaignPolicy;
    if (policy.sponsor !== feePayer.address || policy.browser !== '93PtawNdAfDn7oTjRrbrJJMSgaFTjGS3wjtkrZSNGn74' || policy.genesisHash !== record.network.genesisHash) throw Error('E2E campaign policy/runtime mismatch');
    requireE2eRuntimeRpc(rpcUrl,record);
    campaignBudget=new CampaignBudget(directory,policy);
    sponsorBudget = campaignSponsorship(campaignBudget,rpcBackend(record,rpcUrl));
    admission = new AdmissionJournal(requireEnv('SAC006_E2E_RELAY_ADMISSION_DIR'),'relay-attempts',Number(requireEnv('SAC006_SPONSOR_MAX_ATTEMPTS')));
  }
  const facilitator = new Facilitator({ network: record.network.caip2, programId: record.programId, feePayer, ledger, journal, sponsorBudget, observationKey: requireEnv("SAC006_BEARER_TOKEN"), ...demoSponsorComputeBounds() });
  const sponsorship = new SponsorshipGuard({
    ledger,
    feePayer: feePayer.address,
    maxAttempts: Number(process.env.SAC006_SPONSOR_MAX_ATTEMPTS ?? "50"),
    minLamportsBalance: BigInt(process.env.SAC006_SPONSOR_MIN_LAMPORTS ?? "10000000"), // 0.01 SOL
    admission,
  });
  let faucet:DevnetFaucet|undefined;
  const faucetDirectory='/var/lib/capture402-e2e/facilitator/faucet';
  const faucetPolicyPath=process.env.SAC006_E2E_FAUCET_POLICY_PATH;
  if(e2e && existsSync(faucetDirectory) && !faucetPolicyPath)throw Error('existing faucet custody requires its compatible configured reader');
  if(faucetPolicyPath) {
    if(!e2e || !campaignBudget || !admission || requireEnv('SAC006_SPONSOR_MAX_ATTEMPTS')!=='600')throw Error('faucet is restricted to the reviewed E2E campaign');
    const policy=JSON.parse(trustedRuntimeFile(faucetPolicyPath)) as FaucetPolicy;
    if(policy.sponsor!==feePayer.address || policy.mint!=='91wxVDcTEf5kRRRFmkUKohdNLFRAh5tw9YqWxV8FYvJp' ||
      policy.mint!==requireEnv('SAC006_ALLOWLIST_MINT') || policy.pool!==await ata(feePayer.address,policy.mint) || policy.origin!=='https://e2e.capture402.xyz')throw Error('faucet policy exceeds existing E2E identities');
    const store=new DevnetFaucetStore(faucetDirectory,policy);
    faucet=new DevnetFaucet({store,sponsor:feePayer,ledger,backend:rpcBackend(record,rpcUrl),budget:campaignBudget,admission:sponsorship,
      latest:()=>ledger.latestBlockhash(),challengeKey:requireEnv('SAC006_BEARER_TOKEN'),bearerToken:requireEnv('SAC006_BEARER_TOKEN')});
  }
  const app = createGatewayApp(facilitator, {
    bearerToken: requireEnv("SAC006_BEARER_TOKEN"),
    sponsorship,
    ...(faucet?{faucet}:{}),
    allowlist: {
      merchant: requireEnv("SAC006_ALLOWLIST_MERCHANT") as Address,
      mint: requireEnv("SAC006_ALLOWLIST_MINT") as Address,
    },
  });

  const port = Number(process.env.SAC006_PORT ?? "8787");
  const hostname = process.env.SAC006_HOST ?? "127.0.0.1";
  serve({ fetch: app.fetch, port, hostname }, (info) => {
    console.log(`SAC-006 facilitator listening on http://${hostname}:${info.port}`);
    console.log(`network=${facilitator.network} program=${record.programId} rpc=${e2e ? 'verified-owner-selected-private-provider' : redactRpcUrl(rpcUrl)}`);
    console.log(`deployment record sha256=${record.sha256} (${ACCEPTED_DEPLOYMENT_RECORD.path} at ${ACCEPTED_DEPLOYMENT_RECORD.revision})`);
  });
}

main().catch(() => {
  console.error('Facilitator startup stopped; verify private configuration and accepted Devnet identity.');
  process.exitCode = 1;
});
