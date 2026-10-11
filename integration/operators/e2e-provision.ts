// Separate operator entry point: never defaults to historical dev, never starts services.
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname } from 'node:path';
import { createSolanaRpc, getBase64Decoder, getBase64Encoder, isAddress, isSignature, lamports, type Signature } from '@solana/kit';
import { loadDeploymentRecord } from '../src/deployment-record.ts';
import { RpcLedger } from '../src/rpc-ledger.ts';
import { loadKeypair } from './lib.ts';
import { E2E_APPLICATION_RELEASE, E2EProvisioner, ProvisionStore, validatePlan, type ProvisionBackend, type ProvisionPlan } from './e2e-provisioning.ts';
const PRIVATE = '/etc/capture402-e2e';
const SETUP = '/var/lib/capture402-e2e/setup';
const RELEASE = `/opt/capture402-e2e/releases/${E2E_APPLICATION_RELEASE}`;
const RPC = 'https://api.devnet.solana.com';
export function provisionArguments(args: string[]) {
  if (args.length !== 3 || args[1] !== '--profile' || args[2] !== 'e2e' || !['fund', 'assets', 'observe-funding', 'observe-assets'].includes(args[0]!)) throw Error('expected fund|assets|observe-funding|observe-assets --profile e2e');
  return args[0] as 'fund' | 'assets' | 'observe-funding' | 'observe-assets';
}
function protectedPath(path: string, mode?: number): void {
  let current = path;
  for (;;) {
    const s = lstatSync(current);
    if (s.isSymbolicLink() || s.uid !== 0 || (s.mode & 0o022) || (!s.isFile() && !s.isDirectory())) throw Error('untrusted operator input ancestry');
    if (current === path && (mode !== undefined && (s.mode & 0o777) !== mode || s.isFile() && s.nlink !== 1)) throw Error('unsafe operator input metadata');
    if (dirname(current) === current) break;
    current = dirname(current);
  }
}
const digest = (path: string) => createHash('sha256').update(readFileSync(path)).digest('hex');
export function rpcBackend(record: ReturnType<typeof loadDeploymentRecord>): ProvisionBackend {
  const rpc = createSolanaRpc(RPC);
  const ledger = new RpcLedger({ deployment: record, network: record.network.caip2, genesisHash: record.network.genesisHash, rpcUrl: RPC, confirmTimeoutMs: 90_000 });
  const sendOptions = () => ({ abortSignal: AbortSignal.timeout(15_000) });
  return {
    async genesis() { return await rpc.getGenesisHash().send(sendOptions()); },
    async snapshot(addresses, minSlot = 0n) {
      const result = await rpc.getMultipleAccounts(addresses, { encoding: 'base64', commitment: 'finalized', minContextSlot: minSlot }).send(sendOptions());
      if (typeof result.context.slot !== 'bigint' || result.context.slot < minSlot || result.value.length !== addresses.length) throw Error('finalized snapshot mismatch');
      return { slot: result.context.slot, accounts: result.value.map(a => a ? { owner: a.owner, lamports: a.lamports, executable: a.executable, data: new Uint8Array(getBase64Encoder().encode(a.data[0])) } : null) };
    },
    async rent(size) { return await rpc.getMinimumBalanceForRentExemption(BigInt(size), { commitment: 'finalized' }).send(sendOptions()); },
    async latest() { return await ledger.latestBlockhash(); },
    async fee(transaction) {
      const message = getBase64Decoder().decode(transaction.messageBytes);
      const result = await rpc.getFeeForMessage(message as Parameters<typeof rpc.getFeeForMessage>[0], { commitment: 'finalized' }).send(sendOptions());
      if (result.value === null) throw Error('fee quote unavailable');
      return result.value;
    },
    async airdrop(sponsor, amount) { return await rpc.requestAirdrop(sponsor, lamports(amount), { commitment: 'finalized' }).send(sendOptions()); },
    async submit(tx) { return await ledger.submit(tx); },
    async finalized(signature) {
      if (!isSignature(signature)) throw Error('invalid original signature');
      const result = await rpc.getTransaction(signature as Signature, { commitment: 'finalized', encoding: 'base64', maxSupportedTransactionVersion: 0 }).send(sendOptions());
      if (!result || !result.meta) return null;
      if (typeof result.slot !== 'bigint' || result.slot < 0n || !Array.isArray(result.transaction) || result.transaction[1] !== 'base64' || !('err' in result.meta)) throw Error('malformed finalized transaction response');
      return { slot: result.slot, wire: result.transaction[0], error: result.meta.err };
    },
  };
}
async function setupSigner(role: 'sponsor' | 'mint') {
  const path = `${PRIVATE}/keys/${role}.json`;
  protectedPath(dirname(path));
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 ||
      (metadata.mode & 0o777) !== 0o600 || metadata.uid !== (role === 'sponsor' ? 989 : 0) ||
      metadata.gid !== (role === 'sponsor' ? 986 : 0)) throw Error('setup key custody drift');
  return await loadKeypair(path);
}
async function main(): Promise<void> {
  const action = provisionArguments(process.argv.slice(2));
  if (process.getuid?.() !== 0) throw Error('trusted isolated operator session required');
  protectedPath(`${PRIVATE}/provision-approved.json`, 0o600);
  protectedPath(`${PRIVATE}/b1-complete.json`, 0o600);
  protectedPath(`${PRIVATE}/identities.json`, 0o600);
  protectedPath(SETUP, 0o700); protectedPath(RELEASE);
  const approved = JSON.parse(readFileSync(`${PRIVATE}/provision-approved.json`, 'utf8'));
  const complete = JSON.parse(readFileSync(`${PRIVATE}/b1-complete.json`, 'utf8'));
  const ids = JSON.parse(readFileSync(`${PRIVATE}/identities.json`, 'utf8'));
  if (approved.applicationRelease !== E2E_APPLICATION_RELEASE || complete.release !== E2E_APPLICATION_RELEASE || complete.status !== 'OFFLINE_B1_VERIFIED_B2_B3_NOT_RUN') throw Error('accepted B1/release receipt required');
  if (approved.b1ReceiptSha256 !== digest(`${PRIVATE}/b1-complete.json`) || approved.identitiesSha256 !== digest(`${PRIVATE}/identities.json`)) throw Error('approved custody evidence mismatch');
  const ownPath = realpathSync(new URL(import.meta.url)), corePath = realpathSync(new URL('./e2e-provisioning.ts', import.meta.url));
  for (const [path, expected] of [[ownPath, approved.entrypointSha256], [corePath, approved.coreSha256]]) {
    protectedPath(path!);
    if (digest(path!) !== expected) throw Error('operator executable approval mismatch');
  }
  const permission = approved.actions?.[action];
  if (typeof permission !== 'string' || !permission.trim()) throw Error('exact operator action approval missing');
  if (!isAddress(approved.browser)) throw Error('approved browser public key required');
  const plan: ProvisionPlan = { applicationRelease: E2E_APPLICATION_RELEASE, approvalReference: approved.campaignReference,
    sponsor: ids.sponsor, merchant: ids.merchant, payer: ids.payer, mint: ids.mint, browser: approved.browser };
  validatePlan(plan);
  for (const role of ['sponsor', 'merchant', 'payer', 'mint']) if (ids[role] !== complete.public_ids?.[role]) throw Error('B1 public identity receipt changed');
  const record = loadDeploymentRecord(`${RELEASE}/docs/evidence/sac-007/deployment-identity.v1.json`);
  const provisioner = new E2EProvisioner(plan, new ProvisionStore(SETUP), rpcBackend(record), record.network.genesisHash);
  if (action === 'fund') await provisioner.fund();
  else if (action === 'assets') await provisioner.assets(async () => ({ sponsor: await setupSigner('sponsor'), mint: await setupSigner('mint') }));
  const result = await provisioner.observe(action.endsWith('funding') || action === 'fund' ? 'funding' : 'assets');
  console.log(JSON.stringify(result));
  if (result.status !== 'FINALIZED_SUCCEEDED') process.exitCode = 2;
}
if (process.argv[1]?.endsWith('e2e-provision.ts')) main().catch(() => {
  console.error('E2E provisioning stopped. Preserve all reservations and original wires; observe only, never resend or regenerate.');
  process.exitCode = 1;
});
