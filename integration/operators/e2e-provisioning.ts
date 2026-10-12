// Issue #68 operator-only bounded provisioning. No imports have network side effects.
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  createNoopSigner, getPublicKeyFromAddress,
  getSignatureFromTransaction, isAddress, isSignature,
  lamports, verifySignature, isSome,
  type Address, type KeyPairSigner, type SignatureBytes, type Transaction,
} from '@solana/kit';
import { getCreateAccountInstruction, getTransferSolInstruction, getTransferSolInstructionDataDecoder, SYSTEM_PROGRAM_ADDRESS } from '@solana-program/system';
import { AccountState, getCreateAssociatedTokenIdempotentInstruction, getInitializeMint2Instruction, getMintDecoder, getMintSize, getMintToInstruction, getTokenDecoder, getTokenSize } from '@solana-program/token';
import { CampaignBudget } from '../src/campaign-budget.ts';
import { validatePreSignerContinuation, type PreSignerContinuation } from './p2-presigner-stop.ts';
import { verifiedProof, messageDigest, type FinalizedTransaction } from '../src/campaign-proof.ts';
export type { FinalizedTransaction } from '../src/campaign-proof.ts';
import { createDurableFile } from '../src/durable-file.ts';
import type { LedgerAccount, SubmitResult } from '../src/ledger.ts';
import { ata, TOKEN_PROGRAM_ADDRESS } from '../src/program.ts';
import { buildTransaction, encodeTransaction, type Lifetime } from '../src/transactions.ts';

export const E2E_APPLICATION_RELEASE = '3ddb204d16f10cf6826a3fa4fd831275333a13f5';
export const E2E_BUDGET = Object.freeze({ acceptedExternalFunding: 10_000_000_000n, browserSol: 10_000_000n,
  maximumAssetsRent: 5_540_160n, tokens: 600_000_000n, decimals: 6, sponsorFloor: 10_000_000n, maximumSetupFee: 100_000n });
export type ProvisionPlan = { applicationRelease: string; approvalReference: string;
  sponsor: Address; merchant: Address; payer: Address; mint: Address; browser: Address; externalFunding: readonly { signature: string; amount: string }[] };
export type AccountSnapshot = { slot: bigint; accounts: (LedgerAccount | null)[] };
export interface ProvisionBackend {
  genesis(): Promise<string>;
  snapshot(addresses: Address[], minSlot?: bigint): Promise<AccountSnapshot>;
  rent(size: number): Promise<bigint>;
  latest(): Promise<Lifetime>;
  fee(transaction: Transaction): Promise<bigint>;
  submit(transaction: Transaction): Promise<SubmitResult>;
  finalized(signature: string): Promise<FinalizedTransaction | null>;
}
const stringify = (v: unknown) => JSON.stringify(v, (_k, x) => typeof x === 'bigint' ? x.toString() : x, 2);
const hash = (v: string) => createHash('sha256').update(v).digest('hex');
export function validatePlan(plan: ProvisionPlan): void {
  if (plan.applicationRelease !== E2E_APPLICATION_RELEASE || typeof plan.approvalReference !== 'string' || !plan.approvalReference.trim()) throw Error('approved E2E release/reference required');
  if (!Array.isArray(plan.externalFunding) || plan.externalFunding.length !== 2 || new Set(plan.externalFunding.map(x=>x.signature)).size !== 2 || plan.externalFunding.some(x=>!isSignature(x.signature) || x.amount !== '5000000000')) throw Error('two exact original external funding signatures required');
  const addresses = [plan.sponsor, plan.merchant, plan.payer, plan.mint, plan.browser];
  if (addresses.some(a => !isAddress(a)) || new Set(addresses).size !== 5) throw Error('five distinct E2E/browser identities required');
}
export class ProvisionStore {
  readonly directory: string;
  constructor(directory: string) {
    this.directory = directory;
    const s = lstatSync(directory);
    if (!s.isDirectory() || s.isSymbolicLink() || (s.mode & 0o077)) throw Error('private existing provisioning directory required');
  }
  write(name: string, value: unknown): void {
    if (!/^(external-funding|assets)-(intent|response|signed|broadcast|receipt)\.json$/.test(name) && name !== 'assets-continuation-intent.json') throw Error('invalid provisioning record');
    createDurableFile(join(this.directory, name), stringify(value));
  }
  read(name: string): Record<string, any> | null {
    if (!/^(external-funding|assets)-(intent|response|signed|broadcast|receipt)\.json$/.test(name) && name !== 'assets-continuation-intent.json') throw Error('invalid provisioning record');
    const p = join(this.directory, name);
    let s;
    try { s = lstatSync(p); } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw error;
    }
    if (!s.isFile() || s.isSymbolicLink() || s.nlink !== 1 || (s.mode & 0o077)) throw Error('unsafe provisioning record');
    return JSON.parse(readFileSync(p, 'utf8'));
  }
  originalAssetsIntentHash(): string {
    if (!this.read('assets-intent.json')) throw Error('missing original assets intent');
    return hash(readFileSync(join(this.directory, 'assets-intent.json'), 'utf8'));
  }
}
export class E2EProvisioner {
  private readonly planHash: string;
  readonly plan: ProvisionPlan; readonly store: ProvisionStore; readonly backend: ProvisionBackend; readonly genesisHash: string; readonly budget: CampaignBudget;
  constructor(plan: ProvisionPlan, store: ProvisionStore, backend: ProvisionBackend, genesisHash: string, budget: CampaignBudget) {
    this.store = store; this.backend = backend; this.genesisHash = genesisHash; this.budget = budget;
    validatePlan(plan); this.plan = Object.freeze({ ...plan, externalFunding: Object.freeze(plan.externalFunding.map(x => Object.freeze({...x}))) });
    if (budget.policy.sponsor !== plan.sponsor || budget.policy.browser !== plan.browser || budget.policy.genesisHash !== genesisHash || budget.policy.reference !== plan.approvalReference) throw Error('campaign policy mismatch'); this.planHash = hash(stringify(this.plan));
  }
  private async identity(): Promise<void> {
    if (await this.backend.genesis() !== this.genesisHash) throw Error('Devnet genesis mismatch');
  }
  private reserve(action: 'external-funding' | 'assets'): void {
    // Fixed logical name fences signing AND sending, across concurrent processes/restarts.
    this.store.write(`${action}-intent.json`, { action, planHash: this.planHash, plan: this.plan, budget: E2E_BUDGET });
  }
  private bound(action: 'external-funding' | 'assets'): Record<string, any> {
    const intent = this.store.read(`${action}-intent.json`);
    if (!intent || intent.planHash !== this.planHash) throw Error('missing or changed original provisioning plan');
    return intent;
  }
  async acceptFunding(): Promise<Record<string, unknown>> {
    await this.identity();
    if (!this.store.read('external-funding-intent.json')) this.reserve('external-funding');
    return this.observe('external-funding');
  }
  private async fundingEvidence(): Promise<Record<string, unknown>> {
    const transactions = []; let total = 0n, latestSlot = 0n;
    for (const original of this.plan.externalFunding) {
      const proof = await this.backend.finalized(original.signature);
      if (!proof) return { status: 'UNKNOWN', signature: original.signature, reason: 'original external funding history unavailable' };
      const {message, messageHash} = await verifiedProof(original.signature, proof);
      if (proof.error !== null) throw Error('external funding failed');
      const index = message.staticAccounts.indexOf(this.plan.sponsor);
      if (index <= 0 || proof.postBalances[index]! - proof.preBalances[index]! !== BigInt(original.amount)) throw Error('external funding sponsor delta mismatch');
      const transfers = message.instructions.filter(ix => message.staticAccounts[ix.programAddressIndex] === SYSTEM_PROGRAM_ADDRESS);
      if (transfers.length !== 1 || message.instructions.some(ix => ![SYSTEM_PROGRAM_ADDRESS, 'ComputeBudget111111111111111111111111111111'].includes(message.staticAccounts[ix.programAddressIndex]!))) throw Error('external funding instruction mismatch');
      const ix = transfers[0]!;
      if (ix.data?.length !== 12 || ix.accountIndices?.length !== 2 || message.staticAccounts[ix.accountIndices[0]!] !== message.staticAccounts[0] || ix.accountIndices[1] !== index) throw Error('external funding transfer accounts mismatch');
      const data = getTransferSolInstructionDataDecoder().decode(ix.data);
      if (data.discriminator !== 2 || data.amount !== BigInt(original.amount) || proof.preBalances[0]! - proof.postBalances[0]! !== data.amount + proof.fee) throw Error('external funding transfer/fee mismatch');
      total += data.amount; if (proof.slot > latestSlot) latestSlot = proof.slot;
      transactions.push({signature: original.signature, slot: String(proof.slot), messageHash, amount: String(data.amount), externalPayer: message.staticAccounts[0], externalFee: String(proof.fee)});
    }
    if (total !== E2E_BUDGET.acceptedExternalFunding) throw Error('external funding total mismatch');
    const receipt = {status: 'FINALIZED_SUCCEEDED', action: 'external-funding', planHash: this.planHash, provedExternalFunding: String(total), transactions};
    const existing = this.store.read('external-funding-receipt.json');
    if (existing && stringify(existing) !== stringify(receipt)) throw Error('original funding receipt drift');
    if (!existing) this.store.write('external-funding-receipt.json', receipt);
    const current = await this.backend.snapshot([this.plan.sponsor], latestSlot);
    if (typeof current.slot !== 'bigint' || current.slot < latestSlot || current.accounts.length !== 1) throw Error('current finalized balance unavailable');
    const sponsor = current.accounts[0];
    if (!sponsor || sponsor.owner !== SYSTEM_PROGRAM_ADDRESS || sponsor.executable || sponsor.data.length) throw Error('invalid sponsor wallet');
    return {...receipt, currentBalance: {slot: String(current.slot), lamports: String(sponsor.lamports)}, spending: this.budget.summary()};
  }
  async quoteAssets() {
    await this.identity();
    const browserAta = await ata(this.plan.browser, this.plan.mint);
    const merchantAta = await ata(this.plan.merchant, this.plan.mint);
    const pre = await this.backend.snapshot([this.plan.sponsor, this.plan.mint, browserAta, merchantAta, this.plan.browser]);
    if (typeof pre.slot !== 'bigint' || pre.slot < 0n || pre.accounts.length !== 5) throw Error('invalid finalized setup snapshot');
    const sponsor = pre.accounts[0], browser = pre.accounts[4];
    if (!sponsor || sponsor.owner !== SYSTEM_PROGRAM_ADDRESS || sponsor.executable || sponsor.data.length) throw Error('invalid sponsor budget/account');
    if (pre.accounts.slice(1, 4).some(Boolean)) throw Error('mint/ATAs must be fresh; retain reservation');
    if (browser && (browser.owner !== SYSTEM_PROGRAM_ADDRESS || browser.executable || browser.data.length)) throw Error('browser must be an ordinary wallet');
    const mintRent = await this.backend.rent(getMintSize());
    const tokenRent = await this.backend.rent(getTokenSize());
    if (mintRent <= 0n || tokenRent <= 0n) throw Error('invalid rent quote');
    const lifetime = await this.backend.latest();
    const sponsorIdentity = createNoopSigner(this.plan.sponsor), mintIdentity = createNoopSigner(this.plan.mint);
    const instructions = [
      getCreateAccountInstruction({ payer: sponsorIdentity, newAccount: mintIdentity, lamports: mintRent, space: getMintSize(), programAddress: TOKEN_PROGRAM_ADDRESS }),
      getInitializeMint2Instruction({ mint: this.plan.mint, decimals: E2E_BUDGET.decimals, mintAuthority: this.plan.mint, freezeAuthority: null }),
      getCreateAssociatedTokenIdempotentInstruction({ payer: sponsorIdentity, owner: this.plan.browser, mint: this.plan.mint, ata: browserAta }),
      getCreateAssociatedTokenIdempotentInstruction({ payer: sponsorIdentity, owner: this.plan.merchant, mint: this.plan.mint, ata: merchantAta }),
      getMintToInstruction({ mint: this.plan.mint, token: browserAta, mintAuthority: mintIdentity, amount: E2E_BUDGET.tokens }),
      getTransferSolInstruction({ source: sponsorIdentity, destination: this.plan.browser, amount: lamports(E2E_BUDGET.browserSol) }),
    ];
    const unsigned = await buildTransaction({ feePayer: this.plan.sponsor, signers: [], lifetime, instructions });
    const fee = await this.backend.fee(unsigned);
    const spend = mintRent + 2n * tokenRent + E2E_BUDGET.browserSol + fee;
    if (mintRent + 2n * tokenRent > E2E_BUDGET.maximumAssetsRent || fee <= 0n || fee > E2E_BUDGET.maximumSetupFee || sponsor.lamports - spend < E2E_BUDGET.sponsorFloor) throw Error('setup quote exceeds approved spend/floor');
    if (spend > this.budget.summary().available) throw Error('campaign budget insufficient for assets plan');
    return {browserAta,merchantAta,pre,mintRent,tokenRent,lifetime,instructions,unsigned,fee,spend};
  }
  async assets(loadSigners: () => Promise<{ sponsor: KeyPairSigner; mint: KeyPairSigner }>, continuation?: PreSignerContinuation): Promise<void> {
    await this.identity();
    const funded = this.store.read('external-funding-receipt.json');
    if (!funded || funded.planHash !== this.planHash || funded.status !== 'FINALIZED_SUCCEEDED' || (await this.observe('external-funding')).status !== 'FINALIZED_SUCCEEDED') throw Error('original finalized funding proof required');
    if (continuation) {
      validatePreSignerContinuation(continuation);
      this.bound('assets');
      if (continuation.stop.originalPlanHash !== this.planHash || this.store.originalAssetsIntentHash() !== continuation.stop.originalIntentSha256 || ['signed','broadcast','response','receipt'].some(s => this.store.read(`assets-${s}.json`)) || this.budget.hasReservation('assets')) throw Error('original pre-signer stop does not match; never continue UNKNOWN signing');
      // Preserve the original intent verbatim. Exclusive continuation latch precedes signer access.
      // Any subsequent failure freezes this continuation too; never clear/retry it.
      this.store.write('assets-continuation-intent.json', { planHash: this.planHash, ...continuation });
    } else this.reserve('assets');
    // No signer is loaded before the durable logical reservation.
    const signers = await loadSigners();
    if (signers.sponsor.address !== this.plan.sponsor || signers.mint.address !== this.plan.mint) throw Error('setup signer identity mismatch');
    const {browserAta,merchantAta,pre,mintRent,tokenRent,lifetime,instructions,unsigned,fee,spend} = await this.quoteAssets();
    this.budget.reserve('assets', 'assets', messageDigest(unsigned.messageBytes), { fees: E2E_BUDGET.maximumSetupFee, rent: mintRent + 2n * tokenRent, browserAllocation: E2E_BUDGET.browserSol });
    const transaction = await buildTransaction({ feePayer: this.plan.sponsor, signers: [signers.sponsor, signers.mint], lifetime, instructions });
    if (!Buffer.from(unsigned.messageBytes).equals(Buffer.from(transaction.messageBytes))) throw Error('signed message changed');
    for (const signer of [this.plan.sponsor, this.plan.mint]) {
      const signature = transaction.signatures[signer];
      if (!signature || !await verifySignature(await getPublicKeyFromAddress(signer), signature as SignatureBytes, transaction.messageBytes)) throw Error('setup signature invalid');
    }
    const signature = getSignatureFromTransaction(transaction), wire = encodeTransaction(transaction);
    this.store.write('assets-signed.json', { planHash: this.planHash, signature, wire, wireHash: hash(wire), lifetime,
      browserAta, merchantAta, pre, quote: { mintRent, tokenRent, fee, spend } });
    // A failure flushing either record prevents send. A crash afterward freezes the action.
    this.store.write('assets-broadcast.json', { planHash: this.planHash, signature });
    const result = await this.backend.submit(transaction);
    this.store.write('assets-response.json', { planHash: this.planHash, signature, result });
    await this.observe('assets');
  }
  async observe(action: 'external-funding' | 'assets'): Promise<Record<string, unknown>> {
    await this.identity(); this.bound(action);
    if (action === 'external-funding') return this.fundingEvidence();
    const original = this.store.read('assets-signed.json');
    if (!original) return { status: 'UNKNOWN', reason: 'original signature unavailable; no resend' };
    if (original.planHash !== this.planHash || !isSignature(original.signature)) throw Error('original record mismatch');
    const proof = await this.backend.finalized(original.signature);
    if (!proof) return { status: 'UNKNOWN', signature: original.signature };
    if (typeof proof.slot !== 'bigint' || proof.slot < 0n || typeof proof.wire !== 'string') throw Error('invalid finalized transaction proof');
    await verifiedProof(original.signature, proof);
    if (hash(original.wire) !== original.wireHash || proof.wire !== original.wire) throw Error('original wire mismatch');
    await this.budget.finalize('assets', original.signature, proof);
    if (proof.error !== null) return { status: 'FINALIZED_FAILED', signature: original.signature, slot: String(proof.slot) };
    {
      const post = await this.backend.snapshot([this.plan.mint, original.browserAta, original.merchantAta, this.plan.browser, this.plan.sponsor], proof.slot);
      if (typeof post.slot !== 'bigint' || post.slot < proof.slot || post.accounts.length !== 5 || post.accounts.some(a => !a)) throw Error('setup finalized account evidence unavailable');
      const [mintAccount, browserAccount, merchantAccount, browserSol, sponsor] = post.accounts as LedgerAccount[];
      if ([mintAccount!, browserAccount!, merchantAccount!].some(a => a.owner !== TOKEN_PROGRAM_ADDRESS || a.executable)) throw Error('setup token owner mismatch');
      if (mintAccount!.data.length !== getMintSize() || browserAccount!.data.length !== getTokenSize() || merchantAccount!.data.length !== getTokenSize()) throw Error('setup account shape mismatch');
      const mint = getMintDecoder().decode(mintAccount!.data), browser = getTokenDecoder().decode(browserAccount!.data), merchant = getTokenDecoder().decode(merchantAccount!.data);
      if (!mint.isInitialized || mint.decimals !== 6 || mint.supply !== E2E_BUDGET.tokens || !isSome(mint.mintAuthority) || mint.mintAuthority.value !== this.plan.mint || isSome(mint.freezeAuthority)) throw Error('setup mint mismatch');
      for (const [token, owner, amount] of [[browser, this.plan.browser, E2E_BUDGET.tokens], [merchant, this.plan.merchant, 0n]] as const) {
        if (token.mint !== this.plan.mint || token.owner !== owner || token.amount !== amount || token.state !== AccountState.Initialized || isSome(token.delegate) || isSome(token.closeAuthority)) throw Error('setup token account mismatch');
      }
      if (browserSol!.owner !== SYSTEM_PROGRAM_ADDRESS || browserSol!.executable || browserSol!.data.length || browserSol!.lamports !== BigInt(original.pre.accounts[4]?.lamports ?? '0') + E2E_BUDGET.browserSol) throw Error('browser SOL evidence changed');
      if (sponsor!.owner !== SYSTEM_PROGRAM_ADDRESS || sponsor!.executable || sponsor!.data.length || sponsor!.lamports !== BigInt(original.pre.accounts[0].lamports) - (BigInt(original.quote.mintRent) + 2n * BigInt(original.quote.tokenRent) + E2E_BUDGET.browserSol + proof.fee)) throw Error('sponsor outflow evidence changed');
    }
    const receipt = { status: 'FINALIZED_SUCCEEDED', action, planHash: this.planHash, signature: original.signature, slot: String(proof.slot) };
    if (!this.store.read(`${action}-receipt.json`)) this.store.write(`${action}-receipt.json`, receipt);
    return receipt;
  }
}
