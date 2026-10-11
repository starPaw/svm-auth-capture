// Issue #68 operator-only bounded provisioning. No imports have network side effects.
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  getBase64Encoder, getCompiledTransactionMessageDecoder, getPublicKeyFromAddress,
  getSignatureFromTransaction, getTransactionDecoder, isAddress, isSignature,
  lamports, verifySignature, isSome,
  type Address, type KeyPairSigner, type SignatureBytes, type Transaction,
} from '@solana/kit';
import { getCreateAccountInstruction, getTransferSolInstruction, getTransferSolInstructionDataDecoder, SYSTEM_PROGRAM_ADDRESS } from '@solana-program/system';
import { AccountState, getCreateAssociatedTokenIdempotentInstruction, getInitializeMint2Instruction, getMintDecoder, getMintSize, getMintToInstruction, getTokenDecoder, getTokenSize } from '@solana-program/token';
import { createDurableFile } from '../src/durable-file.ts';
import type { LedgerAccount, SubmitResult } from '../src/ledger.ts';
import { ata, TOKEN_PROGRAM_ADDRESS } from '../src/program.ts';
import { buildTransaction, encodeTransaction, type Lifetime } from '../src/transactions.ts';

export const E2E_APPLICATION_RELEASE = '3ddb204d16f10cf6826a3fa4fd831275333a13f5';
export const E2E_BUDGET = Object.freeze({ sponsorInbound: 1_000_000_000n, browserSol: 10_000_000n,
  tokens: 600_000_000n, decimals: 6, sponsorFloor: 10_000_000n, maximumSetupFee: 100_000n });
export type ProvisionPlan = { applicationRelease: string; approvalReference: string;
  sponsor: Address; merchant: Address; payer: Address; mint: Address; browser: Address };
export type AccountSnapshot = { slot: bigint; accounts: (LedgerAccount | null)[] };
export type FinalizedTransaction = { slot: bigint; wire: string; error: unknown };
export interface ProvisionBackend {
  genesis(): Promise<string>;
  snapshot(addresses: Address[], minSlot?: bigint): Promise<AccountSnapshot>;
  rent(size: number): Promise<bigint>;
  latest(): Promise<Lifetime>;
  fee(transaction: Transaction): Promise<bigint>;
  airdrop(sponsor: Address, amount: bigint): Promise<string>;
  submit(transaction: Transaction): Promise<SubmitResult>;
  finalized(signature: string): Promise<FinalizedTransaction | null>;
}
const stringify = (v: unknown) => JSON.stringify(v, (_k, x) => typeof x === 'bigint' ? x.toString() : x, 2);
const hash = (v: string) => createHash('sha256').update(v).digest('hex');
export function validatePlan(plan: ProvisionPlan): void {
  if (plan.applicationRelease !== E2E_APPLICATION_RELEASE || typeof plan.approvalReference !== 'string' || !plan.approvalReference.trim()) throw Error('approved E2E release/reference required');
  const addresses = [plan.sponsor, plan.merchant, plan.payer, plan.mint, plan.browser];
  if (addresses.some(a => !isAddress(a)) || new Set(addresses).size !== 5) throw Error('five distinct E2E/browser identities required');
}
export class ProvisionStore {
  constructor(readonly directory: string) {
    const s = lstatSync(directory);
    if (!s.isDirectory() || s.isSymbolicLink() || (s.mode & 0o077)) throw Error('private existing provisioning directory required');
  }
  write(name: string, value: unknown): void {
    if (!/^(funding|assets)-(intent|response|signed|broadcast|receipt)\.json$/.test(name)) throw Error('invalid provisioning record');
    createDurableFile(join(this.directory, name), stringify(value));
  }
  read(name: string): Record<string, any> | null {
    if (!/^(funding|assets)-(intent|response|signed|broadcast|receipt)\.json$/.test(name)) throw Error('invalid provisioning record');
    const p = join(this.directory, name);
    if (!existsSync(p)) return null;
    const s = lstatSync(p);
    if (!s.isFile() || s.isSymbolicLink() || s.nlink !== 1 || (s.mode & 0o077)) throw Error('unsafe provisioning record');
    return JSON.parse(readFileSync(p, 'utf8'));
  }
}
export class E2EProvisioner {
  private readonly planHash: string;
  constructor(readonly plan: ProvisionPlan, readonly store: ProvisionStore, readonly backend: ProvisionBackend, readonly genesisHash: string) {
    validatePlan(plan); this.plan = Object.freeze({ ...plan }); this.planHash = hash(stringify(this.plan));
  }
  private async identity(): Promise<void> {
    if (await this.backend.genesis() !== this.genesisHash) throw Error('Devnet genesis mismatch');
  }
  private reserve(action: 'funding' | 'assets'): void {
    // Fixed logical name fences signing AND sending, across concurrent processes/restarts.
    this.store.write(`${action}-intent.json`, { action, planHash: this.planHash, plan: this.plan, budget: E2E_BUDGET });
  }
  private bound(action: 'funding' | 'assets'): Record<string, any> {
    const intent = this.store.read(`${action}-intent.json`);
    if (!intent || intent.planHash !== this.planHash) throw Error('missing or changed original provisioning plan');
    return intent;
  }
  async fund(): Promise<void> {
    await this.identity();
    const before = await this.backend.snapshot([this.plan.sponsor]);
    if (typeof before.slot !== 'bigint' || before.slot < 0n || before.accounts.length !== 1) throw Error('invalid finalized funding snapshot');
    const sponsor = before.accounts[0];
    if (sponsor && (sponsor.owner !== SYSTEM_PROGRAM_ADDRESS || sponsor.executable || sponsor.data.length || sponsor.lamports !== 0n)) throw Error('fresh empty sponsor required; no top-up');
    this.reserve('funding');
    // Response loss leaves the intent intact. There is no retry route.
    const signature = await this.backend.airdrop(this.plan.sponsor, E2E_BUDGET.sponsorInbound);
    if (!isSignature(signature)) throw Error('malformed original airdrop signature');
    this.store.write('funding-response.json', { planHash: this.planHash, signature });
    await this.observe('funding');
  }
  async assets(loadSigners: () => Promise<{ sponsor: KeyPairSigner; mint: KeyPairSigner }>): Promise<void> {
    await this.identity();
    const funded = this.store.read('funding-receipt.json');
    if (!funded || funded.planHash !== this.planHash || funded.status !== 'FINALIZED_SUCCEEDED' || (await this.observe('funding')).status !== 'FINALIZED_SUCCEEDED') throw Error('original finalized funding proof required');
    this.reserve('assets');
    // No signer is loaded before the durable logical reservation.
    const signers = await loadSigners();
    if (signers.sponsor.address !== this.plan.sponsor || signers.mint.address !== this.plan.mint) throw Error('setup signer identity mismatch');
    const browserAta = await ata(this.plan.browser, this.plan.mint);
    const merchantAta = await ata(this.plan.merchant, this.plan.mint);
    const pre = await this.backend.snapshot([this.plan.sponsor, this.plan.mint, browserAta, merchantAta, this.plan.browser]);
    if (typeof pre.slot !== 'bigint' || pre.slot < 0n || pre.accounts.length !== 5) throw Error('invalid finalized setup snapshot');
    const sponsor = pre.accounts[0], browser = pre.accounts[4];
    if (!sponsor || sponsor.owner !== SYSTEM_PROGRAM_ADDRESS || sponsor.executable || sponsor.data.length || sponsor.lamports > E2E_BUDGET.sponsorInbound) throw Error('invalid sponsor budget/account');
    if (pre.accounts.slice(1, 4).some(Boolean)) throw Error('mint/ATAs must be fresh; retain reservation');
    if (browser && (browser.owner !== SYSTEM_PROGRAM_ADDRESS || browser.executable || browser.data.length)) throw Error('browser must be an ordinary wallet');
    const mintRent = await this.backend.rent(getMintSize());
    const tokenRent = await this.backend.rent(getTokenSize());
    if (mintRent <= 0n || tokenRent <= 0n) throw Error('invalid rent quote');
    const lifetime = await this.backend.latest();
    const instructions = [
      getCreateAccountInstruction({ payer: signers.sponsor, newAccount: signers.mint, lamports: mintRent, space: getMintSize(), programAddress: TOKEN_PROGRAM_ADDRESS }),
      getInitializeMint2Instruction({ mint: this.plan.mint, decimals: E2E_BUDGET.decimals, mintAuthority: this.plan.mint, freezeAuthority: null }),
      getCreateAssociatedTokenIdempotentInstruction({ payer: signers.sponsor, owner: this.plan.browser, mint: this.plan.mint, ata: browserAta }),
      getCreateAssociatedTokenIdempotentInstruction({ payer: signers.sponsor, owner: this.plan.merchant, mint: this.plan.mint, ata: merchantAta }),
      getMintToInstruction({ mint: this.plan.mint, token: browserAta, mintAuthority: signers.mint, amount: E2E_BUDGET.tokens }),
      getTransferSolInstruction({ source: signers.sponsor, destination: this.plan.browser, amount: lamports(E2E_BUDGET.browserSol) }),
    ];
    const unsigned = await buildTransaction({ feePayer: this.plan.sponsor, signers: [], lifetime, instructions });
    const fee = await this.backend.fee(unsigned);
    const spend = mintRent + 2n * tokenRent + E2E_BUDGET.browserSol + fee;
    if (fee <= 0n || fee > E2E_BUDGET.maximumSetupFee || sponsor.lamports - spend < E2E_BUDGET.sponsorFloor) throw Error('setup quote exceeds approved spend/floor');
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
  async observe(action: 'funding' | 'assets'): Promise<Record<string, unknown>> {
    await this.identity(); this.bound(action);
    const original = this.store.read(action === 'funding' ? 'funding-response.json' : 'assets-signed.json');
    if (!original) return { status: 'UNKNOWN', reason: 'original signature unavailable; no resend' };
    if (original.planHash !== this.planHash || !isSignature(original.signature)) throw Error('original record mismatch');
    const proof = await this.backend.finalized(original.signature);
    if (!proof) return { status: 'UNKNOWN', signature: original.signature };
    if (typeof proof.slot !== 'bigint' || proof.slot < 0n || typeof proof.wire !== 'string') throw Error('invalid finalized transaction proof');
    const tx = getTransactionDecoder().decode(getBase64Encoder().encode(proof.wire));
    if (encodeTransaction(tx) !== proof.wire) throw Error('noncanonical finalized wire');
    if (getSignatureFromTransaction(tx) !== original.signature) throw Error('finalized signature mismatch');
    if (action === 'assets' && (hash(original.wire) !== original.wireHash || proof.wire !== original.wire)) throw Error('original wire mismatch');
    if (proof.error !== null) return { status: 'FINALIZED_FAILED', signature: original.signature, slot: String(proof.slot) };
    if (action === 'funding') {
      const message = getCompiledTransactionMessageDecoder().decode(tx.messageBytes);
      if (message.version !== 'legacy') throw Error('unsupported funding wire version');
      const matches = message.instructions.filter(ix => {
        if (message.staticAccounts[ix.programAddressIndex] !== SYSTEM_PROGRAM_ADDRESS || ix.data?.length !== 12 || ix.accountIndices?.length !== 2) return false;
        const data = getTransferSolInstructionDataDecoder().decode(ix.data);
        return data.discriminator === 2 && data.amount === E2E_BUDGET.sponsorInbound && message.staticAccounts[ix.accountIndices[1]!] === this.plan.sponsor;
      });
      if (matches.length !== 1) throw Error('airdrop transaction does not prove exact sponsor allocation');
      const post = await this.backend.snapshot([this.plan.sponsor], proof.slot);
      if (typeof post.slot !== 'bigint' || post.slot < proof.slot || post.accounts.length !== 1 || post.accounts[0]?.lamports !== E2E_BUDGET.sponsorInbound) throw Error('funding balance evidence unavailable or changed');
    } else {
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
      if (sponsor!.owner !== SYSTEM_PROGRAM_ADDRESS || sponsor!.executable || sponsor!.data.length || sponsor!.lamports !== BigInt(original.pre.accounts[0].lamports) - BigInt(original.quote.spend)) throw Error('sponsor outflow evidence changed');
    }
    const receipt = { status: 'FINALIZED_SUCCEEDED', action, planHash: this.planHash, signature: original.signature, slot: String(proof.slot) };
    if (!this.store.read(`${action}-receipt.json`)) this.store.write(`${action}-receipt.json`, receipt);
    return receipt;
  }
}
