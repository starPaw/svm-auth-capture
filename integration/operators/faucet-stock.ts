// Operator-only, one original finite stock action. Never imported by an HTTP runtime.
import { createHash } from 'node:crypto';
import { constants, closeSync, fstatSync, lstatSync, openSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createNoopSigner, getBase64Encoder, getTransactionDecoder, getSignatureFromTransaction, getPublicKeyFromAddress, verifySignature, isAddress, isSome, type Address, type KeyPairSigner, type SignatureBytes } from '@solana/kit';
import { SYSTEM_PROGRAM_ADDRESS } from '@solana-program/system';
import { AccountState, getCreateAssociatedTokenIdempotentInstruction, getMintDecoder, getMintSize, getMintToInstruction, getTokenDecoder, getTokenSize } from '@solana-program/token';
import { AdmissionJournal } from '../src/admission-journal.ts';
import { CampaignBudget } from '../src/campaign-budget.ts';
import { messageDigest, verifiedProof } from '../src/campaign-proof.ts';
import { createDurableFile } from '../src/durable-file.ts';
import { ata, TOKEN_PROGRAM_ADDRESS } from '../src/program.ts';
import { buildTransaction, encodeTransaction, type Lifetime } from '../src/transactions.ts';
import type { LedgerAccount } from '../src/ledger.ts';
import type { ProvisionBackend } from './e2e-provisioning.ts';

export const STOCK_AMOUNT = 100_000_000_000n; // 100 claims of 1,000 six-decimal test tokens.
export const STOCK_MAXIMUM_RENT = 2_039_280n;
export const STOCK_MAXIMUM_FEE = 100_000n;
export const STOCK_SPONSOR_FLOOR = 10_000_000n;
export const STOCK_GENESIS = 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG';
export type StockPlan = { schema: 1; sourceRevision: string; approvalReference: string; campaignReference: string;
  sponsor: Address; mint: Address; browser: Address; genesisHash: typeof STOCK_GENESIS };
const encode = (v: unknown) => JSON.stringify(v, (_k, x) => typeof x === 'bigint' ? x.toString() : x, 2);
const digest = (v: string) => createHash('sha256').update(v).digest('hex');
export function validateStockPlan(p: StockPlan) {
  if (!p || Object.keys(p).sort().join() !== 'approvalReference,browser,campaignReference,genesisHash,mint,schema,sourceRevision,sponsor' ||
    p.schema !== 1 || !/^[a-f0-9]{40}$/.test(p.sourceRevision) || !p.approvalReference?.trim() || !p.campaignReference?.trim() ||
    p.genesisHash !== STOCK_GENESIS || ![p.sponsor,p.mint,p.browser].every(isAddress) || new Set([p.sponsor,p.mint,p.browser]).size !== 3) throw Error('invalid source-bound fixed stock plan');
}
type RecordName = 'intent' | 'signed' | 'broadcast' | 'response' | 'receipt';
export class StockStore {
  private readonly identity: string;
  private readonly owner: number;
  readonly directory: string;
  constructor(directory: string) {
    this.directory=directory;
    const s = lstatSync(directory);
    if (!s.isDirectory() || s.isSymbolicLink() || (s.mode & 0o777) !== 0o700) throw Error('pre-created private stock directory required');
    this.identity = `${s.dev}:${s.ino}`; this.owner = s.uid;
  }
  private path(name: RecordName) {
    if (!['intent','signed','broadcast','response','receipt'].includes(name)) throw Error('invalid stock record');
    const s = lstatSync(this.directory);
    if (!s.isDirectory() || s.isSymbolicLink() || `${s.dev}:${s.ino}` !== this.identity || s.uid !== this.owner || (s.mode & 0o777) !== 0o700) throw Error('stock directory custody drift');
    return join(this.directory,`${name}.json`);
  }
  write(name: RecordName, value: unknown) { createDurableFile(this.path(name), encode(value)); }
  read(name: RecordName): Record<string, any> | null {
    const path = this.path(name); let fd: number;
    try { fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW); }
    catch (e) { if ((e as NodeJS.ErrnoException).code === 'ENOENT') return null; throw e; }
    try {
      const s = fstatSync(fd);
      if (!s.isFile() || s.nlink !== 1 || s.uid !== this.owner || (s.mode & 0o777) !== 0o600 || s.size > 64 * 1024) throw Error('unsafe stock record');
      return JSON.parse(readFileSync(fd,'utf8'));
    } finally { closeSync(fd); }
  }
}
function mintValue(a: LedgerAccount | null) {
  if (!a || a.owner !== TOKEN_PROGRAM_ADDRESS || a.executable || a.data.length !== getMintSize()) throw Error('invalid existing classic SPL mint');
  const mint = getMintDecoder().decode(a.data);
  if (!mint.isInitialized || mint.decimals !== 6 || isSome(mint.freezeAuthority)) throw Error('invalid existing test mint policy');
  return mint;
}
function wallet(a: LedgerAccount | null) {
  if (!a || a.owner !== SYSTEM_PROGRAM_ADDRESS || a.executable || a.data.length) throw Error('invalid sponsor wallet');
  return a;
}
async function stockTransaction(plan: StockPlan, lifetime: Lifetime, signers: KeyPairSigner[] = []) {
  const pool = await ata(plan.sponsor,plan.mint);
  return buildTransaction({feePayer:plan.sponsor,lifetime,signers,instructions:[
    getCreateAssociatedTokenIdempotentInstruction({payer:createNoopSigner(plan.sponsor),owner:plan.sponsor,mint:plan.mint,ata:pool}),
    getMintToInstruction({mint:plan.mint,token:pool,mintAuthority:createNoopSigner(plan.mint),amount:STOCK_AMOUNT}),
  ]});
}
export class FaucetStockOperator {
  private readonly planHash: string;
  readonly plan: Readonly<StockPlan>;
  readonly store: StockStore;
  readonly backend: ProvisionBackend;
  readonly budget: CampaignBudget;
  readonly admission: AdmissionJournal;
  constructor(plan: StockPlan, store: StockStore, backend: ProvisionBackend,
    budget: CampaignBudget, admission: AdmissionJournal) {
    this.store=store;this.backend=backend;this.budget=budget;this.admission=admission;
    validateStockPlan(plan); this.plan = Object.freeze({...plan}); this.planHash = digest(encode(plan));
    if (budget.policy.sponsor !== plan.sponsor || budget.policy.browser !== plan.browser || budget.policy.genesisHash !== plan.genesisHash ||
      budget.policy.reference !== plan.campaignReference || admission.policy.kind !== 'relay-attempts' || admission.policy.maximum !== 600) throw Error('existing campaign budget/admission required');
  }
  private async identity() { if (await this.backend.genesis() !== this.plan.genesisHash) throw Error('Devnet genesis mismatch'); }
  async quote() {
    await this.identity();
    if (['intent','signed','broadcast','response','receipt'].some(n=>this.store.read(n as RecordName)) || this.budget.hasReservation('faucet-stock')) throw Error('original stock action retained; observe only');
    const pool = await ata(this.plan.sponsor,this.plan.mint);
    const pre = await this.backend.snapshot([this.plan.sponsor,this.plan.mint,pool]);
    if (typeof pre.slot !== 'bigint' || pre.slot < 0n || pre.accounts.length !== 3) throw Error('invalid finalized stock snapshot');
    const sponsor = wallet(pre.accounts[0]!), mint = mintValue(pre.accounts[1]!);
    if (!isSome(mint.mintAuthority) || mint.mintAuthority.value !== this.plan.mint || pre.accounts[2] !== null || mint.supply + STOCK_AMOUNT > (1n<<64n)-1n) throw Error('stock authority/pool/supply mismatch');
    const rent = await this.backend.rent(getTokenSize()), lifetime = await this.backend.latest();
    const unsigned = await stockTransaction(this.plan,lifetime), fee = await this.backend.fee(unsigned);
    const ceiling = rent + STOCK_MAXIMUM_FEE;
    if (rent <= 0n || rent > STOCK_MAXIMUM_RENT || fee <= 0n || fee > STOCK_MAXIMUM_FEE ||
      sponsor.lamports - ceiling < STOCK_SPONSOR_FLOOR || ceiling > this.budget.summary().available || this.admission.summary().used >= 600) throw Error('stock quote exceeds campaign ceiling/floor/admission');
    return {pool,preSlot:pre.slot,supplyBefore:mint.supply,rent,fee,ceiling,lifetime,unsigned};
  }
  async issue(loadSigners: () => Promise<{sponsor: KeyPairSigner; mint: KeyPairSigner}>) {
    const q = await this.quote();
    // Exclusive fixed intent prevents signing twice, even after failed flush, crash or a new source revision.
    this.store.write('intent',{schema:1,plan:this.plan,planHash:this.planHash,pool:q.pool,preSlot:q.preSlot,supplyBefore:q.supplyBefore,
      rent:q.rent,fee:q.fee,lifetime:q.lifetime,unsigned:encodeTransaction(q.unsigned),messageHash:messageDigest(q.unsigned.messageBytes)});
    this.budget.reserve('faucet-stock','sponsorship',messageDigest(q.unsigned.messageBytes),{fees:STOCK_MAXIMUM_FEE,rent:q.rent,browserAllocation:0n});
    this.admission.reserve(); // Never reset or return this admission, even if signer loading fails.
    const signers = await loadSigners();
    if (signers.sponsor.address !== this.plan.sponsor || signers.mint.address !== this.plan.mint) throw Error('stock signer identity mismatch');
    const transaction = await stockTransaction(this.plan,q.lifetime,[signers.sponsor,signers.mint]);
    if (!Buffer.from(transaction.messageBytes).equals(Buffer.from(q.unsigned.messageBytes))) throw Error('stock signed message drift');
    const signature = getSignatureFromTransaction(transaction), wire = encodeTransaction(transaction);
    // Authenticate all signatures before recording broadcast intent or reaching submit.
    for (const address of [this.plan.sponsor,this.plan.mint]) {
      const bytes = transaction.signatures[address];
      if (!bytes || !await verifySignature(await getPublicKeyFromAddress(address),bytes as SignatureBytes,transaction.messageBytes)) throw Error('stock signature invalid');
    }
    this.store.write('signed',{schema:1,planHash:this.planHash,signature,wire,wireHash:digest(wire)});
    this.store.write('broadcast',{schema:1,planHash:this.planHash,signature});
    const result = await this.backend.submit(transaction);
    this.store.write('response',{schema:1,planHash:this.planHash,signature,result});
    return this.observe();
  }
  async observe() {
    await this.identity();
    const intent = this.store.read('intent');
    if (!intent || intent.schema !== 1 || intent.planHash !== this.planHash || encode(intent.plan) !== encode(this.plan)) throw Error('original source-bound stock intent required');
    const original = this.store.read('signed');
    if (!original) return {status:'UNKNOWN',reason:'original stock signature unavailable; never regenerate'};
    if (original.schema !== 1 || original.planHash !== this.planHash || digest(original.wire) !== original.wireHash) throw Error('original stock wire custody mismatch');
    const expected = await stockTransaction(this.plan,{blockhash:intent.lifetime.blockhash,lastValidBlockHeight:BigInt(intent.lifetime.lastValidBlockHeight)});
    const decoded = getTransactionDecoder().decode(getBase64Encoder().encode(original.wire));
    if (encodeTransaction(expected) !== intent.unsigned || messageDigest(expected.messageBytes) !== intent.messageHash ||
      !Buffer.from(decoded.messageBytes).equals(Buffer.from(expected.messageBytes)) || intent.pool !== await ata(this.plan.sponsor,this.plan.mint)) throw Error('original fixed stock message mismatch');
    const proof = await this.backend.finalized(original.signature);
    if (!proof) return {status:'UNKNOWN',signature:original.signature};
    const verified = await verifiedProof(original.signature,proof);
    if (proof.wire !== original.wire || verified.messageHash !== intent.messageHash || verified.message.staticAccounts[0] !== this.plan.sponsor) throw Error('stock finalized original mismatch');
    const status = proof.error === null ? 'FINALIZED_SUCCEEDED' : 'FINALIZED_FAILED';
    const receipt = {schema:1,planHash:this.planHash,status,signature:original.signature,slot:String(proof.slot),pool:intent.pool,
      minted:proof.error===null?String(STOCK_AMOUNT):'0',supplyBefore:intent.supplyBefore};
    const existing = this.store.read('receipt');
    if (existing && encode(existing) !== encode(receipt)) throw Error('stock original receipt drift');
    if (proof.error === null && !existing) {
      const post = await this.backend.snapshot([this.plan.mint,intent.pool,this.plan.sponsor],proof.slot);
      if (typeof post.slot !== 'bigint' || post.slot < proof.slot || post.accounts.length !== 3) throw Error('stock finalized snapshot unavailable');
      const mint = mintValue(post.accounts[0]!); wallet(post.accounts[2]!);
      const account = post.accounts[1];
      if (!account || account.owner !== TOKEN_PROGRAM_ADDRESS || account.executable || account.data.length !== getTokenSize()) throw Error('stock pool account mismatch');
      const token = getTokenDecoder().decode(account.data);
      if (!isSome(mint.mintAuthority) || mint.mintAuthority.value !== this.plan.mint || mint.supply !== BigInt(intent.supplyBefore)+STOCK_AMOUNT ||
        token.owner !== this.plan.sponsor || token.mint !== this.plan.mint || token.amount !== STOCK_AMOUNT || token.state !== AccountState.Initialized ||
        isSome(token.delegate) || isSome(token.closeAuthority) || isSome(token.isNative)) throw Error('stock finalized mint/pool mismatch');
      if (proof.preBalances[0]!-proof.postBalances[0]!-proof.fee !== BigInt(intent.rent)) throw Error('stock original rent outflow mismatch');
    }
    await this.budget.finalize('faucet-stock',original.signature,proof);
    if (!existing) this.store.write('receipt',receipt);
    return receipt;
  }
}
