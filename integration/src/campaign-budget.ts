// A local durable campaign spending journal, separate from funding and balances.
// All consumers serialize through one pinned flock inode. UNKNOWN retains its ceiling.
import { createHash } from 'node:crypto';
import { closeSync, constants, existsSync, fstatSync, lstatSync, openSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { isAddress, isSignature, type Address } from '@solana/kit';
import { SYSTEM_PROGRAM_ADDRESS, getTransferSolInstructionDataDecoder } from '@solana-program/system';
import { createDurableFile, replaceDurableFile, ensureDurableDirectory } from './durable-file.ts';
import { finalizedOutflow, type FinalizedTransaction } from './campaign-proof.ts';

export const CAMPAIGN_SPEND_LIMIT = 1_000_000_000n;
export type CampaignPolicy = { schema: 1; reference: string; genesisHash: string; sponsor: Address; browser: Address; spendLimit: '1000000000' };
export type Spend = { fees: bigint; rent: bigint; browserAllocation: bigint };
type Reservation = { payer: 'sponsor' | 'browser'; kind: 'assets' | 'sponsorship' | 'browser'; messageHash: string;
  ceiling: Record<keyof Spend, string>; outcome?: { signature: string; slot: string; failed: boolean; actual: Record<keyof Spend, string> } };
type State = { schema: 1; policyHash: string; entries: Record<string, Reservation> };
const encode = (v: unknown) => JSON.stringify(v, (_k, x) => typeof x === 'bigint' ? x.toString() : x, 2);
const hash = (v: string) => createHash('sha256').update(v).digest('hex');
function policyCheck(p: CampaignPolicy) {
  if (p.schema !== 1 || p.spendLimit !== String(CAMPAIGN_SPEND_LIMIT) || !p.reference?.trim() || !p.genesisHash?.trim() || !isAddress(p.sponsor) || !isAddress(p.browser) || p.sponsor === p.browser) throw Error('invalid fixed campaign policy');
}
function amounts(v: Record<keyof Spend, string>): Spend {
  if (!v || Object.keys(v).sort().join() !== 'browserAllocation,fees,rent' || Object.values(v).some(x => typeof x !== 'string' || !/^(0|[1-9][0-9]*)$/.test(x))) throw Error('invalid spending buckets');
  return { fees: BigInt(v.fees), rent: BigInt(v.rent), browserAllocation: BigInt(v.browserAllocation) };
}
const sum = (s: Spend) => s.fees + s.rent + s.browserAllocation;
function file(path: string) {
  const s = lstatSync(path);
  if (!s.isFile() || s.isSymbolicLink() || s.nlink !== 1 || (s.mode & 0o777) !== 0o600) throw Error('unsafe campaign record');
  return s;
}
export class CampaignBudget {
  readonly directory: string;
  readonly policy: CampaignPolicy;
  private readonly policyHash: string;
  private readonly owner: number;
  private readonly lockIdentity: string;
  private readonly directoryIdentity: string;
  private readonly flock: typeof import('fs-ext').flockSync;
  static initialize(directory: string, policy: CampaignPolicy): void {
    policyCheck(policy);
    const s = lstatSync(directory);
    if (!s.isDirectory() || s.isSymbolicLink() || (s.mode & 0o777) !== 0o700) throw Error('private pre-created campaign directory required');
    for (const name of ['policy.json', 'state.json', '.lock']) if (existsSync(join(directory, name))) throw Error('existing/partial campaign: never initialize again');
    ensureDurableDirectory(directory); // Flush the pre-created directory's ancestors before any admission.
    createDurableFile(join(directory, 'policy.json'), encode(policy));
    createDurableFile(join(directory, 'state.json'), encode({ schema: 1, policyHash: hash(encode(policy)), entries: {} }));
    createDurableFile(join(directory, '.lock'), 'CAMPAIGN_LOCK_V1\n');
  }
  constructor(directory: string, policy: CampaignPolicy) {
    policyCheck(policy); this.directory = directory; this.policy = Object.freeze({ ...policy }); this.policyHash = hash(encode(policy));
    const s = lstatSync(directory);
    if (!s.isDirectory() || s.isSymbolicLink() || (s.mode & 0o777) !== 0o700) throw Error('unsafe campaign directory');
    this.owner = s.uid;
    this.directoryIdentity = `${s.dev}:${s.ino}`;
    const lock = file(join(directory, '.lock')); this.lockIdentity = `${lock.dev}:${lock.ino}`;
    this.flock = (createRequire(import.meta.url)('fs-ext') as typeof import('fs-ext')).flockSync;
    this.withLock(() => this.state());
  }
  private withLock<T>(action: () => T): T {
    const d = lstatSync(this.directory);
    if (!d.isDirectory() || d.isSymbolicLink() || (d.mode & 0o777) !== 0o700 || `${d.dev}:${d.ino}` !== this.directoryIdentity || d.uid !== this.owner) throw Error('campaign directory drift');
    const path = join(this.directory, '.lock'); const s = file(path);
    if (s.uid !== this.owner) throw Error('campaign lock custody drift');
    if (`${s.dev}:${s.ino}` !== this.lockIdentity) throw Error('campaign lock replaced');
    const fd = openSync(path, constants.O_RDWR | constants.O_NOFOLLOW);
    try {
      const opened = fstatSync(fd);
      if (`${opened.dev}:${opened.ino}` !== this.lockIdentity) throw Error('campaign lock race');
      this.flock(fd, 'exnb');
      try { return action(); } finally { this.flock(fd, 'un'); }
    } finally { closeSync(fd); }
  }
  private state(): State {
    for (const name of ['policy.json', 'state.json']) if (file(join(this.directory, name)).uid !== this.owner) throw Error('campaign record custody drift');
    if (readFileSync(join(this.directory, 'policy.json'), 'utf8') !== encode(this.policy)) throw Error('campaign policy drift');
    const s = JSON.parse(readFileSync(join(this.directory, 'state.json'), 'utf8')) as State;
    if (s.schema !== 1 || s.policyHash !== this.policyHash || !s.entries || typeof s.entries !== 'object' || Array.isArray(s.entries)) throw Error('campaign state mismatch');
    let charged = 0n, browserUsed = 0n, browserCredit = 0n;
    const signatures = new Set<string>();
    for (const [id, e] of Object.entries(s.entries)) {
      if (!/^[a-z0-9-]{1,100}$/.test(id) || !/^[a-f0-9]{64}$/.test(e.messageHash) || !['assets', 'sponsorship', 'browser'].includes(e.kind) || !['sponsor', 'browser'].includes(e.payer) || (e.kind === 'browser') !== (e.payer === 'browser')) throw Error('invalid campaign entry');
      const ceiling = amounts(e.ceiling), actual = e.outcome ? amounts(e.outcome.actual) : ceiling;
      if (ceiling.fees <= 0n || e.kind !== 'assets' && ceiling.browserAllocation !== 0n || Object.keys(ceiling).some(k => actual[k as keyof Spend] > ceiling[k as keyof Spend])) throw Error('invalid campaign charge');
      if (e.outcome) {
        if (!isSignature(e.outcome.signature) || signatures.has(e.outcome.signature) || !/^[0-9]+$/.test(e.outcome.slot) || typeof e.outcome.failed !== 'boolean') throw Error('duplicate/invalid campaign outcome');
        signatures.add(e.outcome.signature);
        if (e.outcome.failed && (actual.rent !== 0n || actual.browserAllocation !== 0n)) throw Error('failed transaction nonfee charge');
      }
      if (e.payer === 'sponsor') charged += sum(actual); else browserUsed += sum(actual);
      if (e.kind === 'assets' && e.outcome && !e.outcome.failed) browserCredit += actual.browserAllocation;
    }
    if (charged > CAMPAIGN_SPEND_LIMIT || browserUsed > browserCredit) throw Error('campaign cap/allocated browser pool exceeded');
    return s;
  }
  hasReservation(id: string): boolean {
    return this.withLock(() => Object.hasOwn(this.state().entries, id));
  }
  summary() {
    return this.withLock(() => {
      const s = this.state(); let committed = 0n, reserved = 0n, browserUsed = 0n, browserCredit = 0n;
      for (const e of Object.values(s.entries)) {
        const amount = sum(amounts(e.outcome?.actual ?? e.ceiling));
        if (e.payer === 'browser') browserUsed += amount;
        else if (e.outcome) committed += amount; else reserved += amount;
        if (e.kind === 'assets' && e.outcome && !e.outcome.failed) browserCredit += BigInt(e.outcome.actual.browserAllocation);
      }
      return { limit: CAMPAIGN_SPEND_LIMIT, committed, reserved, available: CAMPAIGN_SPEND_LIMIT - committed - reserved, browserCredit, browserUsed };
    });
  }
  reserve(id: string, kind: Reservation['kind'], messageHash: string, ceiling: Spend): void {
    this.withLock(() => {
      const s = this.state();
      if (Object.hasOwn(s.entries, id)) throw Error('original campaign action reserved; never replace it');
      if (!['assets', 'sponsorship', 'browser'].includes(kind) || kind === 'assets' && Object.values(s.entries).some(e=>e.kind === 'assets')) throw Error('invalid/duplicate assets reservation');
      s.entries[id] = { kind, payer: kind === 'browser' ? 'browser' : 'sponsor', messageHash, ceiling: JSON.parse(encode(ceiling)) };
      // Validate the proposed total without persisting an over-cap admission.
      const totals = this.summaryFrom(s);
      if (totals.sponsor > CAMPAIGN_SPEND_LIMIT || totals.browser > totals.credit) throw Error('durable campaign budget exhausted');
      const c = amounts(s.entries[id]!.ceiling);
      if (!/^[a-z0-9-]{1,100}$/.test(id) || !/^[a-f0-9]{64}$/.test(messageHash) || c.fees <= 0n || kind !== 'assets' && c.browserAllocation !== 0n) throw Error('invalid budget reservation');
      replaceDurableFile(join(this.directory, 'state.json'), encode(s));
    });
  }
  private summaryFrom(s: State) {
    let sponsor = 0n, browser = 0n, credit = 0n;
    for (const e of Object.values(s.entries)) {
      const v = amounts(e.outcome?.actual ?? e.ceiling);
      if (e.payer === 'sponsor') sponsor += sum(v); else browser += sum(v);
      if (e.kind === 'assets' && e.outcome && !e.outcome.failed) credit += v.browserAllocation;
    }
    return { sponsor, browser, credit };
  }
  async finalize(id: string, signature: string, proof: FinalizedTransaction): Promise<void> {
    const entry = this.withLock(() => {const entries=this.state().entries;return Object.hasOwn(entries,id)?entries[id]:undefined;});
    if (!entry) throw Error('missing original budget reservation');
    const payer = entry.payer === 'sponsor' ? this.policy.sponsor : this.policy.browser;
    const result = await finalizedOutflow(signature, proof, payer, entry.messageHash);
    const cap = amounts(entry.ceiling);
    const allocation = result.failed ? 0n : cap.browserAllocation;
    if (allocation > 0n) {
      const transfers = result.message.instructions.filter(ix => result.message.staticAccounts[ix.programAddressIndex] === SYSTEM_PROGRAM_ADDRESS && ix.data?.length === 12 && getTransferSolInstructionDataDecoder().decode(ix.data).discriminator === 2);
      if (transfers.length !== 1) throw Error('allocation requires one original browser transfer');
      const ix = transfers[0]!;
      if (ix.accountIndices?.length !== 2 || result.message.staticAccounts[ix.accountIndices[0]!] !== this.policy.sponsor || result.message.staticAccounts[ix.accountIndices[1]!] !== this.policy.browser || getTransferSolInstructionDataDecoder().decode(ix.data!).amount !== allocation) throw Error('browser allocation message mismatch');
      const index = result.message.staticAccounts.indexOf(this.policy.browser);
      if (index < 0 || proof.postBalances[index]! - proof.preBalances[index]! !== allocation) throw Error('browser allocation finalized delta mismatch');
    }
    const actual = { fees: result.fees, rent: result.nonFeeOutflow - allocation, browserAllocation: allocation };
    if (actual.rent < 0n || Object.keys(actual).some(k => actual[k as keyof Spend] > cap[k as keyof Spend])) throw Error('finalized spend exceeds original reservation');
    this.withLock(() => {
      const s = this.state(), original = s.entries[id];
      if (!original || encode(original.ceiling) !== encode(entry.ceiling) || original.messageHash !== entry.messageHash) throw Error('budget reservation drift');
      const outcome = { signature, slot: String(result.slot), failed: result.failed, actual: JSON.parse(encode(actual)) };
      if (original.outcome) { if (encode(original.outcome) !== encode(outcome)) throw Error('conflicting original budget proof'); return; }
      if (Object.values(s.entries).some(e => e.outcome?.signature === signature)) throw Error('signature already charged under another action');
      original.outcome = outcome;
      replaceDurableFile(join(this.directory, 'state.json'), encode(s));
    });
  }
}
