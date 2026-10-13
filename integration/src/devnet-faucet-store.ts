// Test-token distribution only. Durable wallet/global quotas and one original wire;
// no escrow state, authority, admission reset, automatic initialization or resend.
import { createHash } from 'node:crypto';
import { closeSync, constants, existsSync, fstatSync, lstatSync, openSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { isAddress, isSignature, type Address } from '@solana/kit';
import { createDurableFile, ensureDurableDirectory, replaceDurableFile } from './durable-file.ts';

export const FAUCET_AMOUNT = 1_000_000_000n;
export const FAUCET_COOLDOWN_SECONDS = 86_400;
export const FAUCET_MAXIMUM_CLAIMS = 100;
export type FaucetPolicy = { schema: 1; reference: string; network: string; genesisHash: string;
  mint: Address; sponsor: Address; pool: Address; origin: string; maximumClaims: 100;
  amount: '1000000000'; cooldownSeconds: 86400 };
export type FaucetEntry = { id: string; recipient: Address; requestedAt: number;
  consent: { message: string; signature: string; tokenSha256: string; issuedAt: number; expiresAt: number };
  stage: 'reserved' | 'signing' | 'signed' | 'refused' | 'finalized';
  messageHash?: string; unsigned?: string; budgetId?: string; signed?: string;
  signature?: string; blockhash?: string; lastValidBlockHeight?: string;
  outcome?: { slot: string; succeeded: boolean } };
type State = { schema: 1; policyHash: string; entries: Record<string, FaucetEntry> };
const encode = (value: unknown) => JSON.stringify(value, null, 2);
const hash = (value: string) => createHash('sha256').update(value).digest('hex');
const active = (e: FaucetEntry) => ['reserved','signing','signed'].includes(e.stage);
export class FaucetQuotaRefusal extends Error {}
export function validateFaucetPolicy(p: FaucetPolicy) {
  if (!p || Object.keys(p).sort().join() !== 'amount,cooldownSeconds,genesisHash,maximumClaims,mint,network,origin,pool,reference,schema,sponsor' ||
    p.schema !== 1 || !p.reference?.trim() || p.network !== 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1' ||
    p.genesisHash !== 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG' ||
    ![p.mint,p.sponsor,p.pool].every(isAddress) || p.maximumClaims !== FAUCET_MAXIMUM_CLAIMS ||
    p.amount !== String(FAUCET_AMOUNT) || p.cooldownSeconds !== FAUCET_COOLDOWN_SECONDS ||
    new URL(p.origin).origin !== p.origin || !p.origin.startsWith('https://')) throw Error('invalid fixed Devnet faucet policy');
}

export class DevnetFaucetStore {
  readonly policy: Readonly<FaucetPolicy>;
  private readonly directory: string;
  private readonly owner: number;
  private readonly directoryIdentity: string;
  private readonly lockIdentity: string;
  private readonly flock = (createRequire(import.meta.url)('fs-ext') as typeof import('fs-ext')).flockSync;
  static initialize(directory: string, policy: FaucetPolicy) {
    validateFaucetPolicy(policy);
    const s = lstatSync(directory);
    if (!s.isDirectory() || s.isSymbolicLink() || (s.mode & 0o777) !== 0o700) throw Error('pre-created private faucet directory required');
    if (['policy.json','state.json','.lock'].some(n=>existsSync(join(directory,n)))) throw Error('existing or partial faucet initialization; never reset');
    ensureDurableDirectory(directory);
    createDurableFile(join(directory,'policy.json'),encode(policy));
    createDurableFile(join(directory,'state.json'),encode({schema:1,policyHash:hash(encode(policy)),entries:{}}));
    createDurableFile(join(directory,'.lock'),'DEVNET_FAUCET_LOCK_V1\n');
  }
  constructor(directory: string, policy: FaucetPolicy) {
    validateFaucetPolicy(policy); this.directory=directory; this.policy=Object.freeze({...policy});
    const s=lstatSync(directory);
    if (!s.isDirectory() || s.isSymbolicLink() || (s.mode & 0o777)!==0o700) throw Error('unsafe faucet directory');
    this.owner=s.uid;this.directoryIdentity=`${s.dev}:${s.ino}`;
    const lock=this.file('.lock');this.lockIdentity=`${lock.dev}:${lock.ino}`;
    this.withLock(()=>this.state());
  }
  private file(name: string) {
    const s=lstatSync(join(this.directory,name));
    if (!s.isFile() || s.isSymbolicLink() || s.nlink!==1 || s.uid!==this.owner || (s.mode & 0o777)!==0o600) throw Error('unsafe faucet record');
    return s;
  }
  private withLock<T>(fn:()=>T):T {
    const d=lstatSync(this.directory),s=this.file('.lock');
    if (!d.isDirectory() || d.isSymbolicLink() || d.uid!==this.owner || (d.mode & 0o777)!==0o700 ||
      `${d.dev}:${d.ino}`!==this.directoryIdentity || `${s.dev}:${s.ino}`!==this.lockIdentity) throw Error('faucet custody drift');
    const fd=openSync(join(this.directory,'.lock'),constants.O_RDWR|constants.O_NOFOLLOW);
    try {
      const opened=fstatSync(fd);if(`${opened.dev}:${opened.ino}`!==this.lockIdentity)throw Error('faucet lock race');
      this.flock(fd,'exnb');try{return fn();}finally{this.flock(fd,'un');}
    } finally {closeSync(fd);}
  }
  private state():State {
    this.file('policy.json');this.file('state.json');
    if(readFileSync(join(this.directory,'policy.json'),'utf8')!==encode(this.policy))throw Error('faucet policy drift');
    const s=JSON.parse(readFileSync(join(this.directory,'state.json'),'utf8')) as State;
    if(!s || Object.keys(s).sort().join()!=='entries,policyHash,schema' || s.schema!==1 || s.policyHash!==hash(encode(this.policy)) ||
      !s.entries || typeof s.entries!=='object' || Array.isArray(s.entries) || Object.keys(s.entries).length>FAUCET_MAXIMUM_CLAIMS)throw Error('invalid faucet state');
    const signatures=new Set<string>();let inFlight=0;
    for(const [id,e] of Object.entries(s.entries)) {
      if(!/^[a-f0-9]{64}$/.test(id) || !e || e.id!==id || !isAddress(e.recipient) || e.recipient===this.policy.sponsor ||
        !Number.isSafeInteger(e.requestedAt) || e.requestedAt<=0 || !['reserved','signing','signed','refused','finalized'].includes(e.stage) ||
        !e.consent || typeof e.consent.message!=='string' || e.consent.message.length>2048 || !/^[A-Za-z0-9+/]{86}==$/.test(e.consent.signature) ||
        !/^[a-f0-9]{64}$/.test(e.consent.tokenSha256) || !Number.isSafeInteger(e.consent.issuedAt) || e.consent.expiresAt!==e.consent.issuedAt+600)throw Error('invalid faucet claim');
      if(active(e))inFlight++;
      if(e.messageHash!==undefined && (!/^[a-f0-9]{64}$/.test(e.messageHash) || typeof e.unsigned!=='string' || e.budgetId!==`faucet-${id}` ||
        !isAddress(e.blockhash??'') || !/^[0-9]+$/.test(e.lastValidBlockHeight??'')))throw Error('invalid faucet original message');
      if(['signing','signed','finalized'].includes(e.stage) && e.messageHash===undefined)throw Error('partial faucet signing state');
      if(['signed','finalized'].includes(e.stage) && (!isSignature(e.signature??'') || typeof e.signed!=='string'))throw Error('partial faucet original wire');
      if(e.signature) {if(signatures.has(e.signature))throw Error('duplicate faucet signature');signatures.add(e.signature);}
      if(['reserved','refused','signing'].includes(e.stage) && (e.signature!==undefined || e.signed!==undefined))throw Error('partial faucet signature custody');
      if(e.stage==='finalized' && (!e.outcome || !/^[0-9]+$/.test(e.outcome.slot) || typeof e.outcome.succeeded!=='boolean'))throw Error('invalid faucet finality');
      if(e.stage!=='finalized' && e.outcome!==undefined)throw Error('faucet outcome/stage mismatch');
    }
    if(inFlight>1)throw Error('concurrent faucet signing state');
    return s;
  }
  private write(s:State) {replaceDurableFile(join(this.directory,'state.json'),encode(s));}
  get(id:string):FaucetEntry|undefined {
    if(!/^[a-f0-9]{64}$/.test(id))throw Error('invalid faucet claim identifier');
    return this.withLock(()=>this.state().entries[id]);
  }
  pending():FaucetEntry[] {return this.withLock(()=>Object.values(this.state().entries).filter(active));}
  summary() {return this.withLock(()=>({used:Object.keys(this.state().entries).length,maximum:FAUCET_MAXIMUM_CLAIMS}));}
  nextEligibleAt(recipient:Address):number {
    return this.withLock(()=>Math.max(0,...Object.values(this.state().entries).filter(e=>e.recipient===recipient).map(e=>e.requestedAt+FAUCET_COOLDOWN_SECONDS)));
  }
  reserve(id:string,recipient:Address,now:number,consent:FaucetEntry['consent']):FaucetEntry {
    return this.withLock(()=>{
      const s=this.state();
      if(!/^[a-f0-9]{64}$/.test(id) || !isAddress(recipient) || recipient===this.policy.sponsor || !Number.isSafeInteger(now) || now<=0)throw Error('invalid faucet recipient/intent');
      if(s.entries[id])throw Error('original faucet claim already retained; never repeat');
      if(Object.values(s.entries).some(active))throw new FaucetQuotaRefusal('Original faucet operation pending or unknown. New economics stopped.');
      if(Object.keys(s.entries).length>=FAUCET_MAXIMUM_CLAIMS)throw new FaucetQuotaRefusal('The total test-token claim limit has been reached.');
      if(Object.values(s.entries).some(e=>e.recipient===recipient && now<e.requestedAt+FAUCET_COOLDOWN_SECONDS))throw new FaucetQuotaRefusal('This wallet may request 1000 test tokens once per 24 hours.');
      if(!consent || typeof consent.message!=='string' || consent.message.length>2048 || !/^[A-Za-z0-9+/]{86}==$/.test(consent.signature) ||
        !/^[a-f0-9]{64}$/.test(consent.tokenSha256) || !Number.isSafeInteger(consent.issuedAt) || consent.expiresAt!==consent.issuedAt+600)throw Error('invalid faucet consent');
      const e:FaucetEntry={id,recipient,requestedAt:now,consent:{...consent},stage:'reserved'};s.entries[id]=e;this.write(s);return e;
    });
  }
  prepare(id:string,original:Pick<FaucetEntry,'messageHash'|'unsigned'|'budgetId'|'blockhash'|'lastValidBlockHeight'>) {
    this.withLock(()=>{const s=this.state(),e=s.entries[id];if(!e || e.stage!=='reserved' || e.messageHash!==undefined)throw Error('faucet preparation already retained');
      if(!/^[a-f0-9]{64}$/.test(original.messageHash??'') || original.budgetId!==`faucet-${id}` || !isAddress(original.blockhash??'') || !/^[0-9]+$/.test(original.lastValidBlockHeight??'') || !original.unsigned)throw Error('invalid faucet preparation');
      Object.assign(e,original);this.write(s);});
  }
  signing(id:string) {this.withLock(()=>{const s=this.state(),e=s.entries[id];if(!e || e.stage!=='reserved' || !e.messageHash)throw Error('faucet signing already attempted');e.stage='signing';this.write(s);});}
  signed(id:string,signature:string,wire:string) {this.withLock(()=>{const s=this.state(),e=s.entries[id];if(!e || e.stage!=='signing' || !isSignature(signature) || !wire)throw Error('invalid or repeated faucet signing');e.signature=signature;e.signed=wire;e.stage='signed';this.write(s);});}
  refuseBeforeSigning(id:string) {this.withLock(()=>{const s=this.state(),e=s.entries[id];if(!e || e.stage!=='reserved')throw Error('possible faucet signing must remain UNKNOWN');e.stage='refused';this.write(s);});}
  finalize(id:string,signature:string,slot:bigint,succeeded:boolean) {
    this.withLock(()=>{const s=this.state(),e=s.entries[id];if(!e || e.signature!==signature || slot<0n)throw Error('faucet original finality mismatch');
      const outcome={slot:String(slot),succeeded};
      if(e.stage==='finalized') {if(encode(e.outcome)!==encode(outcome))throw Error('faucet finality drift');return;}
      if(e.stage!=='signed')throw Error('missing signed faucet original');e.outcome=outcome;e.stage='finalized';this.write(s);});
  }
}
