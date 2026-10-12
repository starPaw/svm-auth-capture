// Local invariant: admission consumed before signing survives concurrency, crash and restart.
// Separate from money, onchain authority and original operation journals. No automatic init.
import { createHash } from 'node:crypto';
import { closeSync, constants, existsSync, fstatSync, lstatSync, openSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { createDurableFile, replaceDurableFile, ensureDurableDirectory } from './durable-file.ts';

export type AdmissionPolicy = { schema: 1; kind: 'orders' | 'relay-attempts'; reference: string;
  maximum: number; carryForward: number; historicalActual: number | null; sourceSha256: string };
const encode = (value: unknown) => JSON.stringify(value, null, 2);
const hash = (value: string) => createHash('sha256').update(value).digest('hex');
function validate(p: AdmissionPolicy) {
  if (p.schema !== 1 || !['orders','relay-attempts'].includes(p.kind) || !p.reference?.trim() ||
    !Number.isSafeInteger(p.maximum) || !Number.isSafeInteger(p.carryForward) || p.carryForward < 0 ||
    p.maximum < p.carryForward || p.historicalActual !== null && (!Number.isSafeInteger(p.historicalActual) ||
    p.historicalActual < 0 || p.historicalActual > p.carryForward) || !/^[a-f0-9]{64}$/.test(p.sourceSha256)) throw Error('invalid admission policy');
}
export class AdmissionJournal {
  readonly policy: AdmissionPolicy;
  private readonly directory: string;
  private readonly directoryIdentity: string;
  private readonly lockIdentity: string;
  private readonly owner: number;
  private readonly flock = (createRequire(import.meta.url)('fs-ext') as typeof import('fs-ext')).flockSync;
  static initialize(directory: string, policy: AdmissionPolicy) {
    validate(policy);
    const s = lstatSync(directory);
    if (!s.isDirectory() || s.isSymbolicLink() || (s.mode & 0o777) !== 0o700) throw Error('pre-created private admission directory required');
    if (['policy.json','state.json','.lock'].some(name=>existsSync(join(directory,name)))) throw Error('existing/partial admission: never initialize again');
    ensureDurableDirectory(directory);
    // Partial initialization blocks reinitialization, including a crash before the lock write.
    createDurableFile(join(directory,'policy.json'), encode(policy));
    createDurableFile(join(directory,'state.json'), encode({schema:1,policyHash:hash(encode(policy)),used:policy.carryForward}));
    createDurableFile(join(directory,'.lock'), 'ADMISSION_LOCK_V1\n');
  }
  constructor(directory: string, kind: AdmissionPolicy['kind'], maximum: number) {
    this.directory = directory;
    const s = lstatSync(directory);
    if (!s.isDirectory() || s.isSymbolicLink() || (s.mode & 0o777) !== 0o700) throw Error('unsafe admission directory');
    this.owner = s.uid; this.directoryIdentity = `${s.dev}:${s.ino}`;
    const lock = this.file('.lock'); this.lockIdentity = `${lock.dev}:${lock.ino}`;
    this.policy = Object.freeze(JSON.parse(readFileSync(join(directory,'policy.json'),'utf8')) as AdmissionPolicy);
    validate(this.policy);
    if (this.policy.kind !== kind || this.policy.maximum !== maximum) throw Error('admission runtime/policy mismatch');
    this.withLock(() => this.state());
  }
  private file(name: string) {
    const s = lstatSync(join(this.directory,name));
    if (!s.isFile() || s.isSymbolicLink() || s.nlink !== 1 || s.uid !== this.owner || (s.mode & 0o777) !== 0o600) throw Error('unsafe admission record');
    return s;
  }
  private withLock<T>(fn: () => T): T {
    const d = lstatSync(this.directory), s = this.file('.lock');
    if (!d.isDirectory() || d.isSymbolicLink() || (d.mode & 0o777) !== 0o700 || d.uid !== this.owner || `${d.dev}:${d.ino}` !== this.directoryIdentity || `${s.dev}:${s.ino}` !== this.lockIdentity) throw Error('admission custody drift');
    const fd = openSync(join(this.directory,'.lock'), constants.O_RDWR | constants.O_NOFOLLOW);
    try {
      const opened = fstatSync(fd);
      if (`${opened.dev}:${opened.ino}` !== this.lockIdentity) throw Error('admission lock race');
      this.flock(fd,'exnb');
      try { return fn(); } finally { this.flock(fd,'un'); }
    } finally { closeSync(fd); }
  }
  private state(): {schema:1;policyHash:string;used:number} {
    this.file('policy.json'); this.file('state.json');
    if (readFileSync(join(this.directory,'policy.json'),'utf8') !== encode(this.policy)) throw Error('admission policy drift');
    const s = JSON.parse(readFileSync(join(this.directory,'state.json'),'utf8'));
    if (Object.keys(s).sort().join() !== 'policyHash,schema,used' || s.schema !== 1 || s.policyHash !== hash(encode(this.policy)) ||
      !Number.isSafeInteger(s.used) || s.used < this.policy.carryForward || s.used > this.policy.maximum) throw Error('admission state mismatch');
    return s;
  }
  summary() { return this.withLock(() => ({...this.policy,used:this.state().used})); }
  reserve(): void {
    this.withLock(() => {
      const s = this.state();
      if (s.used >= this.policy.maximum) throw Error('durable admission cap reached');
      s.used++;
      replaceDurableFile(join(this.directory,'state.json'),encode(s));
      // No rollback for any subsequent refusal, crash, failed read or lost response.
    });
  }
}
