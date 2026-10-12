// Append-only custody chain. A durable archive precedes each atomic order update.
// Any incomplete publication remains blocked; readers never repair or delete it.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
const hash = (s: string) => createHash('sha256').update(s).digest('hex');
type Lifetime = { blockhash:string; lastValidBlockHeight:string; blockhashSlot?:string };
type Draft = { id:string; payment:string; payer:string; reclaimUnsigned?:string; reclaimLifetime?:Lifetime };
type Archive = { schema:number; order:string; payment:string; payer:string; oldUnsigned:string; oldLifetime:Lifetime;
  oldConsent:string|null; proof:{kind:string;unsignedSha256:string;consentSha256:string|null}; newUnsigned:string; newLifetime:Lifetime };
export const nextReclaimArchive = (path:string, unsigned:string) => `${path}.reclaim-renewal-${hash(unsigned)}.lock`;
export function currentReclaimGeneration(path:string, order:Draft, dispatched:(wire:string)=>boolean): Archive | undefined {
  const first = `${path}.reclaim-renewal.lock`;
  if (!existsSync(first)) return undefined;
  const originalConsent = readFileSync(`${path}.reclaim-consent.lock`, 'utf8');
  let file = first, previous:Archive|undefined;
  const seen = new Set<string>();
  for (;;) {
    const a = JSON.parse(readFileSync(file,'utf8')) as Archive;
    if (a.schema !== 1 || a.order !== order.id || a.payment !== order.payment || a.payer !== order.payer ||
      typeof a.oldUnsigned !== 'string' || typeof a.newUnsigned !== 'string' || !a.oldLifetime || !a.newLifetime ||
      a.oldUnsigned === a.newUnsigned || a.oldLifetime.blockhash === a.newLifetime.blockhash ||
      a.proof?.kind !== 'expired-no-reclaim-effect' || a.proof.unsignedSha256 !== hash(a.oldUnsigned) ||
      a.oldConsent !== (previous ? null : originalConsent) || a.proof.consentSha256 !== (a.oldConsent === null ? null : hash(a.oldConsent)) ||
      dispatched(a.oldUnsigned) ||
      previous && (a.oldUnsigned !== previous.newUnsigned || JSON.stringify(a.oldLifetime) !== JSON.stringify(previous.newLifetime) ||
        existsSync(`${path}.reclaim-consent-${hash(a.oldUnsigned)}.lock`)) || seen.has(a.newUnsigned)) throw Error('Partial reclaim generation remains blocked.');
    seen.add(a.newUnsigned);
    const next = nextReclaimArchive(path,a.newUnsigned);
    if (!existsSync(next)) {
      if (order.reclaimUnsigned !== a.newUnsigned || JSON.stringify(order.reclaimLifetime) !== JSON.stringify(a.newLifetime)) throw Error('Partial reclaim generation remains blocked.');
      return a;
    }
    previous = a; file = next;
  }
}
