// Exact inert metadata schema shared by writers and the no-network quarantine reader.
export const COORDINATION_FILE = ".coordination.lock";
export const DOMAIN_ROLES = ["facilitator", "operations", "orders", "reclaim"] as const;
export const DOMAIN_WRITERS = ["facilitator", "payer", "resource", "restaurant"] as const;
export type DomainRole = typeof DOMAIN_ROLES[number];
export type Member = { role: DomainRole; path: string; device: string; inode: string; lockDevice: string; lockInode: string };
export type CoordinationMetadata = { version: 1; protocol: "flock-v1"; domain: string; role: DomainRole; members: Member[]; writers: typeof DOMAIN_WRITERS[number][] };
function requireValid(ok: unknown): asserts ok { if (!ok) throw new Error("invalid coordination metadata"); }
function keys(v: any, names: string[]) { requireValid(v && typeof v === "object" && !Array.isArray(v) && Object.keys(v).sort().join() === [...names].sort().join()); }
export function coordinationMetadata(raw: string): CoordinationMetadata {
  requireValid(new TextEncoder().encode(raw).length <= 16384);
  const v = JSON.parse(raw); keys(v, ["version", "protocol", "domain", "role", "members", "writers"]);
  requireValid(v.version === 1 && v.protocol === "flock-v1" && /^[a-f0-9]{32}$/.test(v.domain) && DOMAIN_ROLES.includes(v.role));
  requireValid(Array.isArray(v.writers) && JSON.stringify(v.writers) === JSON.stringify(DOMAIN_WRITERS));
  requireValid(Array.isArray(v.members) && v.members.length === DOMAIN_ROLES.length);
  const paths = new Set(), identities = new Set();
  v.members.forEach((m: any, i: number) => {
    keys(m, ["role", "path", "device", "inode", "lockDevice", "lockInode"]);
    requireValid(m.role === DOMAIN_ROLES[i] && typeof m.path === "string" && m.path.startsWith("/") && !m.path.includes("\0") && m.path.length < 4096 && m.path.split("/").slice(1).every((p: string) => p && p !== "." && p !== ".."));
    requireValid(typeof m.device === "string" && typeof m.inode === "string" && /^(0|[1-9][0-9]*)$/.test(m.device) && /^[1-9][0-9]*$/.test(m.inode));
    requireValid(typeof m.lockInode === "string" && m.lockDevice === m.device && /^[1-9][0-9]*$/.test(m.lockInode) && m.lockInode !== m.inode);
    requireValid(!paths.has(m.path) && !identities.has(`${m.device}:${m.inode}`)); paths.add(m.path); identities.add(`${m.device}:${m.inode}`);
  });
  // Canonical bytes also reject duplicate keys/BOM/extra whitespace without a permissive parser.
  requireValid(raw === JSON.stringify(v));
  return v;
}
export function coordinationSet(records: { role: string; raw: string }[]): CoordinationMetadata | undefined {
  if (!records.length) return undefined; // Legacy stores stay legacy; no recovery admission.
  requireValid(records.length === DOMAIN_ROLES.length);
  const metadata = records.map(r => { const m = coordinationMetadata(r.raw); requireValid(m.role === r.role); return m; });
  const first = metadata[0]!;
  for (const m of metadata) requireValid(m.domain === first.domain && JSON.stringify(m.members) === JSON.stringify(first.members) && JSON.stringify(m.writers) === JSON.stringify(first.writers));
  requireValid(new Set(metadata.map(m => m.role)).size === DOMAIN_ROLES.length);
  return first;
}
