// Kernel flock ownership is in this Node process, with no keeper process or lock deletion.
import { AsyncLocalStorage } from "node:async_hooks";
import { randomBytes } from "node:crypto";
import { constants, closeSync, existsSync, fstatSync, lstatSync, openSync, readFileSync, realpathSync, statfsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import fsExt from "fs-ext";
import { createDurableFile } from "./durable-file.ts";
import { COORDINATION_FILE, DOMAIN_ROLES, DOMAIN_WRITERS, coordinationMetadata, coordinationSet, type CoordinationMetadata, type DomainRole } from "./coordination-schema.ts";
export type DomainPaths = Record<DomainRole, string>;
const context = new AsyncLocalStorage<CoordinationToken>();
const fail = (): never => { throw new Error("coordination refused: incomplete, changed or unsafe domain"); };
function trusted(path: string) {
  if (path !== resolve(path) || realpathSync(path) !== path) fail();
  for (let p = path;; p = dirname(p)) {
    const s = lstatSync(p, { bigint: true });
    // A root-owned sticky temporary ancestor cannot let another UID replace our child.
    const stickyRoot = s.uid === 0n && (s.mode & 0o1000n) !== 0n && p !== path;
    if (!s.isDirectory() || s.isSymbolicLink() || (s.uid !== 0n && s.uid !== BigInt(process.getuid!())) || ((s.mode & 0o022n) !== 0n && !stickyRoot)) fail();
    if (dirname(p) === p) break;
  }
  // Local durable storage only. NFS/SMB/FUSE/overlay/tmpfs and unknown types refuse.
  const type = statfsSync(path, { bigint: true }).type;
  if (!(process.platform === "darwin" && [0x1an, 0x11n].includes(type) || process.platform === "linux" && [0xef53n, 0x58465342n, 0x9123683en].includes(type))) fail();
  return lstatSync(path, { bigint: true });
}
function fileIdentity(path: string, fd: number) {
  const a = lstatSync(path, { bigint: true }), b = fstatSync(fd, { bigint: true });
  if (!a.isFile() || a.isSymbolicLink() || a.nlink !== 1n || a.uid !== BigInt(process.getuid!()) || a.mode !== (0o100000n | 0o600n) || a.size > 16384n || a.dev !== b.dev || a.ino !== b.ino) fail();
  return `${a.dev}:${a.ino}`;
}
export class CoordinationToken {
  readonly domain: RecoveryDomain;
  readonly mode: "shared" | "exclusive";
  private live = true;
  constructor(domain: RecoveryDomain, mode: "shared" | "exclusive") { this.domain = domain; this.mode = mode; }
  assert() { if (!this.live) fail(); this.domain.verify(); }
  invalidate() { this.live = false; }
}
export class RecoveryDomain {
  readonly metadata: CoordinationMetadata;
  private ancestry: { path: string; identity: string }[] = [];
  private pins: { path: string; identity: string; raw: string }[];
  constructor(paths: DomainPaths) {
    const records = DOMAIN_ROLES.map(role => ({ role, raw: readFileSync(join(paths[role], COORDINATION_FILE), "utf8") }));
    this.metadata = coordinationSet(records)!;
    this.pins = this.metadata.members.map(m => {
      if (paths[m.role] !== m.path) fail();
      const s = trusted(m.path); if (s.dev.toString() !== m.device || s.ino.toString() !== m.inode) fail();
      const path = join(m.path, COORDINATION_FILE), fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
      try { const identity = fileIdentity(path, fd), raw = readFileSync(fd, "utf8"); coordinationMetadata(raw); return { path, identity, raw }; }
      finally { closeSync(fd); }
    }).sort((a,b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
    const parents = new Map<string, string>();
    for (const m of this.metadata.members) for (let path = m.path;; path = dirname(path)) {
      const s = lstatSync(path, { bigint: true }); parents.set(path, `${s.dev}:${s.ino}`);
      if (dirname(path) === path) break;
    }
    this.ancestry = [...parents].map(([path, identity]) => ({ path, identity }));
    this.verify();
  }
  verify() {
    for (const p of this.ancestry) { const s = lstatSync(p.path, { bigint: true }); if (`${s.dev}:${s.ino}` !== p.identity) fail(); }
    for (const m of this.metadata.members) { const s = trusted(m.path); if (s.dev.toString() !== m.device || s.ino.toString() !== m.inode) fail(); }
    for (const p of this.pins) {
      const fd = openSync(p.path, constants.O_RDONLY | constants.O_NOFOLLOW);
      try { if (fileIdentity(p.path, fd) !== p.identity || readFileSync(fd, "utf8") !== p.raw) fail(); } finally { closeSync(fd); }
    }
  }
  assertMember(path: string) { if (!this.metadata.members.some(m => m.path === path)) fail(); }
  /** Future recovery callers must supply a trusted deployment verifier, never metadata alone.
   * It must inspect the complete host capability/activation inventory and reject legacy or
   * external writers. There is intentionally no default verifier or application command. */
  async recoveryFence<T>(verifyDeployment: ((token: CoordinationToken) => Promise<boolean>) | undefined, action: (token: CoordinationToken) => Promise<T>, waitMs = 2000): Promise<T> {
    if (!verifyDeployment) fail();
    return this.run("exclusive", async token => {
      if (await verifyDeployment!(token) !== true) fail();
      token.assert(); return action(token);
    }, waitMs);
  }
  async run<T>(mode: "shared" | "exclusive", action: (token: CoordinationToken) => Promise<T>, waitMs = 2000): Promise<T> {
    if (!Number.isFinite(waitMs) || waitMs <= 0 || waitMs > 60_000) fail();
    const held = context.getStore();
    if (held) {
      held.assert();
      // Nested calls reuse the whole-domain token. No upgrade, no second domain/order.
      if (held.domain.metadata.domain !== this.metadata.domain || held.mode !== mode) fail();
      this.verify(); return action(held);
    }
    const deadline = performance.now() + waitMs;
    const fds: number[] = [];
    const token = new CoordinationToken(this, mode);
    try {
      this.verify();
      // Retain trusted directory handles alongside each locked inode for the full operation.
      for (const m of this.metadata.members) {
        const fd = openSync(m.path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW); fds.push(fd);
        const s = fstatSync(fd, { bigint: true }); if (s.dev.toString() !== m.device || s.ino.toString() !== m.inode) fail();
      }
      for (const p of this.pins) {
        const fd = openSync(p.path, constants.O_RDONLY | constants.O_NOFOLLOW); fds.push(fd);
        if (fileIdentity(p.path, fd) !== p.identity || readFileSync(fd, "utf8") !== p.raw) fail();
        for (;;) {
          if (performance.now() >= deadline) throw new Error("coordination wait deadline exceeded");
          try { fsExt.flockSync(fd, mode === "shared" ? "shnb" : "exnb"); break; }
          catch (e) { if (!["EAGAIN", "EWOULDBLOCK"].includes((e as NodeJS.ErrnoException).code ?? "")) throw e; }
          await new Promise(r => setTimeout(r, Math.min(10, Math.max(1, deadline - performance.now()))));
        }
      }
      token.assert();
      return await context.run(token, () => action(token));
    } finally {
      token.invalidate();
      // close releases the kernel lock even on thrown errors. SIGKILL closes every descriptor.
      for (const fd of fds.reverse()) closeSync(fd);
    }
  }
}
/** Offline maintenance primitive only. Never invoked by application startup or recovery. */
export function enrollRecoveryDomain(paths: DomainPaths) {
  const domain = randomBytes(16).toString("hex");
  const members = DOMAIN_ROLES.map(role => { const path = paths[role], s = trusted(path); return { role, path, device: s.dev.toString(), inode: s.ino.toString() }; });
  if (new Set(members.map(m => `${m.device}:${m.inode}`)).size !== members.length) fail();
  for (const m of members) if (existsSync(join(m.path, COORDINATION_FILE))) fail();
  // Failure leaves a partial enrollment that every coordinated writer/recovery refuses.
  for (const m of members) createDurableFile(join(m.path, COORDINATION_FILE), JSON.stringify({ version: 1, protocol: "flock-v1", domain, role: m.role, members, writers: [...DOMAIN_WRITERS] }));
  return new RecoveryDomain(paths);
}
export function domainFromEnvironment(): RecoveryDomain | undefined {
  const raw = process.env.SAC006_COORDINATION_PATHS;
  if (!raw) return undefined;
  const paths = JSON.parse(raw); if (Object.keys(paths).sort().join() !== [...DOMAIN_ROLES].sort().join()) fail();
  return new RecoveryDomain(paths);
}
export function assertStoreAccess(path: string, domain?: RecoveryDomain) {
  if (!domain) { if (existsSync(join(path, COORDINATION_FILE))) fail(); return; }
  domain.assertMember(path);
  const token = context.getStore(); if (!token || token.domain.metadata.domain !== domain.metadata.domain) throw new Error("coordination token required");
  token.assert(); domain.verify();
}
export async function withShared<T>(domain: RecoveryDomain | undefined, action: (token?: CoordinationToken) => Promise<T>) {
  return domain ? domain.run("shared", action) : action();
}
