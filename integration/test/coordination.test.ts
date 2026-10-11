import { afterEach, describe, expect, test } from "vitest";
import { fork, type ChildProcess } from "node:child_process";
import { chmodSync, linkSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, renameSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { enrollRecoveryDomain, RecoveryDomain, withShared, type DomainPaths } from "../src/coordination.ts";
import { COORDINATION_FILE, DOMAIN_ROLES, coordinationMetadata } from "../src/coordination-schema.ts";
import { FileSubmissionJournal } from "../src/submission-journal.ts";
import { RestaurantOrders } from "../src/restaurant.ts";
const roots: string[] = [], children: ChildProcess[] = [];
afterEach(() => { for (const c of children.splice(0)) c.kill("SIGKILL"); for (const p of roots.splice(0)) rmSync(p, { recursive: true, force: true }); });
function fixture() {
  const root = mkdtempSync(join(realpathSync(tmpdir()), "coordination-")); roots.push(root);
  const paths = Object.fromEntries(DOMAIN_ROLES.map(role => { const p = join(root, role); mkdirSync(p, { mode: 0o700 }); return [role,p]; })) as DomainPaths;
  return { root, paths, domain: enrollRecoveryDomain(paths) };
}
function worker(paths: DomainPaths, mode = "shared", wait = 2000, id = "a".repeat(32)) {
  const c = fork(resolve("test/fixtures/coordination-worker.ts"), [JSON.stringify(paths), mode, String(wait), id], { execArgv: ["--experimental-strip-types"], stdio: ["ignore", "ignore", "pipe", "ipc"] }); children.push(c);
  const messages: string[] = []; const pending: { m: string; resolve: () => void }[] = [];
  c.on("message", m => { messages.push(String(m)); for (const p of pending) if (p.m === m) p.resolve(); });
  let error = ""; c.stderr?.on("data", d => { error += d; });
  return { c, messages, receive(m: string) { if (messages.includes(m)) return Promise.resolve(); return new Promise<void>((resolve,reject) => { const timer = setTimeout(() => reject(new Error(`worker missing ${m}: ${error}`)), 4000); pending.push({ m, resolve: () => { clearTimeout(timer); resolve(); } }); }); } };
}
describe("real kernel multiprocess coordination", () => {
  test("shared/shared permits a nested cross-process writer even while exclusive waits", async () => {
    const { paths } = fixture(); const a = worker(paths); await a.receive("entered");
    const x = worker(paths, "exclusive", 800); await x.receive("ready");
    const b = worker(paths, "shared", 2000, "b".repeat(32)); await b.receive("entered");
    expect(x.messages).not.toContain("entered");
    b.c.send("release"); await b.receive("released");
    a.c.send("release"); await a.receive("released"); await x.receive("entered"); x.c.send("release"); await x.receive("released");
  });
  test("exclusive blocks shared with one bounded wait across the complete domain", async () => {
    const { paths } = fixture(); const a = worker(paths, "exclusive"); await a.receive("entered");
    const before = Date.now(), b = worker(paths, "shared", 80); await b.receive("refused");
    expect(b.messages).not.toContain("entered"); expect(Date.now() - before).toBeLessThan(1800);
    a.c.send("release"); await a.receive("released");
  });
  test("SIGKILL releases only process locks; busy and action reservations remain", async () => {
    const { paths, domain } = fixture(); const a = worker(paths); await a.receive("entered");
    const exit = new Promise(r => a.c.once("exit", r)); a.c.kill("SIGKILL"); await exit;
    await domain.run("exclusive", async () => { expect(readFileSync(join(paths.orders, `${"a".repeat(32)}.json.busy`), "utf8")).toBe("beer");
      expect(JSON.parse(readFileSync(join(paths.orders, `${"a".repeat(32)}.json.beer.lock`), "utf8"))).toMatchObject({ action:"beer",status:"prepared" });
      expect(JSON.parse(readFileSync(join(paths.orders, `${"a".repeat(32)}.json`), "utf8"))).toMatchObject({ status:"pending" });
    });
  });
  test("same-process nesting reuses token; upgrade and second domain refuse", async () => {
    const { domain } = fixture(), other = fixture();
    await domain.run("shared", async token => {
      await domain.run("shared", async nested => { expect(nested).toBe(token); });
      await expect(domain.run("exclusive", async () => {})).rejects.toThrow();
      await expect(other.domain.run("shared", async () => {})).rejects.toThrow();
    });
  });
  test("post-result callbacks cannot use an expired token or mutate an enrolled store", async () => {
    const { domain, paths } = fixture(); const journal = new FileSubmissionJournal(paths.facilitator, { coordination: domain });
    let late!: () => void;
    await domain.run("shared", async token => { late = () => { token.assert(); journal.resolve("synthetic", { result: "unresolved", recordedAt: new Date().toISOString() }); }; });
    expect(late).toThrow(); expect(() => journal.prepare({} as never)).toThrow();
  });
});
test.each(["inode", "symlink", "hardlink", "corrupt", "missing", "weak-mode"])("refuses %s coordination member without effects", async kind => {
  const { domain, paths, root } = fixture(), p = join(paths.orders, COORDINATION_FILE);
  const raw = readFileSync(p);
  if (kind === "inode") { renameSync(p, join(root,"old")); writeFileSync(p,raw, { mode:0o600 }); }
  if (kind === "symlink" || kind === "hardlink") { renameSync(p,join(root,"old")); if (kind === "symlink") symlinkSync(join(root,"old"),p); else linkSync(join(root,"old"),p); }
  if (kind === "corrupt") writeFileSync(p,"{}");
  if (kind === "missing") unlinkSync(p);
  if (kind === "weak-mode") chmodSync(p,0o644);
  expect(() => new RecoveryDomain(paths)).toThrow();
  let effects = 0; await expect(domain.run("exclusive",async () => { effects++; })).rejects.toThrow(); expect(effects).toBe(0);
});
test("aliases and incomplete enrollment refuse; unconfigured new writers stop at enrollment metadata", () => {
  const { paths, root } = fixture(); symlinkSync(paths.orders,join(root,"alias"));
  expect(() => new RecoveryDomain({ ...paths, orders: join(root,"alias") })).toThrow();
  expect(() => new RestaurantOrders(paths.orders).read("a".repeat(32))).toThrow();
  unlinkSync(join(paths.reclaim,COORDINATION_FILE)); expect(() => new RecoveryDomain(paths)).toThrow();
});
test("recovery admission refuses absent, incomplete or legacy-writer deployment proof", async () => {
  const { domain } = fixture(); let effects = 0;
  await expect(domain.recoveryFence(undefined, async () => { effects++; })).rejects.toThrow();
  await expect(domain.recoveryFence(async () => false, async () => { effects++; })).rejects.toThrow();
  expect(effects).toBe(0);
});

test("real unsupported devfs refuses before enrollment or recovery", () => {
  const { paths } = fixture();
  expect(() => enrollRecoveryDomain({ ...paths, facilitator:realpathSync("/dev") })).toThrow(/unsupported filesystem/);
});
test("directory replacement and writable ancestry refuse both existing and restarted processes", async () => {
  const { paths, domain, root } = fixture();
  renameSync(paths.orders,join(root,"original-orders")); mkdirSync(paths.orders,{ mode:0o700 });
  writeFileSync(join(paths.orders,COORDINATION_FILE),readFileSync(join(root,"original-orders",COORDINATION_FILE)),{ mode:0o600 });
  expect(() => new RecoveryDomain(paths)).toThrow(); await expect(domain.run("exclusive",async () => {})).rejects.toThrow();
  chmodSync(root,0o777); expect(() => new RecoveryDomain(paths)).toThrow();
});
test("dangling symlink metadata never becomes an unenrolled legacy writer", () => {
  const { paths,root } = fixture(), p = join(paths.reclaim,COORDINATION_FILE); unlinkSync(p); symlinkSync(join(root,"absent"),p);
  expect(() => new FileSubmissionJournal(paths.reclaim).assertAccess()).toThrow(); expect(() => new RecoveryDomain(paths)).toThrow();
});
test("oversized and non-regular lock bytes refuse before parsing or effects", () => {
  const { paths } = fixture(), p = join(paths.reclaim,COORDINATION_FILE); writeFileSync(p,"x".repeat(16385));
  expect(() => new RecoveryDomain(paths)).toThrow(); unlinkSync(p); mkdirSync(p,{ mode:0o700 }); expect(() => new RecoveryDomain(paths)).toThrow();
});

test("identity substitution while token is held refuses the next durable mutation", async () => {
  const { paths,root,domain } = fixture(), p = join(paths.orders,COORDINATION_FILE);
  await domain.run("shared",async () => {
    const raw = readFileSync(p); renameSync(p,join(root,"old-lock")); writeFileSync(p,raw,{ mode:0o600 });
    expect(() => new RestaurantOrders(paths.orders,domain).reserve("b".repeat(32),"beer")).toThrow();
    expect(() => readFileSync(join(paths.orders,`${"b".repeat(32)}.json.busy`))).toThrow();
  });
});

test("exclusive recovery scope cannot enter even an unconfigured ordinary writer", async () => {
  const { domain } = fixture(); let effects = 0;
  await domain.run("exclusive",async () => { await expect(withShared(undefined,async () => { effects++; })).rejects.toThrow(); });
  expect(effects).toBe(0);
});

test.each(["device", "inode", "lockInode"])("strict metadata rejects numeric %s just like the host quarantine reader", field => {
  const { domain } = fixture(), m = structuredClone(domain.metadata); (m.members[0] as any)[field] = Number((m.members[0] as any)[field]);
  if (field === "device") (m.members[0] as any).lockDevice = Number(m.members[0]!.device);
  expect(() => coordinationMetadata(JSON.stringify(m))).toThrow();
});
test("pure quarantine schema uses the same raw-byte bound as native writer and host readers", () => {
  const { domain } = fixture(), m = structuredClone(domain.metadata);
  m.members.forEach((v,i) => { v.path = "/" + String(i).repeat(4090); });
  expect(() => coordinationMetadata(JSON.stringify(m))).toThrow();
});
