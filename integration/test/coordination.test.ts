import { afterEach, describe, expect, test } from "vitest";
import { fork, type ChildProcess } from "node:child_process";
import { chmodSync, linkSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, renameSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { enrollRecoveryDomain, RecoveryDomain, type DomainPaths } from "../src/coordination.ts";
import { COORDINATION_FILE, DOMAIN_ROLES } from "../src/coordination-schema.ts";
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
    await domain.run("exclusive", async () => { expect(readFileSync(join(paths.orders, `${"a".repeat(32)}.json.busy`), "utf8")).toBe("beer"); });
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
  let effects = 0; await expect(domain.run("exclusive",async () => { effects++; })).rejects.toThrow(); expect(effects).toBe(0);
});
test("aliases and incomplete enrollment refuse; unconfigured new writers stop at enrollment metadata", () => {
  const { paths, root } = fixture(); symlinkSync(paths.orders,join(root,"alias"));
  expect(() => new RecoveryDomain({ ...paths, orders: join(root,"alias") })).toThrow();
  expect(() => new RestaurantOrders(paths.orders).read("a".repeat(32))).toThrow();
  unlinkSync(join(paths.reclaim,COORDINATION_FILE)); expect(() => new RecoveryDomain(paths)).toThrow();
});
