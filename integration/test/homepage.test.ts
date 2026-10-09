import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { Hono } from "hono";
import { expect, test } from "vitest";
import { createPresentationApp } from "../src/restaurant-server.js";

const web = new URL("../web/", import.meta.url);
const html = readFileSync(new URL("homepage.html", web), "utf8");
const proof = JSON.parse(readFileSync(new URL("homepage-proof.json", web), "utf8"));
const app = () => createPresentationApp({ programId: "not-the-historical-program", network: "test", configured: false });

test("root is a separate static homepage; both restaurant routes and CSP are preserved", async () => {
  const ui = app();
  const root = await ui.request("/");
  expect(await root.text()).toBe(html);
  const demo = readFileSync(new URL("index.html", web), "utf8");
  for (const path of ["/customer", "/merchant"]) {
    const response = await ui.request(path);
    expect(await response.text()).toBe(demo);
    expect(response.headers.get("content-security-policy")).toBe(root.headers.get("content-security-policy"));
  }
  expect(root.headers.get("content-security-policy")).not.toMatch(/unsafe-inline|unsafe-eval/);
  expect(root.headers.get("x-content-type-options")).toBe("nosniff");
  expect(html).toContain('content="noindex,nofollow"');
  expect([...html.matchAll(/(?:src|href)="(\/assets\/[^\"]+)"/g)].map(m => m[1]))
    .toEqual(["/assets/homepage.css", "/assets/homepage.js"]);
  expect(html).not.toMatch(/<style|<script[^>]*>[^<]+|\sstyle=|\sonclick=/);
});

test.each([["homepage.css", "text/css"], ["homepage.js", "text/javascript"]])("only the exact GET asset %s is served", async (name, mime) => {
  const ui = app();
  const response = await ui.request(`/assets/${name}`);
  expect(response.status).toBe(200);
  expect(response.headers.get("content-type")).toBe(`${mime}; charset=utf-8`);
  expect(await response.text()).toBe(readFileSync(new URL(name, web), "utf8"));
  for (const method of ["HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]) {
    expect((await ui.request(`/assets/${name}`, { method })).status).toBe(405);
  }
  for (const path of [`/assets/${name}/`, `/assets/${name}.extra`, "/assets/homepage-proof.json"]) {
    expect((await ui.request(path)).status).toBe(404);
  }
});

test("loading homepage and assets never calls economic backend or config", async () => {
  const requests: string[] = [];
  const backend = new Hono();
  backend.all("*", c => { requests.push(c.req.path); return c.text("unexpected backend", 500); });
  const ui = createPresentationApp({ programId: "unconfigured", network: "test", configured: false }, backend);
  for (const route of ["/", "/assets/homepage.css", "/assets/homepage.js"]) expect((await ui.request(route)).status).toBe(200);
  expect(requests).toEqual([]);
  const script = readFileSync(new URL("homepage.js", web), "utf8");
  expect(script).not.toMatch(/\b(fetch|XMLHttpRequest|WebSocket|localStorage|sessionStorage|solana|solflare)\b|\/api\//);
});

test("static evidence includes every full historical identity, URL, slot and correct H/F", () => {
  expect(proof.transactions).toHaveLength(4);
  const audit = readFileSync(new URL(`../../docs/evidence/sac-006/runs/${proof.runId}/paced-live-audit.json`, import.meta.url), "utf8");
  const states = [["100", "0"], ["70", "30"], ["0", "50"], ["0", "35"]];
  proof.transactions.forEach((record: any, index: number) => {
    expect(record.err).toBeNull(); expect(record.commitment).toBe("finalized"); expect(record.exactWireMatch).toBe(true);
    expect(record.explorerUrl).toBe(`https://explorer.solana.com/tx/${record.signature}?cluster=devnet`);
    expect(html).toContain(`href="${record.explorerUrl}"`);
    for (const value of [record.signature, record.slot, record.wireSha256]) { expect(html).toContain(value); expect(audit).toContain(value); }
    expect([record.result.held, record.result.refundable]).toEqual(states[index]);
    expect(html).toContain(`Held ${record.result.held} · Captured, unrefunded ${record.result.refundable}`);
  });
  expect(proof.finalSnapshot).toMatchObject({ held: "0", grossCaptured: "50", releasedUnused: "50", refunded: "15", capturedUnrefunded: "35" });
  expect(Number(proof.finalSnapshot.grossCaptured) - Number(proof.finalSnapshot.refunded)).toBe(35);
  for (const key of ["runSourceRevision", "recordedAuditAt", "programId", "paymentId", "mint", "sbfSha256"]) expect(html).toContain(proof[key]);
  expect(html).toContain("07 Oct 2026 · Test-token base units · Recorded evidence");
  for (const source of proof.sourceFiles) {
    // Evidence URLs pin historical bytes; current architecture docs may evolve.
    const prefix = "https://github.com/starPaw/svm-auth-capture/blob/";
    expect(source.url.startsWith(prefix)).toBe(true);
    const revision = source.url.slice(prefix.length).split("/")[0];
    expect(revision).toMatch(/^[0-9a-f]{40}$/);
    expect(source.url).toBe(`${prefix}${revision}/${source.path}`);
    const content = execFileSync("git", ["show", `${revision}:${source.path}`], {
      cwd: fileURLToPath(new URL("../../", import.meta.url)),
      maxBuffer: 8 * 1024 * 1024,
    });
    expect(createHash("sha256").update(content).digest("hex")).toBe(source.sha256);
    expect(html).toContain(source.sha256); expect(html).toContain(source.url);
  }
  expect(html).toContain("not a live service-status indicator or validation of the current website release");
  expect(html).toContain("upgrade authority"); expect(html).toContain("Private repository — access required.");
});

test("critical lifecycle, refund and reclaim copy survives without JS and assets stay within budgets", () => {
  expect([...html.matchAll(/data-step-panel=/g)]).toHaveLength(4);
  expect([...html.matchAll(/<h1\b/g)]).toHaveLength(1);
  expect(html).toContain("unused 50 in the same operation");
  expect(html).toContain("cannot be topped up or reopened");
  expect(html).toContain("It does not restore the spending budget");
  expect(html).toContain("Funds do not move automatically");
  for (const [name, budget] of [["homepage.js", 20_000], ["homepage.css", 25_000]] as const) {
    expect(gzipSync(readFileSync(new URL(name, web))).byteLength).toBeLessThan(budget);
  }
  expect(gzipSync(Buffer.from(html)).byteLength + gzipSync(readFileSync(new URL("homepage.css", web))).byteLength + gzipSync(readFileSync(new URL("homepage.js", web))).byteLength).toBeLessThan(200_000);
});
