// The static regression always runs. Set SAC006_TEST_NGINX to an nginx executable
// for HTTPS requests through the deployment fragment and real backend.
import { execFileSync, spawn, spawnSync, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { request } from "node:https";
import { createServer, type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { serve, type ServerType } from "@hono/node-server";
import { getMintToInstruction } from "@solana-program/token";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { demoSponsorComputeBounds } from "../src/demo-compute.js";
import { decodeHeader } from "../src/http-transport.js";
import { OperationStore } from "../src/operation-store.js";
import { createRestaurantApp, DEMO_BUDGET, RestaurantOrders, type RestaurantConfig } from "../src/restaurant.js";
import { createPresentationApp } from "../src/restaurant-server.js";
import { FileSubmissionJournal } from "../src/submission-journal.js";
import { createHarness, type Harness } from "./fixture.js";

const fragmentPath = fileURLToPath(new URL("../deploy/nginx-resource.conf", import.meta.url));
const fragment = readFileSync(fragmentPath, "utf8");
const devFragmentPath = fileURLToPath(new URL("../deploy/dev/nginx-routes.conf", import.meta.url));
const devFragment = readFileSync(devFragmentPath, "utf8");

test("the development proxy routes only to its restaurant and never retries payment requests", () => {
  expect([...devFragment.matchAll(/proxy_pass\s+(\S+);/g)].map(match => match[1]))
    .toEqual(Array(5).fill("http://127.0.0.1:18888"));
  expect(devFragment).toContain("proxy_next_upstream off;");
  expect(devFragment).toContain("location / { return 404; }");
});

test("the browser's POST order-creation endpoint has an exact public nginx route", () => {
  const browser = readFileSync(new URL("../web/app.js", import.meta.url), "utf8");
  const endpoint = browser.match(/request\('([^']+)',\s*\{\s*method:\s*'POST'/)?.[1];
  expect(endpoint).toBe("/api/orders");
  const routes = [...fragment.matchAll(/location\s+=\s+\/api\/orders\s*\{([\s\S]*?)\n\}/g)];
  expect(routes, "order creation must not fall through to the /api/ deny rule").toHaveLength(1);
  expect(routes[0]![1]).toMatch(/if\s*\(\$request_method\s*!=\s*POST\)\s*\{\s*return\s+405;/);
  expect(routes[0]![1]).toMatch(/proxy_pass\s+http:\/\/127\.0\.0\.1:8788\s*;/);
});

const nginxBin = process.env.SAC006_TEST_NGINX;
for (const [environment, testedFragmentPath, upstreamPort] of [
  ["stable", fragmentPath, 8788], ["development", devFragmentPath, 18888],
] as const) {
describe.skipIf(!nginxBin)(`${environment} deployment fragment through nginx HTTPS (SAC006_TEST_NGINX)`, () => {
  let h: Harness, config: RestaurantConfig, backend: ServerType | undefined;
  let nginx: ChildProcess | undefined, dir: string | undefined, origin: string, ca: Buffer;
  const upstream: { path: string; method: string; headers: Headers }[] = [];
  let nginxOutput = "";

  async function https(path: string, method = "GET", headers: Record<string, string> = {}, body?: string) {
    return new Promise<{ status: number; headers: import("node:http").IncomingHttpHeaders; body: string }>((resolve, reject) => {
      const req = request(new URL(path, origin), { method, headers, ca, agent: false }, res => {
        const chunks: Buffer[] = [];
        res.on("data", chunk => chunks.push(Buffer.from(chunk)));
        res.on("error", reject);
        res.on("end", () => resolve({ status: res.statusCode!, headers: res.headers, body: Buffer.concat(chunks).toString() }));
      });
      req.on("error", reject);
      req.setTimeout(5_000, () => req.destroy(new Error("nginx request timed out")));
      req.end(body);
    });
  }

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "capture402-nginx-"));
    writeFileSync(join(dir, "certificate.conf"), `[req]
distinguished_name=dn
x509_extensions=ext
prompt=no
[dn]
CN=localhost
[ext]
subjectAltName=IP:127.0.0.1,DNS:localhost
basicConstraints=critical,CA:TRUE
`);
    execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-config", join(dir, "certificate.conf"), "-keyout", join(dir, "key.pem"), "-out", join(dir, "certificate.pem")], { stdio: "pipe" });
    ca = readFileSync(join(dir, "certificate.pem"));
    const reservation = createServer();
    reservation.listen(0, "127.0.0.1"); await once(reservation, "listening");
    const port = (reservation.address() as AddressInfo).port;
    await new Promise<void>((resolve, reject) => reservation.close(error => error ? reject(error) : resolve()));
    origin = `https://127.0.0.1:${port}`;
    writeFileSync(join(dir, "nginx.conf"), `daemon off;
master_process off;
pid "${dir}/nginx.pid";
error_log stderr notice;
events { worker_connections 64; }
http {
  access_log off;
  client_body_temp_path "${dir}/body";
  proxy_temp_path "${dir}/proxy";
  server {
    listen 127.0.0.1:${port} ssl;
    server_name localhost;
    ssl_certificate "${dir}/certificate.pem";
    ssl_certificate_key "${dir}/key.pem";
    include "${testedFragmentPath}";
  }
}
`);
    const version = spawnSync(nginxBin!, ["-V"], { encoding: "utf8" });
    const validation = spawnSync(nginxBin!, ["-t", "-e", "stderr", "-p", `${dir}/`, "-c", join(dir, "nginx.conf")], { encoding: "utf8" });
    const evidence = `${version.stdout}${version.stderr}${validation.stdout}${validation.stderr}`;
    console.info(evidence);
    expect(version.status, evidence).toBe(0);
    expect(validation.status, evidence).toBe(0);

    h = await createHarness(demoSponsorComputeBounds());
    h.ok(await h.direct([getMintToInstruction({ mint: h.mint, token: await h.payerAta(), mintAuthority: h.setup, amount: 1_000_000_000n })]));
    const ledger = Object.assign(h.ledger, {
      getSignatureStatus: async () => ({ kind: "not-found" as const }),
      getAccountAtLeast: async (address: import("@solana/kit").Address) => ({ kind: "ok" as const, slot: 1n, account: await h.ledger.getAccount(address) }),
    });
    config = {
      merchantToken: "local-nginx-merchant-credential-0123456789", bearerToken: "local-nginx-facilitator-credential",
      facilitatorUrl: h.url, network: h.ledger.network, programId: h.facilitator.programId,
      feePayer: h.facilitatorKey.address, server: h.server, asset: h.mint, amount: DEMO_BUDGET,
      captureDeadlineSeconds: 150, refundDeadlineSeconds: 30, origin, ledger,
      store: new OperationStore(join(dir, "legacy")), orders: new RestaurantOrders(join(dir, "orders")),
      reclaimJournal: new FileSubmissionJournal(join(dir, "reclaim")),
      now: () => h.ledger.now(), getLatestBlockhash: async () => h.lifetime(),
      handler: async () => { throw new Error("unused legacy handler"); },
    };
    const app = createPresentationApp({ programId: config.programId, network: config.network, configured: true }, createRestaurantApp(config));
    // Use the fragment's actual fixed upstream; fail if the port is occupied.
    await new Promise<void>((resolve, reject) => {
      backend = serve({ port: upstreamPort, hostname: "127.0.0.1", fetch: req => {
        upstream.push({ path: new URL(req.url).pathname, method: req.method, headers: req.headers });
        return app.fetch(req);
      } }, () => resolve());
      backend.on("error", reject);
    });
    nginx = spawn(nginxBin!, ["-e", "stderr", "-p", `${dir}/`, "-c", join(dir, "nginx.conf")], { stdio: ["ignore", "pipe", "pipe"] });
    nginx.stderr!.on("data", chunk => { nginxOutput += chunk.toString(); });
    let ready = false;
    for (let attempt = 0; attempt < 50; attempt++) {
      if (nginx.exitCode !== null) throw new Error(`nginx exited: ${nginxOutput}`);
      try { if ((await https("/api/config")).status === 200) { ready = true; break; } } catch { /* bounded startup retry */ }
      await delay(100);
    }
    expect(ready, nginxOutput).toBe(true);
  });

  afterAll(async () => {
    if (nginx && nginx.exitCode === null) { const closed = once(nginx, "exit"); nginx.kill("SIGTERM"); await closed; }
    if (backend?.listening) await new Promise<void>((resolve, reject) => backend!.close(error => error ? reject(error) : resolve()));
    await h?.close();
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  test("homepage is isolated and exact assets are GET-only through both real proxies", async () => {
    const root = await https("/");
    expect(root.status).toBe(200); expect(root.body).toContain("Authorize once.");
    expect(root.body).not.toContain('src="/assets/app.js"');
    for (const path of ["/customer", "/merchant"]) {
      const demo = await https(path); expect(demo.status).toBe(200); expect(demo.body).toContain("Pivovar Marina");
    }
    if (environment === "development") {
      expect(root.headers["x-robots-tag"]).toBe("noindex, nofollow");
      expect(root.headers["cache-control"]).toBe("no-store");
    }
    for (const [name, mime] of [["homepage.css", "text/css"], ["homepage.js", "text/javascript"]]) {
      const asset = await https(`/assets/${name}`); expect(asset.status).toBe(200);
      expect(asset.headers["content-type"]).toBe(`${mime}; charset=utf-8`);
      const before = upstream.length;
      for (const method of ["HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]) expect((await https(`/assets/${name}`, method)).status).toBe(405);
      for (const path of [`/assets/${name}/`, `/assets/${name}.extra`]) expect((await https(path)).status).toBe(404);
      expect(upstream).toHaveLength(before);
    }
    expect(h.ledger.submissions).toHaveLength(0);
  });

  test("same-origin POST returns the real 402 offer, PAYMENT-REQUIRED and secure session cookie", async () => {
    const result = await https("/api/orders", "POST", { origin, "content-type": "application/json", "sec-fetch-site": "same-origin" }, JSON.stringify({ payer: h.payer.address, scenario: "normal" }));
    expect(result.status).toBe(402);
    const body = JSON.parse(result.body);
    expect(body.order).toMatch(/^[a-f0-9]{32}$/); expect(body.unsigned).toBeTruthy();
    expect(decodeHeader(result.headers["payment-required"] as string)).toEqual(body.required);
    expect(body.required).toMatchObject({ x402Version: 2, resource: { url: `${origin}/resource` }, accepts: [{ amount: "100000000" }] });
    const cookie = result.headers["set-cookie"]![0]!;
    for (const attribute of ["HttpOnly", "Secure", "SameSite=Strict", "Path=/"]) expect(cookie).toContain(attribute);
    expect(result.headers["x-content-type-options"]).toBe("nosniff");
    expect(result.headers["content-security-policy"]).toContain("default-src 'self'");
    if (environment === "development") {
      expect(result.headers["x-capture402-environment"]).toBe("development");
      expect(result.headers["cache-control"]).toBe("no-store");
      expect(result.headers["x-robots-tag"]).toBe("noindex, nofollow");
    }
    const received = upstream.at(-1)!;
    expect(received).toMatchObject({ path: "/api/orders", method: "POST" });
    expect(received.headers.get("origin")).toBe(origin);
    expect(received.headers.get("x-forwarded-proto")).toBe("https");
    expect(received.headers.get("x-forwarded-for")).toBe("127.0.0.1");
    expect(received.headers.get("host")).toBe("127.0.0.1");
    const before = upstream.length;
    expect((await https(`/api/orders/${body.order}`, "GET", { cookie: cookie.split(";")[0]! })).status).toBe(200);
    expect(upstream).toHaveLength(before + 1);
    expect(h.ledger.submissions).toHaveLength(0);
  });

  test("order-action GET preflight passes the same bearer boundary through HTTPS without economics", async () => {
    const prepared = await https("/api/orders", "POST", { origin, "content-type": "application/json" }, JSON.stringify({ payer: h.payer.address }));
    const { order } = JSON.parse(prepared.body);
    const files = readdirSync(config.orders.dir).sort(), simulations = h.ledger.simulated.length;
    const path = `/api/orders/${order}/actions/beer`;
    for (const token of [undefined, "incorrect", config.bearerToken]) {
      expect((await https(path, "GET", token ? { authorization: `Bearer ${token}` } : {})).status).toBe(401);
    }
    const access = await https(path, "GET", { authorization: `Bearer ${config.merchantToken}` });
    expect(access.status).toBe(200);
    expect(JSON.parse(access.body)).toMatchObject({ id: order, operatorAccess: true, actions: { beer: false } });
    expect(access.headers["cache-control"]).toBe("no-store");
    expect(access.body).not.toContain(config.merchantToken);
    expect(readdirSync(config.orders.dir).sort()).toEqual(files);
    expect(h.ledger.simulated).toHaveLength(simulations); expect(h.ledger.submissions).toHaveLength(0);
  });

  test.each(["GET", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"])("%s /api/orders returns 405 before reaching the backend", async method => {
    const before = upstream.length;
    expect((await https("/api/orders", method)).status).toBe(405);
    expect(upstream).toHaveLength(before);
  });

  test.each(["/api/orders/", "/api/orders-other", "/api/private", "/api/orders/invalid", `/api/orders/${"a".repeat(32)}/actions/unrelated`, `/api/orders/${"a".repeat(32)}/reclaim/`, "/assets/private.js", "/settle", "/verify", "/supported", "/json/list", "/.git/config"])("%s remains private or outside the allowlist", async path => {
    const before = upstream.length;
    for (const method of ["GET", "POST"]) expect((await https(path, method, { origin })).status).toBe(404);
    expect(upstream).toHaveLength(before);
  });

  test.each([undefined, "null", "https://attacker.invalid"])("order creation preserves the backend Origin gate: %s", async suppliedOrigin => {
    const files = readdirSync(config.orders.dir), simulations = h.ledger.simulated.length;
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (suppliedOrigin) headers.origin = suppliedOrigin;
    const result = await https("/api/orders", "POST", headers, JSON.stringify({ payer: h.payer.address }));
    expect(result.status).toBe(403); expect(result.headers["set-cookie"]).toBeUndefined();
    expect(readdirSync(config.orders.dir)).toEqual(files); expect(h.ledger.simulated).toHaveLength(simulations);
  });

  test("JSON and body-limit gates survive proxying", async () => {
    const files = readdirSync(config.orders.dir), simulations = h.ledger.simulated.length;
    expect((await https("/api/orders", "POST", { origin, "content-type": "text/plain" }, "{}")).status).toBe(415);
    const before = upstream.length;
    expect((await https("/api/orders", "POST", { origin, "content-type": "application/json" }, "x".repeat(32_769))).status).toBe(413);
    expect(upstream).toHaveLength(before);
    expect(readdirSync(config.orders.dir)).toEqual(files); expect(h.ledger.simulated).toHaveLength(simulations);
  });

  test.each([undefined, "local-nginx-facilitator-credential"])("merchant routes reject unauthorized callers before lookup: %s", async token => {
    const headers: Record<string, string> = { origin };
    if (token) headers.authorization = `Bearer ${token}`;
    expect((await https(`/api/orders/${"a".repeat(32)}/actions/beer`, "POST", headers)).status).toBe(401);
    expect(h.ledger.submissions).toHaveLength(0);
  });
});
}
