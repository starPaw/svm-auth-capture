// Static presentation remains available before provisioning. An unconfigured backend returns
// 503; it never fabricates balances, receipts or signatures, or substitutes generated keys.
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { createKeyPairSignerFromBytes, type Address } from "@solana/kit";
import { getMintDecoder } from "@solana-program/token";
import { loadDeploymentRecord } from "./deployment-record.ts";
import { createRestaurantApp, RestaurantOrders, DEMO_BUDGET, type RestaurantConfig } from "./restaurant.ts";
import { DEMO_COMPUTE } from "./demo-compute.ts";
import { OperationStore } from "./operation-store.ts";
import { FileSubmissionJournal } from "./submission-journal.ts";
import { RpcLedger, cachedClusterClock } from "./rpc-ledger.ts";
import { TOKEN_PROGRAM_ADDRESS } from "./program.ts";

export const DEMO_TIMING = { captureSeconds: 150, refundSecondsAfterCapture: 30 } as const;
const root = fileURLToPath(new URL("../web/", import.meta.url));
export function createPresentationApp(info: { programId: string; network: string; configured: boolean; reason?: string; sponsor?: string; merchant?: string; mint?: string }, backend?: Hono): Hono {
  const app = new Hono();
  app.use("*", async (c, next) => {
    c.header("X-Content-Type-Options", "nosniff");
    c.header("Referrer-Policy", "no-referrer");
    c.header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-src https://connect.solflare.com; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    await next();
  });
  app.all("/assets/homepage.css", async (c, next) => { if (c.req.method !== "GET") return c.body(null, 405); await next(); });
  app.all("/assets/homepage.js", async (c, next) => { if (c.req.method !== "GET") return c.body(null, 405); await next(); });
  app.get("/", c => c.html(readFileSync(`${root}homepage.html`, "utf8")));
  for (const route of ["/customer", "/merchant"]) app.get(route, c => c.html(readFileSync(`${root}index.html`, "utf8")));
  for (const [name, mime] of [["homepage.css", "text/css"], ["homepage.js", "text/javascript"], ["app.js", "text/javascript"], ["wallet.js", "text/javascript"], ["style.css", "text/css"], ["solflare.js", "text/javascript"], ["solflare.js.LEGAL.txt", "text/plain"]]) app.get(`/assets/${name}`, c => { c.header("Content-Type", `${mime}; charset=utf-8`); return c.body(readFileSync(`${root}${name}`)); });
  app.get("/api/config", c => c.json({ ...info, venue: "Pivovar Marina", budget: 100, decimals: 6, assetLabel: "demo USDC", cluster: "devnet", walletChain: "solana:devnet", computeBudget: DEMO_COMPUTE, timing: DEMO_TIMING }));
  if (backend) app.route("/", backend);
  else { for (const pattern of ["/api/*", "/resource"]) app.all(pattern, c => c.json({ error: "Devnet demo awaits keypairs, six-decimal test mint and token funding." }, 503)); }
  return app;
}
async function main() {
  const recordPath = process.env.SAC006_DEPLOYMENT_RECORD_PATH;
  if (!recordPath) throw new Error("SAC006_DEPLOYMENT_RECORD_PATH required");
  const record = loadDeploymentRecord(recordPath);
  const names = ["SOLANA_RPC_URL", "SAC006_BEARER_TOKEN", "SAC006_FACILITATOR_URL", "SAC006_FEE_PAYER", "SAC006_SERVER_KEYPAIR_PATH", "SAC006_STORE_DIR", "SAC006_ASSET_MINT"];
  const missing = names.filter(n => !process.env[n]);
  if (process.env.SAC006_SERVER_KEYPAIR_PATH && !existsSync(process.env.SAC006_SERVER_KEYPAIR_PATH)) missing.push("merchant key file");
  const info = { programId: record.programId, network: record.network.caip2, configured: false, reason: "Provisioning required" };
  let backend: Hono | undefined;
  if (missing.length === 0) {
    const ledger = new RpcLedger({ deployment: record, network: record.network.caip2, genesisHash: record.network.genesisHash, rpcUrl: process.env.SOLANA_RPC_URL! });
    await ledger.verifyGenesis();
    const server = await createKeyPairSignerFromBytes(Uint8Array.from(JSON.parse(readFileSync(process.env.SAC006_SERVER_KEYPAIR_PATH!, "utf8"))));
    const mint = await ledger.getAccount(process.env.SAC006_ASSET_MINT as Address);
    if (!mint || mint.owner !== TOKEN_PROGRAM_ADDRESS || mint.data.length !== getMintDecoder().fixedSize || !getMintDecoder().decode(mint.data).isInitialized || getMintDecoder().decode(mint.data).decimals !== 6) throw new Error("restaurant requires an initialized classic SPL mint with six decimals");
    const baseDir = process.env.SAC006_STORE_DIR!;
    const config: RestaurantConfig = {
      merchantToken: process.env.SAC006_MERCHANT_TOKEN || undefined,
      facilitatorUrl: process.env.SAC006_FACILITATOR_URL!, bearerToken: process.env.SAC006_BEARER_TOKEN!, network: record.network.caip2, programId: record.programId,
      feePayer: process.env.SAC006_FEE_PAYER as Address, server, asset: process.env.SAC006_ASSET_MINT as Address, amount: DEMO_BUDGET,
      captureDeadlineSeconds: DEMO_TIMING.captureSeconds, refundDeadlineSeconds: DEMO_TIMING.refundSecondsAfterCapture,
      store: new OperationStore(baseDir), orders: new RestaurantOrders(`${baseDir}-restaurant`), ledger,
      reclaimJournal: new FileSubmissionJournal(process.env.SAC006_RECLAIM_JOURNAL_DIR ?? `${baseDir}-restaurant-reclaim`),
      origin: process.env.SAC006_PUBLIC_ORIGIN ?? "https://capture402.xyz", getLatestBlockhash: () => ledger.latestBlockhash(), now: cachedClusterClock(() => ledger.now()),
      handler: async () => { throw new Error("restaurant menu uses explicit lifecycle captures"); },
    };
    backend = createRestaurantApp(config); info.configured = true;
    Object.assign(info, { sponsor: config.feePayer, merchant: server.address, mint: config.asset, reason: undefined });
  }
  console.log(missing.length ? `Restaurant UI available; missing configuration: ${missing.join(", ")}` : "Restaurant backend enabled against accepted Devnet deployment");
  serve({ fetch: createPresentationApp(info, backend).fetch, hostname: process.env.SAC006_HOST ?? "127.0.0.1", port: Number(process.env.SAC006_RESOURCE_PORT ?? 8788) });
}
if (process.argv[1]?.endsWith("restaurant-server.ts")) main().catch(() => { console.error("Restaurant startup stopped; verify private configuration and accepted Devnet identity."); process.exitCode = 1; });
