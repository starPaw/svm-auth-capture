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
import { AdmissionJournal } from './admission-journal.ts';
import { selectedAbandonPolicies } from './authorize-abandon.ts';
import { PENDING_A_ISOLATION } from './unknown-authorize-isolation.ts';
import { E2E_SPONSOR, requireE2eRuntimeRpc, trustedRuntimeFile } from './e2e-runtime-policy.ts';
import { validateFaucetPolicy, type FaucetPolicy } from './devnet-faucet-store.ts';
import { devnetFaucetProxy } from './devnet-faucet-proxy.ts';
import { ata } from './program.ts';
import {validateMerchantDemoPolicy,E2E_MERCHANT_DEMO_POLICY} from './merchant-demo.ts';

export const DEMO_TIMING = { captureSeconds: 150, refundSecondsAfterCapture: 30 } as const;
const root = fileURLToPath(new URL("../web/", import.meta.url));
export function createPresentationApp(info: { programId: string; network: string; configured: boolean; reason?: string; sponsor?: string; merchant?: string; mint?: string; faucetEnabled?:boolean; publicMerchantDemoEnabled?:boolean }, backend?: Hono): Hono {
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
  for (const [name, mime] of [["homepage.css", "text/css"], ["homepage.js", "text/javascript"], ["app.js", "text/javascript"], ["receipt-state.js", "text/javascript"], ["wallet.js", "text/javascript"], ["style.css", "text/css"], ["solflare.js", "text/javascript"], ["solflare.js.LEGAL.txt", "text/plain"]]) app.get(`/assets/${name}`, c => { c.header("Content-Type", `${mime}; charset=utf-8`); return c.body(readFileSync(`${root}${name}`)); });
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
    const e2e = process.env.SAC006_FEE_PAYER === E2E_SPONSOR || process.env.SAC006_SERVER_KEYPAIR_PATH!.includes('/capture402-e2e/');
    if (e2e) requireE2eRuntimeRpc(process.env.SOLANA_RPC_URL!,record);
    const b3Recovery = e2e && process.env.SAC006_B3_RECOVERY_POLICY_PATH ? JSON.parse(trustedRuntimeFile(process.env.SAC006_B3_RECOVERY_POLICY_PATH)) : undefined;
    if (b3Recovery && (b3Recovery.order !== 'c17b234248fb69cf0e624fc32ac45bcd' || b3Recovery.payment !== '2ZGNGg4k97DX5RPnQSDsuTb99Nxjyt4cYpjvYitUv8JS' ||
      b3Recovery.payer !== '93PtawNdAfDn7oTjRrbrJJMSgaFTjGS3wjtkrZSNGn74' || b3Recovery.authorizeSignature !== '2d3tAStAtNT891UPAqThpwVNvHGkFP76dX5yvfYNPjAmKLkzBdEFzvZ6ZBh9Ba7HhNotUGdrFmitwdDiW7iRh4dT')) throw Error('B3 recovery policy exceeds the selected operation');
    const authorizeAbandonPolicies=e2e && process.env.SAC006_B3_AUTHORIZE_ABANDON_POLICY_PATH ? selectedAbandonPolicies(JSON.parse(trustedRuntimeFile(process.env.SAC006_B3_AUTHORIZE_ABANDON_POLICY_PATH))) : undefined;
    const authorizeIsolationPolicy=e2e && process.env.SAC006_B3_AUTHORIZE_ISOLATION_POLICY_PATH ? JSON.parse(trustedRuntimeFile(process.env.SAC006_B3_AUTHORIZE_ISOLATION_POLICY_PATH)) : undefined;
    if(authorizeIsolationPolicy && (Object.keys(authorizeIsolationPolicy).sort().join()!==[...Object.keys(PENDING_A_ISOLATION),'archiveSha256'].sort().join() ||
      Object.entries(PENDING_A_ISOLATION).some(([k,v])=>authorizeIsolationPolicy[k]!==v) || !/^[a-f0-9]{64}$/.test(authorizeIsolationPolicy.archiveSha256)))throw Error('Unknown authorization isolation exceeds the selected original');
    const ledger = new RpcLedger({ deployment: record, network: record.network.caip2, genesisHash: record.network.genesisHash, rpcUrl: process.env.SOLANA_RPC_URL!, rpcMinIntervalMs:e2e?250:0 });
    await ledger.verifyGenesis();
    const server = await createKeyPairSignerFromBytes(Uint8Array.from(JSON.parse(readFileSync(process.env.SAC006_SERVER_KEYPAIR_PATH!, "utf8"))));
    const mint = await ledger.getAccount(process.env.SAC006_ASSET_MINT as Address);
    if (!mint || mint.owner !== TOKEN_PROGRAM_ADDRESS || mint.data.length !== getMintDecoder().fixedSize || !getMintDecoder().decode(mint.data).isInitialized || getMintDecoder().decode(mint.data).decimals !== 6) throw new Error("restaurant requires an initialized classic SPL mint with six decimals");
    const baseDir = process.env.SAC006_STORE_DIR!;
    let faucet;
    const faucetPolicyPath=process.env.SAC006_E2E_FAUCET_POLICY_PATH;
    if(faucetPolicyPath) {
      if(!e2e)throw Error('faucet is restricted to the reviewed E2E campaign');
      const policy=JSON.parse(trustedRuntimeFile(faucetPolicyPath)) as FaucetPolicy;validateFaucetPolicy(policy);
      if(policy.mint!==process.env.SAC006_ASSET_MINT || policy.mint!=='91wxVDcTEf5kRRRFmkUKohdNLFRAh5tw9YqWxV8FYvJp' ||
        policy.sponsor!==E2E_SPONSOR || policy.pool!==await ata(policy.sponsor,policy.mint) || policy.origin!==process.env.SAC006_PUBLIC_ORIGIN)throw Error('faucet policy exceeds existing E2E identities');
      faucet=devnetFaucetProxy(process.env.SAC006_FACILITATOR_URL!,process.env.SAC006_BEARER_TOKEN!);
    }
    const config: RestaurantConfig = {
      merchantToken: process.env.SAC006_MERCHANT_TOKEN || undefined,
      facilitatorUrl: process.env.SAC006_FACILITATOR_URL!, bearerToken: process.env.SAC006_BEARER_TOKEN!, network: record.network.caip2, programId: record.programId,
      feePayer: process.env.SAC006_FEE_PAYER as Address, server, asset: process.env.SAC006_ASSET_MINT as Address, amount: DEMO_BUDGET,
      captureDeadlineSeconds: DEMO_TIMING.captureSeconds, refundDeadlineSeconds: DEMO_TIMING.refundSecondsAfterCapture,
      store: new OperationStore(baseDir), orders: new RestaurantOrders(`${baseDir}-restaurant`), ledger,
      reclaimJournal: new FileSubmissionJournal(process.env.SAC006_RECLAIM_JOURNAL_DIR ?? `${baseDir}-restaurant-reclaim`),
      origin: process.env.SAC006_PUBLIC_ORIGIN ?? "https://capture402.xyz", getLatestBlockhash: () => ledger.latestBlockhash(), now: cachedClusterClock(() => ledger.now()),
      ...(faucet?{faucet}:{}),
      handler: async () => { throw new Error("restaurant menu uses explicit lifecycle captures"); },
      ...(e2e ? { orderAdmission:new AdmissionJournal(process.env.SAC006_E2E_ORDER_ADMISSION_DIR!,'orders',Number(process.env.SAC006_E2E_MAX_ORDERS)),
        ...(b3Recovery ? {b3Recovery} : {}),
        ...(authorizeAbandonPolicies ? {authorizeAbandonPolicies} : {}),
        ...(authorizeIsolationPolicy ? {authorizeIsolationPolicy} : {}),
        now:() => ledger.now() } : {}),
    };
    const demoPolicyPath=process.env.SAC006_E2E_PUBLIC_MERCHANT_DEMO_POLICY_PATH;
    if(demoPolicyPath) {
      if(!e2e || process.env.SAC006_E2E_MAX_ORDERS!=='100')throw Error('public merchant demo restricted to bounded E2E');
      validateMerchantDemoPolicy(JSON.parse(trustedRuntimeFile(demoPolicyPath)));
      const p=E2E_MERCHANT_DEMO_POLICY;
      if(config.origin!==p.origin || config.network!==p.network || config.programId!==p.programId || config.feePayer!==p.sponsor || server.address!==p.merchant || config.asset!==p.mint)throw Error('public merchant demo runtime identity differs');
      config.publicMerchantDemo=true;
    }
    backend = createRestaurantApp(config); info.configured = true;
    Object.assign(info, { sponsor: config.feePayer, merchant: server.address, mint: config.asset, reason: undefined,...(faucet?{faucetEnabled:true}:{}),...(config.publicMerchantDemo?{publicMerchantDemoEnabled:true}:{}) });
  }
  console.log(missing.length ? `Restaurant UI available; missing configuration: ${missing.join(", ")}` : "Restaurant backend enabled against accepted Devnet deployment");
  serve({ fetch: createPresentationApp(info, backend).fetch, hostname: process.env.SAC006_HOST ?? "127.0.0.1", port: Number(process.env.SAC006_RESOURCE_PORT ?? 8788) });
}
if (process.argv[1]?.endsWith("restaurant-server.ts")) main().catch(() => { console.error("Restaurant startup stopped; verify private configuration and accepted Devnet identity."); process.exitCode = 1; });
