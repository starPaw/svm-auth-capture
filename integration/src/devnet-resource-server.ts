// SAC-006 runnable resource-server entry point for Devnet (gap #2). Wires `createResourceApp`
// to a running `devnet-server.ts` gateway over HTTP with a bearer token, and to the merchant's
// own keypair for signing the terminal capture/void. Applies the same configuration checks as
// the facilitator: the network and program come only from the accepted SAC-007 deployment
// record, the RPC genesis must match it, and the facilitator's `/supported` must advertise the
// same network and the configured sponsor. Binds to localhost only by default: like the
// facilitator, this process must stay private (ARCHITECTURE).
import { readFileSync } from "node:fs";
import { serve } from "@hono/node-server";
import { type Address, createKeyPairSignerFromBytes, type KeyPairSigner } from "@solana/kit";
import { ACCEPTED_DEPLOYMENT_RECORD, loadDeploymentRecord } from "./deployment-record.ts";
import { OperationStore } from "./operation-store.ts";
import { createResourceApp, type HandlerResult } from "./resource-server.ts";
import { cachedClusterClock, redactRpcUrl, RpcLedger } from "./rpc-ledger.ts";

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`missing required environment variable ${name}`);
  return value;
}

async function loadKeypair(path: string): Promise<KeyPairSigner> {
  const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (!Array.isArray(parsed) || parsed.length !== 64) throw new Error(`${path} must be a solana-keygen 64-byte secret key JSON array`);
  return createKeyPairSignerFromBytes(new Uint8Array(parsed as number[]));
}

/** Refuses to start against a facilitator that serves another network or sponsor. */
async function checkFacilitator(url: string, network: string, feePayer: Address): Promise<void> {
  const res = await fetch(`${url}/supported`, { signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new Error(`facilitator /supported answered HTTP ${res.status}`);
  const supported = (await res.json()) as { kinds?: { scheme?: string; network?: string; extra?: { feePayer?: string } }[] };
  const kind = supported.kinds?.find((k) => k.scheme === "auth-capture" && k.network === network);
  if (!kind) throw new Error(`facilitator does not support auth-capture on ${network}`);
  if (kind.extra?.feePayer !== feePayer) throw new Error(`facilitator sponsor ${kind.extra?.feePayer} is not the configured ${feePayer}`);
}

/**
 * The demo's protected work. Replace with a real handler for an actual resource; the escrow
 * flow around it (reservation, authorize, capture/void) is unaffected by what this does. With
 * `SAC006_DEMO_RELEASE_REMAINDER=false` the capture is partial and the remainder stays held
 * until the payer reclaims it at `Dc`.
 */
async function demoHandler(): Promise<HandlerResult> {
  const release = process.env.SAC006_DEMO_RELEASE_REMAINDER ?? "true";
  if (release !== "true" && release !== "false") throw new Error("SAC006_DEMO_RELEASE_REMAINDER must be true or false");
  return { ok: true, amount: BigInt(requireEnv("SAC006_DEMO_CAPTURE_AMOUNT")), releaseRemainder: release === "true" };
}

async function main(): Promise<void> {
  const record = loadDeploymentRecord(requireEnv("SAC006_DEPLOYMENT_RECORD_PATH"));
  const rpcUrl = requireEnv("SOLANA_RPC_URL");
  const ledger = new RpcLedger({ network: record.network.caip2, genesisHash: record.network.genesisHash, rpcUrl });
  await ledger.verifyGenesis();

  const facilitatorUrl = requireEnv("SAC006_FACILITATOR_URL");
  const feePayer = requireEnv("SAC006_FEE_PAYER") as Address;
  await checkFacilitator(facilitatorUrl, record.network.caip2, feePayer);

  const server = await loadKeypair(requireEnv("SAC006_SERVER_KEYPAIR_PATH"));
  const store = new OperationStore(requireEnv("SAC006_STORE_DIR"));
  // A restart never resumes or retries anything; it only surfaces what needs an operator.
  const unresolved = store.unresolved();
  if (unresolved.length > 0) {
    console.warn(`${unresolved.length} unresolved operation record(s); run devnet:reconcile before relying on them:`);
    for (const r of unresolved) console.warn(`  ${r.fingerprint}  status=${r.status}`);
  }

  const app = createResourceApp({
    facilitatorUrl,
    bearerToken: requireEnv("SAC006_BEARER_TOKEN"),
    network: record.network.caip2,
    programId: record.programId,
    feePayer,
    server,
    asset: requireEnv("SAC006_ASSET_MINT") as Address,
    amount: BigInt(requireEnv("SAC006_AUTHORIZE_AMOUNT")),
    captureDeadlineSeconds: Number(process.env.SAC006_CAPTURE_DEADLINE_SECONDS ?? "120"),
    refundDeadlineSeconds: Number(process.env.SAC006_REFUND_DEADLINE_SECONDS ?? "600"),
    store,
    getLatestBlockhash: () => ledger.latestBlockhash(),
    // Offered deadlines are cluster time, the same clock the program and facilitator enforce;
    // cached so an anonymous 402 request does not cost an RPC read.
    now: cachedClusterClock(() => ledger.now()),
    handler: demoHandler,
  });

  const port = Number(process.env.SAC006_RESOURCE_PORT ?? "8788");
  const hostname = process.env.SAC006_HOST ?? "127.0.0.1";
  serve({ fetch: app.fetch, port, hostname }, (info) => {
    console.log(`SAC-006 resource server listening on http://${hostname}:${info.port}`);
    console.log(`network=${record.network.caip2} program=${record.programId} rpc=${redactRpcUrl(rpcUrl)}`);
    console.log(`deployment record sha256=${record.sha256} (${ACCEPTED_DEPLOYMENT_RECORD.path} at ${ACCEPTED_DEPLOYMENT_RECORD.revision})`);
  });
}

main().catch((error) => {
  console.error(error instanceof Error ? (error.stack ?? error.message) : String(error));
  process.exitCode = 1;
});
