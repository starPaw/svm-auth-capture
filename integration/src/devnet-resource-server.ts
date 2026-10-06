// SAC-006 runnable resource-server entry point for Devnet (gap #2). Wires `createResourceApp`
// to a running `devnet-server.ts` gateway over HTTP with a bearer token, and to the merchant's
// own keypair for signing the terminal capture/void. Binds to localhost only by default: like
// the facilitator, this process must stay private (ARCHITECTURE).
import { readFileSync } from "node:fs";
import { serve } from "@hono/node-server";
import { type Address, createKeyPairSignerFromBytes, createSolanaRpc, type KeyPairSigner } from "@solana/kit";
import { OperationStore } from "./operation-store.ts";
import { createResourceApp, type HandlerResult } from "./resource-server.ts";

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

/**
 * The demo's protected work. Replace with a real handler for an actual resource; the escrow
 * flow around it (reservation, authorize, capture/void) is unaffected by what this does.
 */
async function demoHandler(): Promise<HandlerResult> {
  return { ok: true, amount: BigInt(requireEnv("SAC006_DEMO_CAPTURE_AMOUNT")), releaseRemainder: true };
}

async function main(): Promise<void> {
  const rpc = createSolanaRpc(requireEnv("SOLANA_RPC_URL"));
  const server = await loadKeypair(requireEnv("SAC006_SERVER_KEYPAIR_PATH"));
  const store = new OperationStore(requireEnv("SAC006_STORE_DIR"));

  const app = createResourceApp({
    facilitatorUrl: requireEnv("SAC006_FACILITATOR_URL"),
    bearerToken: requireEnv("SAC006_BEARER_TOKEN"),
    network: requireEnv("SAC006_NETWORK"),
    programId: requireEnv("SAC006_PROGRAM_ID") as Address,
    feePayer: requireEnv("SAC006_FEE_PAYER") as Address,
    server,
    asset: requireEnv("SAC006_ASSET_MINT") as Address,
    amount: BigInt(requireEnv("SAC006_AUTHORIZE_AMOUNT")),
    captureDeadlineSeconds: Number(process.env.SAC006_CAPTURE_DEADLINE_SECONDS ?? "120"),
    refundDeadlineSeconds: Number(process.env.SAC006_REFUND_DEADLINE_SECONDS ?? "600"),
    store,
    getLatestBlockhash: async () => {
      const { value } = await rpc.getLatestBlockhash().send();
      return { blockhash: value.blockhash, lastValidBlockHeight: value.lastValidBlockHeight };
    },
    now: () => BigInt(Math.floor(Date.now() / 1000)),
    handler: demoHandler,
  });

  const port = Number(process.env.SAC006_RESOURCE_PORT ?? "8788");
  const hostname = process.env.SAC006_HOST ?? "127.0.0.1";
  serve({ fetch: app.fetch, port, hostname }, (info) => {
    console.log(`SAC-006 resource server listening on http://${hostname}:${info.port}`);
  });
}

main().catch((error) => {
  console.error(error instanceof Error ? (error.stack ?? error.message) : String(error));
  process.exitCode = 1;
});
