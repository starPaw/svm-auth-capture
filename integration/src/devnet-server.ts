// SAC-006 runnable facilitator entry point for Devnet. Wires `RpcLedger` to the HTTP
// `createGatewayApp` binding using the externally pinned, independently accepted SAC-007
// deployment record (see `deployment-record.ts`) and `SOLANA_RPC_URL`; refuses to start on a
// network/program mismatch or an unaccepted record. Binds to localhost only by default: the
// gateway applies bearer authentication, a merchant/mint allowlist, and a sponsorship
// attempt/balance cap in front of every facilitator route (`gateway.ts`), but it must still
// never be exposed publicly (ARCHITECTURE).
import { readFileSync } from "node:fs";
import { serve } from "@hono/node-server";
import { type Address, createKeyPairSignerFromBytes, type KeyPairSigner } from "@solana/kit";
import { loadDeploymentRecord } from "./deployment-record.js";
import { Facilitator } from "./facilitator.js";
import { createGatewayApp } from "./gateway.js";
import { RpcLedger } from "./rpc-ledger.js";
import { SponsorshipGuard } from "./sponsorship.js";

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`missing required environment variable ${name}`);
  return value;
}

async function loadFeePayer(path: string): Promise<KeyPairSigner> {
  const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (!Array.isArray(parsed) || parsed.length !== 64) {
    throw new Error(`${path} must be a solana-keygen 64-byte secret key JSON array`);
  }
  return createKeyPairSignerFromBytes(new Uint8Array(parsed as number[]));
}

async function main(): Promise<void> {
  const record = loadDeploymentRecord(requireEnv("SAC006_DEPLOYMENT_RECORD_PATH"));
  const rpcUrl = requireEnv("SOLANA_RPC_URL");
  const feePayer = await loadFeePayer(requireEnv("SAC006_FACILITATOR_KEYPAIR_PATH"));

  const ledger = new RpcLedger({ network: record.network.caip2, genesisHash: record.network.genesisHash, rpcUrl });
  await ledger.verifyGenesis();

  const facilitator = new Facilitator({ network: record.network.caip2, programId: record.programId, feePayer, ledger });
  const sponsorship = new SponsorshipGuard({
    ledger,
    feePayer: feePayer.address,
    maxAttempts: Number(process.env.SAC006_SPONSOR_MAX_ATTEMPTS ?? "50"),
    minLamportsBalance: BigInt(process.env.SAC006_SPONSOR_MIN_LAMPORTS ?? "10000000"), // 0.01 SOL
  });
  const app = createGatewayApp(facilitator, {
    bearerToken: requireEnv("SAC006_BEARER_TOKEN"),
    sponsorship,
    allowlist: {
      merchant: requireEnv("SAC006_ALLOWLIST_MERCHANT") as Address,
      mint: requireEnv("SAC006_ALLOWLIST_MINT") as Address,
    },
  });

  const port = Number(process.env.SAC006_PORT ?? "8787");
  const hostname = process.env.SAC006_HOST ?? "127.0.0.1";
  serve({ fetch: app.fetch, port, hostname }, (info) => {
    console.log(`SAC-006 facilitator listening on http://${hostname}:${info.port}`);
    console.log(`network=${facilitator.network} program=${record.programId} rpc=${rpcUrl}`);
  });
}

main().catch((error) => {
  console.error(error instanceof Error ? (error.stack ?? error.message) : String(error));
  process.exitCode = 1;
});
