// Demo client (SAC-006 gap #2): drives `GET /resource` against the resource server, handles the
// `402` challenge, signs the authorize transaction, retries with `PAYMENT-SIGNATURE`, and
// decodes the `PAYMENT-RESPONSE` header the resource server returns. Every term the client
// signs over (`programId`, `feePayer`, `payTo`, `asset`, `amount`, deadlines) comes from the
// resource server's own 402 challenge, not from a value this script invents: the facilitator
// independently re-derives and checks every one of them at `/settle`.
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { createKeyPairSignerFromBytes, createSolanaRpc, type Address, type KeyPairSigner } from "@solana/kit";
import { decodeHeaderPayload, encodeHeaderPayload } from "./resource-server.ts";
import { authorizeInstruction, authorizePayload, buildTransaction } from "./transactions.ts";
import type { PaymentRequirements } from "./types.ts";

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

async function main(): Promise<void> {
  const resourceUrl = requireEnv("SAC006_RESOURCE_URL");
  const rpcUrl = requireEnv("SOLANA_RPC_URL");
  const payer = await loadKeypair(requireEnv("SAC006_PAYER_KEYPAIR_PATH"));

  const challenge = await fetch(`${resourceUrl}/resource`);
  if (challenge.status !== 402) throw new Error(`expected 402 Payment Required, got ${challenge.status}`);
  const { accepts } = (await challenge.json()) as { accepts: PaymentRequirements[] };
  const requirements = accepts[0];
  if (!requirements) throw new Error("402 response carried no accepts[]");
  const extra = requirements.extra as { programId: Address; feePayer: Address; captureDeadline: number; refundDeadline: number };

  const salt = new Uint8Array(randomBytes(32));
  const ix = await authorizeInstruction({
    programId: extra.programId,
    payer: payer.address,
    server: requirements.payTo as Address,
    mint: requirements.asset as Address,
    funder: extra.feePayer,
    salt,
    maximum: BigInt(requirements.amount),
    captureDeadline: BigInt(extra.captureDeadline),
    refundDeadline: BigInt(extra.refundDeadline),
  });
  const rpc = createSolanaRpc(rpcUrl);
  const { value } = await rpc.getLatestBlockhash().send();
  const tx = await buildTransaction({
    feePayer: extra.feePayer,
    instructions: [ix],
    signers: [payer],
    lifetime: { blockhash: value.blockhash, lastValidBlockHeight: value.lastValidBlockHeight },
  });

  const res = await fetch(`${resourceUrl}/resource`, { headers: { "payment-signature": encodeHeaderPayload(authorizePayload(tx)) } });
  const body = await res.json();
  console.log(`status=${res.status}`);
  console.log(JSON.stringify(body, null, 2));
  const responseHeader = res.headers.get("payment-response");
  if (responseHeader) console.log("payment-response:", JSON.stringify(decodeHeaderPayload(responseHeader), null, 2));
}

if (process.argv[1]?.endsWith("client.ts")) {
  main().catch((error) => {
    console.error(error instanceof Error ? (error.stack ?? error.message) : String(error));
    process.exitCode = 1;
  });
}
