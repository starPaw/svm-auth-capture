// Payer-direct reclaim (SAC-006 gap #2). Reclaim is never relayed through `/settle`
// (`Reason.reclaimNotRelayed`): the payer signs this directly and pays their own transaction
// fee, so it stays usable while the facilitator and resource server are both stopped. Reads the
// stored payment account itself for its authoritative `server`/`mint`, so the only inputs this
// needs are a `Ledger`, the payer's own keypair, and the payment PDA.
import { readFileSync } from "node:fs";
import { createKeyPairSignerFromBytes, getSignatureFromTransaction, type Address, type KeyPairSigner } from "@solana/kit";
import { loadDeploymentRecord } from "./deployment-record.ts";
import type { Ledger, SubmitResult } from "./ledger.ts";
import { decodePayment } from "./program.ts";
import { RpcLedger } from "./rpc-ledger.ts";
import { buildTransaction, type Lifetime, reclaimInstruction } from "./transactions.ts";

/** Submits the payer's reclaim; returns the transaction's signature with the adapter's outcome. */
export async function submitReclaim(a: {
  ledger: Ledger;
  programId: Address;
  payer: KeyPairSigner;
  payment: Address;
  lifetime: Lifetime;
}): Promise<{ signature: string; result: SubmitResult }> {
  const account = await a.ledger.getAccount(a.payment);
  if (!account || account.owner !== a.programId) throw new Error(`payment ${a.payment} is not owned by ${a.programId}`);
  const stored = decodePayment(account.data);
  if (!stored) throw new Error(`payment ${a.payment} data is invalid`);
  if (stored.payer !== a.payer.address) throw new Error(`payment ${a.payment} is not this payer's payment`);
  const ix = await reclaimInstruction({ programId: a.programId, payment: a.payment, payer: a.payer.address, server: stored.server, mint: stored.mint });
  const tx = await buildTransaction({ feePayer: a.payer.address, instructions: [ix], signers: [a.payer], lifetime: a.lifetime });
  return { signature: getSignatureFromTransaction(tx), result: await a.ledger.submit(tx) };
}

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
  const payment = process.argv[2] as Address | undefined;
  if (!payment) throw new Error("usage: node reclaim.ts <payment-address>");
  const record = loadDeploymentRecord(requireEnv("SAC006_DEPLOYMENT_RECORD_PATH"));
  const rpcUrl = requireEnv("SOLANA_RPC_URL");
  const payer = await loadKeypair(requireEnv("SAC006_PAYER_KEYPAIR_PATH"));
  const ledger = new RpcLedger({ network: record.network.caip2, genesisHash: record.network.genesisHash, rpcUrl });
  await ledger.verifyGenesis();
  const { signature, result } = await submitReclaim({ ledger, programId: record.programId, payer, payment, lifetime: await ledger.latestBlockhash() });
  const status = await ledger.getSignatureStatus(signature);
  console.log(JSON.stringify({ payment, signature, result, status }, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 2));
}

if (process.argv[1]?.endsWith("reclaim.ts")) {
  main().catch((error) => {
    console.error(error instanceof Error ? (error.stack ?? error.message) : String(error));
    process.exitCode = 1;
  });
}
