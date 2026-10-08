// Explicit operator-only dev preparation. Private keys, credentials and wire journals
// remain on the VPS. Each network mutation is reserved once before submission.
import { existsSync, mkdirSync, readFileSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { Keypair } from "@solana/web3.js";
import { createSolanaRpc, getSignatureFromTransaction, lamports, type Signature } from "@solana/kit";
import { getCreateAccountInstruction, getTransferSolInstruction } from "@solana-program/system";
import { getCreateAssociatedTokenIdempotentInstruction, getInitializeMint2Instruction, getMintSize, getMintToInstruction, getTokenDecoder } from "@solana-program/token";
import { createDurableFile } from "../src/durable-file.ts";
import { loadDeploymentRecord } from "../src/deployment-record.ts";
import { RpcLedger } from "../src/rpc-ledger.ts";
import { ata, TOKEN_PROGRAM_ADDRESS } from "../src/program.ts";
import { buildTransaction, encodeTransaction } from "../src/transactions.ts";
import { loadKeypair } from "./lib.ts";

const ROLES = ["sponsor", "merchant", "payer", "mint"] as const;
const PRIVATE = "/etc/capture402-dev";
const SETUP = "/var/lib/capture402-dev/setup";
const RECORD = "/opt/capture402-dev/current/docs/evidence/sac-007/deployment-identity.v1.json";
const RPC_URL = "https://api.devnet.solana.com";
const TOKEN_AMOUNT = 10_000_000_000n;

export function reserveOperation(directory: string, name: string, value: unknown): void {
  if (!["funding", "asset-preparation"].includes(name)) throw new Error("unknown dev preparation operation");
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  createDurableFile(join(directory, `${name}.json`), JSON.stringify(value, (_key, v) => typeof v === "bigint" ? v.toString() : v, 2));
}

export function prepareKeys(directory: string): Record<string, string> {
  mkdirSync(join(directory, "keys"), { recursive: true, mode: 0o750 });
  if (existsSync(join(directory, "identities.json")) || ROLES.some(role => existsSync(join(directory, "keys", `${role}.json`)))) {
    throw new Error("dev identities already exist or initialization was interrupted; never overwrite them");
  }
  const identities: Record<string, string> = {};
  for (const role of ROLES) {
    const key = Keypair.generate();
    createDurableFile(join(directory, "keys", `${role}.json`), JSON.stringify(Array.from(key.secretKey)));
    chmodSync(join(directory, "keys", `${role}.json`), 0o600);
    identities[role] = key.publicKey.toBase58();
  }
  createDurableFile(join(directory, "identities.json"), JSON.stringify(identities, null, 2));
  return identities;
}

async function context() {
  const record = loadDeploymentRecord(RECORD);
  const ledger = new RpcLedger({ deployment: record, network: record.network.caip2, genesisHash: record.network.genesisHash,
    rpcUrl: RPC_URL, confirmTimeoutMs: 90_000 });
  await ledger.verifyGenesis();
  const [sponsor, merchant, payer, mint] = await Promise.all(ROLES.map(role => loadKeypair(join(PRIVATE, "keys", `${role}.json`))));
  if (new Set([sponsor!.address, merchant!.address, payer!.address, mint!.address]).size !== 4) throw new Error("distinct dev identities required");
  return { record, ledger, rpc: createSolanaRpc(RPC_URL), sponsor: sponsor!, merchant: merchant!, payer: payer!, mint: mint! };
}

async function fund(): Promise<void> {
  const c = await context();
  if (((await c.ledger.getAccount(c.sponsor.address))?.lamports ?? 0n) >= 50_000_000n) {
    console.log("Dev sponsor already funded; no faucet request submitted.");
    return;
  }
  // Even a lost request response leaves a durable reservation. Never request again.
  reserveOperation(SETUP, "funding", { operation: "requestAirdrop", sponsor: c.sponsor.address, lamports: "1000000000" });
  const signature = await c.rpc.requestAirdrop(c.sponsor.address, lamports(1_000_000_000n), { commitment: "finalized" })
    .send({ abortSignal: AbortSignal.timeout(15_000) });
  createDurableFile(join(SETUP, "funding-response.json"), JSON.stringify({ signature }));
  console.log(JSON.stringify({ operation: "funding requested once", signature, sponsor: c.sponsor.address }));
  // No replacement request or implicit success: the next explicit observe reconciles it.
}

async function prepareAsset(): Promise<void> {
  if (existsSync(join(SETUP, "asset-preparation.json"))) throw new Error("asset preparation already reserved; never create replacement consent");
  const c = await context();
  if (((await c.ledger.getAccount(c.sponsor.address))?.lamports ?? 0n) < 50_000_000n) throw new Error("dev sponsor requires at least 0.05 Devnet SOL");
  if (await c.ledger.getAccount(c.mint.address)) throw new Error("fresh dev mint already exists; reconcile setup instead");
  const payerAta = await ata(c.payer.address, c.mint.address);
  const merchantAta = await ata(c.merchant.address, c.mint.address);
  const rent = await c.rpc.getMinimumBalanceForRentExemption(BigInt(getMintSize())).send({ abortSignal: AbortSignal.timeout(10_000) });
  const lifetime = await c.ledger.latestBlockhash();
  const tx = await buildTransaction({ feePayer: c.sponsor.address, signers: [c.sponsor, c.mint], lifetime,
    instructions: [
      getTransferSolInstruction({ source: c.sponsor, destination: c.payer.address, amount: lamports(20_000_000n) }),
      getCreateAccountInstruction({ payer: c.sponsor, newAccount: c.mint, lamports: rent, space: getMintSize(), programAddress: TOKEN_PROGRAM_ADDRESS }),
      getInitializeMint2Instruction({ mint: c.mint.address, decimals: 6, mintAuthority: c.mint.address, freezeAuthority: null }),
      getCreateAssociatedTokenIdempotentInstruction({ payer: c.sponsor, owner: c.payer.address, mint: c.mint.address, ata: payerAta }),
      getCreateAssociatedTokenIdempotentInstruction({ payer: c.sponsor, owner: c.merchant.address, mint: c.mint.address, ata: merchantAta }),
      getMintToInstruction({ mint: c.mint.address, token: payerAta, mintAuthority: c.mint, amount: TOKEN_AMOUNT }),
    ] });
  const signature = getSignatureFromTransaction(tx);
  reserveOperation(SETUP, "asset-preparation", { signature, transactionBase64: encodeTransaction(tx), blockhash: lifetime.blockhash,
    lastValidBlockHeight: lifetime.lastValidBlockHeight, sponsor: c.sponsor.address, payer: c.payer.address,
    merchant: c.merchant.address, mint: c.mint.address, payerAta, merchantAta, tokenAmount: TOKEN_AMOUNT });
  const result = await c.ledger.submit(tx);
  createDurableFile(join(SETUP, "asset-result.json"), JSON.stringify({ signature, result }));
  console.log(JSON.stringify({ operation: "asset preparation", signature, result }));
  if (result.kind !== "submitted" || result.outcome?.status !== "succeeded" || result.outcome.commitment !== "finalized") {
    throw new Error("asset setup unresolved or failed; reconcile original signature, never rerun");
  }
  const account = await c.ledger.getAccount(payerAta);
  if (!account || account.owner !== TOKEN_PROGRAM_ADDRESS || getTokenDecoder().decode(account.data).amount !== TOKEN_AMOUNT) {
    throw new Error("finalized dev token preparation needs authoritative balance evidence");
  }
}

async function observe(): Promise<void> {
  const c = await context();
  const signatures: Signature[] = [];
  for (const name of ["funding-response", "asset-preparation"]) {
    const file = join(SETUP, `${name}.json`);
    if (existsSync(file)) signatures.push(JSON.parse(readFileSync(file, "utf8")).signature as Signature);
  }
  const statuses = signatures.length ? await c.rpc.getSignatureStatuses(signatures, { searchTransactionHistory: true })
    .send({ abortSignal: AbortSignal.timeout(10_000) }) : null;
  console.log(JSON.stringify({ sponsor: c.sponsor.address, payer: c.payer.address, merchant: c.merchant.address, mint: c.mint.address,
    sponsorLamports: String((await c.ledger.getAccount(c.sponsor.address))?.lamports ?? 0n),
    originalSignatures: signatures, statuses }, (_key, value) => typeof value === "bigint" ? value.toString() : value));
}

async function main(): Promise<void> {
  const action = process.argv[2];
  if (action === "keys") { prepareKeys(PRIVATE); console.log("Fresh private dev identities prepared; no transaction submitted."); }
  else if (action === "fund") await fund();
  else if (action === "asset") await prepareAsset();
  else if (action === "observe") await observe();
  else throw new Error("explicit operator action required: keys|fund|asset|observe");
}

if (process.argv[1]?.endsWith("dev-environment.ts")) main().catch(() => {
  console.error("Dev preparation stopped. Retain private journals and reconcile original signatures before any next operation.");
  process.exitCode = 1;
});
