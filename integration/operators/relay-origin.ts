// #52 bounded public Devnet evidence only. No keys/config/context loader, signing, simulation
// or broadcast. Run from repository root; retain sanitized stdout outside payment stores.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { RpcLedger } from "../src/rpc-ledger.ts";
const genesisHash = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
const network = `solana:${genesisHash.slice(0, 32)}`;
const ledger = new RpcLedger({ network, genesisHash, rpcUrl: "https://api.devnet.solana.com", requestTimeoutMs: 5000 });
const evidence: Record<string, unknown> = { version: 1, collectedAt: new Date().toISOString(),
  endpoint: "https://api.devnet.solana.com", network, genesisHash,
  scope: "read-only fresh RPC observation; no transaction construction, wallet, signing or broadcast",
  queryPlan: ["getGenesisHash", "getLatestBlockhash", "getGenesisHash", "getBlock"],
  requestTimeoutMs: 5000, maximumTotalMs: 15000, originCandidates: 1,
  sourceSha256: Object.fromEntries(["../src/rpc-ledger.ts", "../src/lifetime-provenance.ts", "./relay-origin.ts"].map(path =>
    [path, createHash("sha256").update(readFileSync(new URL(path, import.meta.url))).digest("hex")])),
  completedStages: [], historicalRecovery: "not established" };
try {
  await ledger.verifyGenesis();
  (evidence.completedStages as string[]).push("genesis-matched");
  const lifetime = await ledger.latestBlockhash();
  evidence.observation = { blockhash: lifetime.blockhash, lastValidBlockHeight: lifetime.lastValidBlockHeight.toString(),
    contextSlot: lifetime.contextSlot!.toString(), commitment: lifetime.commitment, network: lifetime.network, genesisHash: lifetime.genesisHash };
  (evidence.completedStages as string[]).push("original-observation-recorded");
  const origin = await ledger.verifyBlockhashOrigin(lifetime.blockhash, lifetime.contextSlot!, genesisHash, network);
  evidence.origin = origin;
  (evidence.completedStages as string[]).push("bounded-origin-lookup-completed");
  evidence.result = origin.state === "verified" ? "matching-finalized-origin" : "acceptance-blocked";
} catch {
  evidence.result = "acceptance-blocked";
  evidence.origin = { state: "unverified", reason: "public-rpc-unavailable" };
}
evidence.completedAt = new Date().toISOString();
console.log(JSON.stringify(evidence, null, 2));
