// One-shot preparation of fresh Devnet test identities. No airdrop or repeated submission.
// SAC006_MINT_KEYPAIR_PATH identifies the new mint signer; all other inputs match run-all.sh.
import { join } from "node:path";
import { getCreateAccountInstruction, getTransferSolInstruction } from "@solana-program/system";
import { getCreateAssociatedTokenIdempotentInstruction, getInitializeMint2Instruction, getMintSize, getMintToInstruction } from "@solana-program/token";
import { createSolanaRpc, getSignatureFromTransaction, lamports } from "@solana/kit";
import { createDurableFile, ensureDurableDirectory } from "../src/durable-file.ts";
import { ata, TOKEN_PROGRAM_ADDRESS } from "../src/program.ts";
import { buildTransaction, encodeTransaction } from "../src/transactions.ts";
import { check, context, emit, env, finalizedSlot, loadKeypair, snapshot } from "./lib.ts";

async function main(): Promise<void> {
  const c = await context();
  const mintKey = await loadKeypair(env("SAC006_MINT_KEYPAIR_PATH"));
  check(mintKey.address === c.mint, "mint key matches the configured fresh test mint");
  check(new Set([c.sponsor.address, c.payer.address, c.server.address, c.mint]).size === 4, "four distinct test identities");
  check(await c.ledger.getAccount(c.mint) === null, "new mint does not already exist");
  const sponsor = await c.ledger.getAccount(c.sponsor.address);
  check((sponsor?.lamports ?? 0n) >= 50_000_000n, "sponsor has at least 0.05 Devnet SOL for setup and the campaign");
  const payerAta = await ata(c.payer.address, c.mint);
  const serverAta = await ata(c.server.address, c.mint);
  const rent = await createSolanaRpc(c.rpcUrl).getMinimumBalanceForRentExemption(BigInt(getMintSize())).send({ abortSignal: AbortSignal.timeout(10_000) });
  const lifetime = await c.ledger.latestBlockhash();
  const tx = await buildTransaction({ feePayer: c.sponsor.address, signers: [c.sponsor, mintKey], lifetime, instructions: [
    getTransferSolInstruction({ source: c.sponsor, destination: c.payer.address, amount: lamports(10_000_000n) }),
    getCreateAccountInstruction({ payer: c.sponsor, newAccount: mintKey, lamports: rent, space: getMintSize(), programAddress: TOKEN_PROGRAM_ADDRESS }),
    getInitializeMint2Instruction({ mint: c.mint, decimals: 6, mintAuthority: mintKey.address, freezeAuthority: null }),
    getCreateAssociatedTokenIdempotentInstruction({ payer: c.sponsor, owner: c.payer.address, mint: c.mint, ata: payerAta }),
    getCreateAssociatedTokenIdempotentInstruction({ payer: c.sponsor, owner: c.server.address, mint: c.mint, ata: serverAta }),
    getMintToInstruction({ mint: c.mint, token: payerAta, mintAuthority: mintKey, amount: 10_000n }),
  ] });
  const signature = getSignatureFromTransaction(tx);
  const dir = env("SAC006_EVIDENCE_DIR");
  ensureDurableDirectory(dir);
  // Exclusive creation blocks a rerun with another blockhash after a lost result or crash.
  createDurableFile(join(dir, "preparation.json"), JSON.stringify({ signature, transactionBase64: encodeTransaction(tx), blockhash: lifetime.blockhash,
    lastValidBlockHeight: lifetime.lastValidBlockHeight.toString(), sponsor: c.sponsor.address, payer: c.payer.address, server: c.server.address, mint: c.mint }, null, 2));
  emit("test asset preparation reserved", { signature });
  const result = await c.ledger.submit(tx);
  emit("test asset preparation result", { signature, result });
  check(result.kind === "submitted" && result.outcome?.status === "succeeded" && result.outcome.commitment === "finalized", "setup finalized; otherwise reconcile the original signature, never rerun");
  const state = await snapshot(c, "fresh test assets prepared", undefined, await finalizedSlot(c, signature));
  check(state.payerAta === "10000" && state.serverAta === "0", "payer and merchant ATAs initialized with exact test balances");
}

main().catch(() => { console.error("Preparation stopped. Inspect retained original-signature evidence; do not rerun an unresolved submission."); process.exitCode = 1; });
