// Payer-direct reclaim (SAC-006 gap #2). Reclaim is never relayed through `/settle`
// (`Reason.reclaimNotRelayed`): the payer signs this directly and pays their own transaction
// fee, so it stays usable while the facilitator and resource server are both stopped. Reads the
// stored payment account itself for its authoritative `server`/`mint`, so the only inputs this
// needs are a `Ledger`, the payer's own keypair, and the payment PDA.
import { readFileSync } from "node:fs";
import { createKeyPairSignerFromBytes, getBase64EncodedWireTransaction, getSignatureFromTransaction, isSignature, type Address, type KeyPairSigner } from "@solana/kit";
import { loadDeploymentRecord } from "./deployment-record.ts";
import type { Ledger, SubmitResult } from "./ledger.ts";
import { decodePayment } from "./program.ts";
import { RpcLedger } from "./rpc-ledger.ts";
import { FileSubmissionJournal, messageHash, submissionOutcome, type SubmissionJournal } from "./submission-journal.ts";
import type { ChainReader } from "./reconciliation.ts";
import { buildTransaction, type Lifetime, reclaimInstruction } from "./transactions.ts";

/** Submits the payer's reclaim; returns the transaction's signature with the adapter's outcome. */
export async function submitReclaim(a: {
  ledger: Ledger;
  programId: Address;
  payer: KeyPairSigner;
  payment: Address;
  lifetime: Lifetime;
  journal: SubmissionJournal;
  /** Explicit operator continuation; never accepted on missing/weaker/successful evidence. */
  retryAfter?: string;
  reader?: Pick<ChainReader, "getSignatureStatus">;
}): Promise<{ signature: string; result: SubmitResult }> {
  const account = await a.ledger.getAccount(a.payment);
  if (!account || account.owner !== a.programId) throw new Error(`payment ${a.payment} is not owned by ${a.programId}`);
  const stored = decodePayment(account.data);
  if (!stored) throw new Error(`payment ${a.payment} data is invalid`);
  if (stored.payer !== a.payer.address) throw new Error(`payment ${a.payment} is not this payer's payment`);
  if (stored.held === 0n) throw new Error("reclaim requires a positive remaining hold");
  if ((await a.ledger.now()) < stored.captureDeadline) throw new Error("reclaim requires cluster Clock >= captureDeadline");
  if (a.retryAfter !== undefined) {
    if (!isSignature(a.retryAfter) || !a.reader) throw new Error("reclaim continuation requires an original signature and chain reader");
    const previous = a.journal.read(a.retryAfter);
    if (!previous || previous.operation !== "reclaim" || previous.payment !== a.payment || previous.payer !== a.payer.address) throw new Error("original signature is not this payment's journaled reclaim");
    const status = await a.reader.getSignatureStatus(a.retryAfter);
    if (status.kind !== "found" || status.commitment !== "finalized" || typeof status.err !== "string" || status.err.length === 0) throw new Error("original reclaim is not proved finalized-failed; continuation is blocked");
    a.journal.resolve(a.retryAfter, { result: "finalized-failed", recordedAt: new Date().toISOString(), detail: status.err });
  }
  const ix = await reclaimInstruction({ programId: a.programId, payment: a.payment, payer: a.payer.address, server: stored.server, mint: stored.mint });
  const tx = await buildTransaction({ feePayer: a.payer.address, instructions: [ix], signers: [a.payer], lifetime: a.lifetime });
  const signature = getSignatureFromTransaction(tx);
  // Do not release broadcastable payer bytes to the simulation backend before journaling.
  const simulation = await a.ledger.simulate({ ...tx, signatures: { ...tx.signatures, [a.payer.address]: null } });
  if (!simulation.ok) throw new Error(`reclaim simulation failed: ${simulation.error}`);
  a.journal.prepare({ signature, messageHash: messageHash(tx.messageBytes), transactionBase64: getBase64EncodedWireTransaction(tx),
    blockhash: a.lifetime.blockhash, operation: "reclaim", payment: a.payment, payer: a.payer.address,
    expectedHeld: stored.held.toString(), expectedRefundable: stored.refundable.toString(),
    ...(a.retryAfter === undefined ? {} : { retryAfter: a.retryAfter }) });
  let result: SubmitResult;
  try {
    result = await a.ledger.submit(tx);
  } catch (error) {
    try {
      a.journal.resolve(signature, { result: "submit-threw", recordedAt: new Date().toISOString() });
    } catch {
      // The original durable reservation still blocks reuse.
    }
    throw error;
  }
  try {
    a.journal.resolve(signature, { ...submissionOutcome(result), recordedAt: new Date().toISOString() });
  } catch {
    console.error(`reclaim outcome could not be journaled for ${signature}; inspect the original signature`);
  }
  return { signature, result };
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
  const [paymentArg, flag, retryAfter, ...rest] = process.argv.slice(2);
  const payment = paymentArg as Address | undefined;
  if (!payment || (flag !== undefined && (flag !== "--retry-after" || !retryAfter || rest.length !== 0))) throw new Error("usage: node reclaim.ts <payment-address> [--retry-after <finalized-failed-signature>]");
  const record = loadDeploymentRecord(requireEnv("SAC006_DEPLOYMENT_RECORD_PATH"));
  const rpcUrl = requireEnv("SOLANA_RPC_URL");
  const payer = await loadKeypair(requireEnv("SAC006_PAYER_KEYPAIR_PATH"));
  const ledger = new RpcLedger({ deployment: record, network: record.network.caip2, genesisHash: record.network.genesisHash, rpcUrl });
  await ledger.verifyGenesis();
  const journal = new FileSubmissionJournal(process.env.SAC006_RECLAIM_JOURNAL_DIR ?? requireEnv("SAC006_FACILITATOR_JOURNAL_DIR"));
  const { signature, result } = await submitReclaim({ ledger, programId: record.programId, payer, payment, lifetime: await ledger.latestBlockhash(), journal, retryAfter, reader: ledger });
  const status = await ledger.getSignatureStatus(signature);
  console.log(JSON.stringify({ payment, signature, result, status }, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 2));
}

if (process.argv[1]?.endsWith("reclaim.ts")) {
  main().catch((error) => {
    console.error(error instanceof Error ? (error.stack ?? error.message) : String(error));
    process.exitCode = 1;
  });
}
