import { withShared } from "./coordination.ts";
// Payer-direct reclaim (SAC-006 gap #2). Reclaim is never relayed through `/settle`
// (`Reason.reclaimNotRelayed`): the payer signs this directly and pays their own transaction
// fee, so it stays usable while the facilitator and resource server are both stopped. Reads the
// stored payment account itself for its authoritative `server`/`mint`, so the only inputs this
// needs are a `Ledger`, the payer's own keypair, and the payment PDA.
import { readFileSync } from "node:fs";
import { createKeyPairSignerFromBytes, getBase64EncodedWireTransaction, getSignatureFromTransaction, isSignature, type Address, type Blockhash, type KeyPairSigner } from "@solana/kit";
import { loadDeploymentRecord } from "./deployment-record.ts";
import type { Ledger, SubmitResult } from "./ledger.ts";
import { decodePayment } from "./program.ts";
import { RpcLedger } from "./rpc-ledger.ts";
import { FileSubmissionJournal, messageHash, submissionOutcome, type SubmissionJournal, type PreparedSubmission } from "./submission-journal.ts";
import type { BlockhashCheck, ChainReader } from "./reconciliation.ts";
import { buildTransaction, type Lifetime, reclaimInstruction } from "./transactions.ts";

/** Submits the payer's reclaim; returns the transaction's signature with the adapter's outcome. */
export async function submitReclaim(a: Parameters<typeof submitReclaimCoordinated>[0]): Promise<{ signature: string; result: SubmitResult }> {
  return withShared(a.journal.coordination, async () => { a.journal.assertAccess?.(); return submitReclaimCoordinated(a); });
}

async function submitReclaimCoordinated(a: {
  ledger: Ledger;
  programId: Address;
  payer: KeyPairSigner;
  payment: Address;
  lifetime: Lifetime;
  journal: SubmissionJournal;
  /** Explicit operator continuation; missing history requires separate expiry/no-effect proof. */
  retryAfter?: string;
  reader?: Pick<ChainReader, "getSignatureStatus"> & Partial<Pick<ChainReader, "getAccountAtLeast">> & {
    getFinalizedBlockhashStatus?: (blockhash: string, originSlot: bigint) => Promise<BlockhashCheck>;
  };
  /** Legacy journal only: supplied slot must authenticate the exact finalized blockhash. */
  retryBlockhashSlot?: bigint;
}): Promise<{ signature: string; result: SubmitResult }> {
  const account = await a.ledger.getAccount(a.payment);
  if (!account || account.owner !== a.programId) throw new Error(`payment ${a.payment} is not owned by ${a.programId}`);
  const stored = decodePayment(account.data);
  if (!stored) throw new Error(`payment ${a.payment} data is invalid`);
  if (stored.payer !== a.payer.address) throw new Error(`payment ${a.payment} is not this payer's payment`);
  if (stored.held === 0n) throw new Error("reclaim requires a positive remaining hold");
  if ((await a.ledger.now()) < stored.captureDeadline) throw new Error("reclaim requires cluster Clock >= captureDeadline");
  let reclaimRecovery: PreparedSubmission["reclaimRecovery"];
  if (a.retryAfter !== undefined) {
    if (!isSignature(a.retryAfter) || !a.reader) throw new Error("reclaim continuation requires an original signature and chain reader");
    const previous = a.journal.read(a.retryAfter);
    if (!previous || previous.signature !== a.retryAfter || previous.operation !== "reclaim" || previous.payment !== a.payment || previous.payer !== a.payer.address) throw new Error("original signature is not this payment's journaled reclaim");
    const status = await a.reader.getSignatureStatus(a.retryAfter);
    if (status.kind === "found" && status.commitment === "finalized" && typeof status.err === "string" && status.err.length > 0) {
      a.journal.resolve(a.retryAfter, { result: "finalized-failed", recordedAt: new Date().toISOString(), detail: status.err });
    } else {
      const blocked = () => new Error("original reclaim is not proved finalized-failed or expired without effect; continuation is blocked");
      if (status.kind !== "not-found" || previous.attempts.at(-1)?.outcome?.result === "finalized-succeeded" ||
          !a.reader.getFinalizedBlockhashStatus || !a.reader.getAccountAtLeast) throw blocked();
      const originSlot = previous.blockhashSlot === undefined ? a.retryBlockhashSlot : /^(0|[1-9][0-9]*)$/.test(previous.blockhashSlot) ? BigInt(previous.blockhashSlot) : undefined;
      if (originSlot === undefined || originSlot < 0n) throw blocked();
      // Authenticate the complete wire as this payer's single recent-blockhash reclaim.
      // Height is off-wire metadata. This rebuild excludes nonce/extra spending instructions;
      // it never submits the old transaction or changes its journal.
      const original = await buildTransaction({ feePayer: a.payer.address,
        instructions: [await reclaimInstruction({ programId: a.programId, payment: a.payment, payer: a.payer.address, server: stored.server, mint: stored.mint })],
        signers: [a.payer], lifetime: { blockhash: previous.blockhash as Blockhash, lastValidBlockHeight: a.lifetime.lastValidBlockHeight } });
      if (getSignatureFromTransaction(original) !== previous.signature || messageHash(original.messageBytes) !== previous.messageHash ||
          getBase64EncodedWireTransaction(original) !== previous.transactionBase64) throw blocked();
      const expiry = await a.reader.getFinalizedBlockhashStatus(previous.blockhash, originSlot);
      if (expiry.kind !== "ok" || expiry.valid || expiry.slot <= originSlot) throw blocked();
      const read = await a.reader.getAccountAtLeast(a.payment, expiry.slot);
      if (read.kind !== "ok" || read.slot < expiry.slot || !read.account || read.account.owner !== a.programId) throw blocked();
      const after = decodePayment(read.account.data);
      // H never increases in this one-use payment. Successful reclaim permanently makes H=0.
      // Exact pair/bytes refuse stale state and changed terms. A concurrent release after this
      // read can only make the onchain H>0 guard fail, never cause a second economic effect.
      if (!after || after.held === 0n || after.held.toString() !== previous.expectedHeld || after.refundable.toString() !== previous.expectedRefundable ||
          Buffer.compare(Buffer.from(account.data), Buffer.from(read.account.data)) !== 0) throw blocked();
      reclaimRecovery = { kind: "expired-no-effect", blockhash: previous.blockhash, originSlot: originSlot.toString(), expirySlot: expiry.slot.toString(), paymentSlot: read.slot.toString() };
    }
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
    ...(a.lifetime.blockhashSlot === undefined ? {} : { blockhashSlot: a.lifetime.blockhashSlot.toString() }),
    lastValidBlockHeight: a.lifetime.lastValidBlockHeight.toString(),
    ...(reclaimRecovery === undefined ? {} : { reclaimRecovery }),
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
  const [paymentArg, flag, retryAfter, slotFlag, slotArg, ...rest] = process.argv.slice(2);
  const payment = paymentArg as Address | undefined;
  if (!payment || (flag !== undefined && (flag !== "--retry-after" || !retryAfter)) ||
      (slotFlag !== undefined && (slotFlag !== "--blockhash-slot" || !/^(0|[1-9][0-9]*)$/.test(slotArg ?? ""))) || rest.length !== 0) {
    throw new Error("usage: node reclaim.ts <payment-address> [--retry-after <original-signature> [--blockhash-slot <finalized-origin-slot>]]");
  }
  const record = loadDeploymentRecord(requireEnv("SAC006_DEPLOYMENT_RECORD_PATH"));
  const rpcUrl = requireEnv("SOLANA_RPC_URL");
  const payer = await loadKeypair(requireEnv("SAC006_PAYER_KEYPAIR_PATH"));
  const ledger = new RpcLedger({ deployment: record, network: record.network.caip2, genesisHash: record.network.genesisHash, rpcUrl });
  await ledger.verifyGenesis();
  const journal = new FileSubmissionJournal(process.env.SAC006_RECLAIM_JOURNAL_DIR ?? requireEnv("SAC006_FACILITATOR_JOURNAL_DIR"));
  const { signature, result } = await withShared(journal.coordination, async () => {
    journal.assertAccess();
    return submitReclaim({ ledger, programId: record.programId, payer, payment, lifetime: await ledger.latestBlockhash(), journal, retryAfter, retryBlockhashSlot: slotArg === undefined ? undefined : BigInt(slotArg), reader: ledger });
  });
  const status = await ledger.getSignatureStatus(signature);
  console.log(JSON.stringify({ payment, signature, result, status }, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 2));
}

if (process.argv[1]?.endsWith("reclaim.ts")) {
  main().catch((error) => {
    console.error(error instanceof Error ? (error.stack ?? error.message) : String(error));
    process.exitCode = 1;
  });
}
