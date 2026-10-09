// Client and resource-server helpers that build the partially signed transactions and the
// x402 payloads the facilitator relays. The economic party signs; the facilitator adds only
// its fee-payer signature at `/settle`.
import {
  type Address,
  appendTransactionMessageInstructions,
  type Blockhash,
  compileTransaction,
  createTransactionMessage,
  getBase64EncodedWireTransaction,
  type Instruction,
  type KeyPairSigner,
  partiallySignTransaction,
  pipe,
  setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash,
  type Transaction,
} from "@solana/kit";
import {
  ata,
  authorizeAccounts,
  authorizeData,
  captureAccounts,
  captureData,
  paymentAddress,
  reclaimAccounts,
  refundAccounts,
  refundData,
  Tag,
  toInstruction,
  voidAccounts,
  voidData,
} from "./program.ts";

import { retainObservation } from "./lifetime-provenance.ts";

export type Lifetime = { blockhash: Blockhash; lastValidBlockHeight: bigint; blockhashSlot?: bigint;
  contextSlot?: bigint; commitment?: "processed" | "confirmed" | "finalized"; network?: string; genesisHash?: string };

/** Compiles a legacy message with the sponsor as fee payer and applies the given partial signers. */
export async function buildTransaction(a: {
  feePayer: Address;
  instructions: Instruction[];
  signers: KeyPairSigner[];
  lifetime: Lifetime;
}): Promise<Transaction> {
  const message = pipe(
    createTransactionMessage({ version: "legacy" }),
    (m) => setTransactionMessageFeePayer(a.feePayer, m),
    (m) => setTransactionMessageLifetimeUsingBlockhash(a.lifetime, m),
    (m) => appendTransactionMessageInstructions(a.instructions, m),
  );
  const transaction = await partiallySignTransaction(
    a.signers.map((s) => s.keyPair),
    compileTransaction(message),
  );
  retainObservation(transaction, a.lifetime);
  return transaction;
}

export const encodeTransaction = (tx: Transaction): string => getBase64EncodedWireTransaction(tx);

/** The client's payer-signed authorization: the exact authorize instruction and its accounts. */
export async function authorizeInstruction(a: {
  programId: Address;
  payer: Address;
  server: Address;
  mint: Address;
  funder: Address;
  salt: Uint8Array;
  maximum: bigint;
  captureDeadline: bigint;
  refundDeadline: bigint;
}): Promise<Instruction> {
  const payment = await paymentAddress(a.programId, a.payer, a.salt);
  return toInstruction(
    a.programId,
    authorizeAccounts({
      payer: a.payer,
      server: a.server,
      payment,
      mint: a.mint,
      source: await ata(a.payer, a.mint),
      vault: await ata(payment, a.mint),
      funder: a.funder,
    }),
    authorizeData(a.salt, a.maximum, a.captureDeadline, a.refundDeadline),
  );
}

type Stored = { programId: Address; payment: Address; payer: Address; server: Address; mint: Address };

export async function captureInstruction(
  s: Stored,
  amount: bigint,
  releaseRemainder: boolean,
  expectedHeld: bigint,
  expectedRefundable: bigint,
): Promise<Instruction> {
  return toInstruction(
    s.programId,
    captureAccounts({
      server: s.server,
      payment: s.payment,
      mint: s.mint,
      vault: await ata(s.payment, s.mint),
      serverAta: await ata(s.server, s.mint),
      payerAta: await ata(s.payer, s.mint),
    }),
    captureData(amount, releaseRemainder, expectedHeld, expectedRefundable),
  );
}

export async function voidInstruction(s: Stored, expectedHeld: bigint, expectedRefundable: bigint): Promise<Instruction> {
  return toInstruction(
    s.programId,
    voidAccounts({
      server: s.server,
      payment: s.payment,
      mint: s.mint,
      vault: await ata(s.payment, s.mint),
      payerAta: await ata(s.payer, s.mint),
    }),
    voidData(expectedHeld, expectedRefundable),
  );
}

export async function refundInstruction(
  s: Stored,
  amount: bigint,
  expectedHeld: bigint,
  expectedRefundable: bigint,
): Promise<Instruction> {
  return toInstruction(
    s.programId,
    refundAccounts({
      server: s.server,
      payment: s.payment,
      mint: s.mint,
      serverAta: await ata(s.server, s.mint),
      payerAta: await ata(s.payer, s.mint),
    }),
    refundData(amount, expectedHeld, expectedRefundable),
  );
}

/**
 * The payer's direct reclaim: builds the one-signer `reclaim` instruction (wire: `[Tag.reclaim]`,
 * no further fields). Never relayed through the facilitator (`/settle` rejects with
 * `Reason.reclaimNotRelayed`): the payer signs, pays their own fee, and submits this directly
 * against a `Ledger`, so it stays usable while the facilitator and resource server are both
 * stopped.
 */
export async function reclaimInstruction(s: Stored): Promise<Instruction> {
  return toInstruction(
    s.programId,
    reclaimAccounts({ payer: s.payer, payment: s.payment, mint: s.mint, vault: await ata(s.payment, s.mint), payerAta: await ata(s.payer, s.mint) }),
    Uint8Array.of(Tag.reclaim),
  );
}

export const authorizePayload = (tx: Transaction) => ({ transaction: encodeTransaction(tx) });

export const capturePayload = (
  payment: Address,
  tx: Transaction,
  amount: bigint,
  releaseRemainder: boolean,
  expectedHeld: bigint,
  expectedRefundable: bigint,
) => ({
  type: "capture",
  payment,
  transaction: encodeTransaction(tx),
  amount: amount.toString(),
  releaseRemainder,
  expectedHeld: expectedHeld.toString(),
  expectedRefundable: expectedRefundable.toString(),
});

export const voidPayload = (payment: Address, tx: Transaction, expectedHeld: bigint, expectedRefundable: bigint) => ({
  type: "void",
  payment,
  transaction: encodeTransaction(tx),
  expectedHeld: expectedHeld.toString(),
  expectedRefundable: expectedRefundable.toString(),
});

export const refundPayload = (
  payment: Address,
  tx: Transaction,
  amount: bigint,
  expectedHeld: bigint,
  expectedRefundable: bigint,
) => ({
  type: "refund",
  payment,
  transaction: encodeTransaction(tx),
  amount: amount.toString(),
  expectedHeld: expectedHeld.toString(),
  expectedRefundable: expectedRefundable.toString(),
});
