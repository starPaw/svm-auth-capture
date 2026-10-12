// Public finalized transaction evidence only. Never signs, sends, or reads a key.
import { getBase64Encoder, getCompiledTransactionMessageDecoder, getPublicKeyFromAddress, getSignatureFromTransaction, getTransactionDecoder, isSignature, verifySignature, type Address, type SignatureBytes } from '@solana/kit';
import { createHash } from 'node:crypto';
import { encodeTransaction } from './transactions.ts';

export type FinalizedTransaction = { slot: bigint; wire: string; error: unknown;
  fee: bigint; preBalances: bigint[]; postBalances: bigint[] };
export const messageDigest = (bytes: ArrayLike<number>) => createHash('sha256').update(Buffer.from(bytes)).digest('hex');
export async function verifiedProof(signature: string, proof: FinalizedTransaction) {
  if (!isSignature(signature) || typeof proof.slot !== 'bigint' || proof.slot < 0n ||
      typeof proof.fee !== 'bigint' || proof.fee < 0n || proof.error === undefined) throw Error('invalid finalized evidence');
  const tx = getTransactionDecoder().decode(getBase64Encoder().encode(proof.wire));
  if (encodeTransaction(tx) !== proof.wire || getSignatureFromTransaction(tx) !== signature) throw Error('original canonical signature/wire mismatch');
  const message = getCompiledTransactionMessageDecoder().decode(tx.messageBytes);
  if (message.version !== 'legacy' || message.header.numSignerAccounts < 1) throw Error('unsupported approved wire version');
  for (const balances of [proof.preBalances, proof.postBalances]) {
    if (!Array.isArray(balances) || balances.length !== message.staticAccounts.length || balances.some(n => typeof n !== 'bigint' || n < 0n || n > (1n << 64n) - 1n)) throw Error('invalid finalized balance metadata');
  }
  for (const address of message.staticAccounts.slice(0, message.header.numSignerAccounts)) {
    const bytes = tx.signatures[address];
    if (!bytes || !await verifySignature(await getPublicKeyFromAddress(address), bytes as SignatureBytes, tx.messageBytes)) throw Error('invalid original transaction signature');
  }
  return { transaction: tx, message, messageHash: messageDigest(tx.messageBytes) };
}
export async function finalizedOutflow(signature: string, proof: FinalizedTransaction, payer: Address, expectedMessageHash: string) {
  const verified = await verifiedProof(signature, proof);
  if (verified.messageHash !== expectedMessageHash || verified.message.staticAccounts[0] !== payer) throw Error('budget original message/payer mismatch');
  const outflow = proof.preBalances[0]! - proof.postBalances[0]!;
  if (outflow < proof.fee || proof.error !== null && outflow !== proof.fee) throw Error('inconsistent finalized outflow');
  return { fees: proof.fee, nonFeeOutflow: outflow - proof.fee, failed: proof.error !== null, slot: proof.slot, message: verified.message };
}
