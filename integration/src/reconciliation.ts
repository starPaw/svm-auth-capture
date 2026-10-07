// Read-only manual reconciliation for `OperationStore` records (SAC-006 gap #3; ARCHITECTURE,
// "Relay, recovery, and separation from application state"). For each journaled submission it
// identifies the *original* transaction — by the signature a facilitator receipt reported, by
// the facilitator's pre-broadcast journal, or by matching the exact journaled message bytes
// against the payment's transaction history — and reports that signature's status, the
// blockhash lifetime, and a payment-account snapshot read at a slot no older than the evidence
// it is compared with. It never resubmits, re-signs, or updates the store: an operator decides
// the real outcome from this report. Unavailable history or RPC evidence stays unknown, never
// absence.
import {
  type Address,
  getBase64Encoder,
  getCompiledTransactionMessageDecoder,
  getTransactionDecoder,
} from "@solana/kit";
import type { LedgerAccount } from "./ledger.ts";
import type { OperationRecord, OperationStore, PreSubmission } from "./operation-store.ts";
import { decodePayment } from "./program.ts";
import { messageHash } from "./submission-journal.ts";

export type SignatureLookup =
  | { kind: "unavailable"; detail: string }
  | { kind: "not-found" }
  | { kind: "found"; slot: bigint; commitment: "processed" | "confirmed" | "finalized"; err: string | null };

export type MessageSearch = { kind: "unavailable"; detail: string } | { kind: "ok"; signatures: string[]; truncated: boolean };

export type BlockhashCheck = { kind: "unavailable"; detail: string } | { kind: "ok"; valid: boolean; slot: bigint };

export type SlotAccount = { kind: "unavailable"; detail: string } | { kind: "ok"; slot: bigint; account: LedgerAccount | null };

/** The read-only chain evidence reconciliation needs; `RpcLedger` implements it. */
export interface ChainReader {
  getSignatureStatus(signature: string): Promise<SignatureLookup>;
  /** Signatures of transactions touching `address` whose message bytes equal `messageBytes`. */
  findSignaturesByMessage(address: Address, messageBytes: Uint8Array): Promise<MessageSearch>;
  /** Whether `blockhash` can still be used, as of the latest bank at the returned slot. */
  isBlockhashValid(blockhash: string): Promise<BlockhashCheck>;
  /** The account as of a finalized slot no older than `minContextSlot`. */
  getAccountAtLeast(address: Address, minContextSlot: bigint): Promise<SlotAccount>;
}

/** Looks up the facilitator journal's signature for a message hash, if that journal is available. */
export type JournalLookup = (messageHash: string) => string[];

export type Verdict =
  | "landed-succeeded" // the original signature is finalized without error
  | "landed-failed" // the original signature is finalized with an execution error: no economic effect
  | "not-final" // seen only at processed/confirmed commitment
  | "may-still-land" // not found and its blockhash is still valid
  | "payment-exists-history-missing" // authorize not found, but the payment identity it creates exists
  | "unknown"; // evidence unavailable, or state moved for a reason this report cannot attribute: stays pending

export type SubmissionEvidence = {
  op: "authorize" | "capture" | "void";
  messageHash: string;
  signature?: string;
  signatureSource?: "receipt" | "facilitator-journal" | "chain-search";
  status: SignatureLookup | MessageSearch;
  blockhash: string;
  blockhashCheck?: BlockhashCheck;
  verdict: Verdict;
};

export type PaymentSnapshot =
  | { kind: "unavailable"; detail: string }
  | { kind: "ok"; slot: string; exists: false }
  | { kind: "ok"; slot: string; exists: true; held: string; refundable: string };

export type ReconcileReport = {
  record: OperationRecord;
  submissions: SubmissionEvidence[];
  payment?: PaymentSnapshot;
  /**
   * `definitive` when every journaled submission's fate is established (it still may leave a
   * hold for the operator to act on); `pending` when any submission may still land or lacks
   * evidence.
   */
  conclusion: "definitive" | "pending";
};

const base64 = getBase64Encoder();
const transactionDecoder = getTransactionDecoder();
const messageDecoder = getCompiledTransactionMessageDecoder();

function journaledMessage(sub: PreSubmission): { bytes: Uint8Array; blockhash: string } {
  const transaction = transactionDecoder.decode(base64.encode(sub.transactionBase64));
  const bytes = new Uint8Array(transaction.messageBytes);
  return { bytes, blockhash: messageDecoder.decode(transaction.messageBytes).lifetimeToken };
}

/** Finds the original signature and its status, without guessing from absence. */
async function locate(
  sub: PreSubmission,
  bytes: Uint8Array,
  hash: string,
  reader: ChainReader,
  journal?: JournalLookup,
): Promise<Pick<SubmissionEvidence, "signature" | "signatureSource" | "status">> {
  if (sub.signature) return { signature: sub.signature, signatureSource: "receipt", status: await reader.getSignatureStatus(sub.signature) };
  const journaled = journal?.(hash) ?? [];
  if (journaled.length === 1) {
    return { signature: journaled[0], signatureSource: "facilitator-journal", status: await reader.getSignatureStatus(journaled[0]!) };
  }
  const search = await reader.findSignaturesByMessage(sub.payment as Address, bytes);
  if (search.kind === "ok" && search.signatures.length === 1) {
    const signature = search.signatures[0]!;
    return { signature, signatureSource: "chain-search", status: await reader.getSignatureStatus(signature) };
  }
  if (search.kind === "ok" && search.signatures.length > 1) {
    return { status: { kind: "unavailable", detail: `ambiguous: ${search.signatures.length} signatures carry these message bytes` } };
  }
  if (search.kind === "ok" && search.truncated) {
    return { status: { kind: "unavailable", detail: "payment history exceeds the bounded search; signature not identified" } };
  }
  return { status: search };
}

/**
 * What the snapshot says about this submission's effect. The payment PDA is never closed in v1,
 * so an absent payment proves no authorize for it ever executed; an existing one proves the
 * identity was authorized (by these bytes or another payer-signed authorize for the same salt).
 * A capture or void always changes a positive hold, so an unchanged expected pair proves it did
 * not execute; a changed pair is not attributed, because payer reclaim also moves it.
 */
function paymentEffect(sub: PreSubmission, op: SubmissionEvidence["op"], snapshot?: PaymentSnapshot): "absent" | "present" | "unattributed" {
  if (!snapshot || snapshot.kind !== "ok") return "unattributed";
  if (op === "authorize") return snapshot.exists ? "present" : "absent";
  if (snapshot.exists && snapshot.held === sub.expectedHeld && snapshot.refundable === sub.expectedRefundable) return "absent";
  return "unattributed";
}

function verdictFor(e: Omit<SubmissionEvidence, "verdict">, sub: PreSubmission, snapshot?: PaymentSnapshot): Verdict {
  const s = e.status;
  if (s.kind === "found") {
    if (s.err !== null && (typeof s.err !== "string" || s.err.length === 0)) return "unknown";
    if (s.commitment !== "finalized") return "not-final";
    return s.err === null ? "landed-succeeded" : "landed-failed";
  }
  const notFound = s.kind === "not-found" || (s.kind === "ok" && s.signatures.length === 0 && !s.truncated);
  if (!notFound || e.blockhashCheck?.kind !== "ok") return "unknown";
  const effect = paymentEffect(sub, e.op, snapshot);
  if (effect === "present") return "payment-exists-history-missing";
  if (effect === "unattributed") return "unknown";
  // false means invalid at that bank, not necessarily expired: it may be unknown to a
  // lagging node or on a competing fork. Neither absence nor unchanged state closes that gap.
  return e.blockhashCheck.valid ? "may-still-land" : "unknown";
}

async function readPayment(reader: ChainReader, programId: Address, payment: Address, minSlot: bigint): Promise<PaymentSnapshot> {
  const read = await reader.getAccountAtLeast(payment, minSlot);
  if (read.kind !== "ok") return read;
  const slot = read.slot.toString();
  if (!read.account || read.account.owner !== programId) return { kind: "ok", slot, exists: false };
  const decoded = decodePayment(read.account.data);
  if (!decoded) return { kind: "unavailable", detail: "payment account is owned by the program but does not decode" };
  return { kind: "ok", slot, exists: true, held: decoded.held.toString(), refundable: decoded.refundable.toString() };
}

/**
 * Reports, for one journaled record, what happened to each of its submissions. Read-only: the
 * store is never modified.
 */
export async function reconcileEntry(
  store: OperationStore,
  reader: ChainReader,
  programId: Address,
  fp: string,
  journal?: JournalLookup,
): Promise<ReconcileReport> {
  const record = store.read(fp);
  if (!record) throw new Error(`no reservation for fingerprint ${fp}`);
  const subs: { sub: PreSubmission; op: SubmissionEvidence["op"] }[] = [];
  if (record.authorize) subs.push({ sub: record.authorize, op: "authorize" });
  if (record.terminal) subs.push({ sub: record.terminal, op: record.terminal.op });
  // Nothing was journaled for submission: no transaction can exist for this record.
  if (subs.length === 0) return { record, submissions: [], conclusion: "definitive" };

  const partial: Omit<SubmissionEvidence, "verdict">[] = [];
  for (const { sub, op } of subs) {
    const { bytes, blockhash } = journaledMessage(sub);
    const hash = messageHash(bytes);
    const located = await locate(sub, bytes, hash, reader, journal);
    const found = located.status.kind === "found";
    partial.push({ op, messageHash: hash, ...located, blockhash, ...(found ? {} : { blockhashCheck: await reader.isBlockhashValid(blockhash) }) });
  }

  // Read the payment no earlier than every slot the verdicts rely on: each found transaction's
  // slot and each blockhash-expiry observation.
  let minSlot = 0n;
  for (const e of partial) {
    if (e.status.kind === "found" && e.status.slot > minSlot) minSlot = e.status.slot;
    if (e.blockhashCheck?.kind === "ok" && e.blockhashCheck.slot > minSlot) minSlot = e.blockhashCheck.slot;
  }
  const payment = await readPayment(reader, programId, subs[0]!.sub.payment as Address, minSlot);

  const submissions = partial.map((e, i) => ({ ...e, verdict: verdictFor(e, subs[i]!.sub, payment) }));
  const definitive: ReadonlySet<Verdict> = new Set(["landed-succeeded", "landed-failed"]);
  return { record, submissions, payment, conclusion: submissions.every((s) => definitive.has(s.verdict)) ? "definitive" : "pending" };
}
