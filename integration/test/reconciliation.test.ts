// Unit tests for read-only manual reconciliation (SAC-006 gap #3) against a fake `ChainReader` —
// no network access. Exercises identifying the original transaction (receipt signature,
// facilitator pre-broadcast journal, exact-message chain search), the finality/lifetime
// verdicts, payment evidence read no older than the evidence it is compared with, and that
// unavailable or unattributable evidence stays pending and the store is never modified.
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type Address,
  generateKeyPairSigner,
  getBase64EncodedWireTransaction,
  getTransactionDecoder,
  lamports,
  type Transaction,
} from "@solana/kit";
import { getTransferSolInstruction } from "@solana-program/system";
import { describe, expect, test } from "vitest";
import type { LedgerAccount } from "../src/ledger.js";
import { OperationStore, type PreSubmission } from "../src/operation-store.js";
import { DISCRIMINATOR, LOCAL_PROGRAM_ID, PAYMENT_LEN } from "../src/program.js";
import type { BlockhashCheck, ChainReader, MessageSearch, SignatureLookup, SlotAccount } from "../src/reconciliation.js";
import { reconcileEntry } from "../src/reconciliation.js";
import { messageHash } from "../src/submission-journal.js";
import { buildTransaction } from "../src/transactions.js";

const PAYMENT = "11111111111111111111111111111112" as Address;
const BLOCKHASH = "11111111111111111111111111111111111111111111";

async function journaledTransaction(): Promise<Transaction> {
  const [feePayer, destination] = await Promise.all([generateKeyPairSigner(), generateKeyPairSigner()]);
  return buildTransaction({
    feePayer: feePayer.address,
    instructions: [getTransferSolInstruction({ source: feePayer, destination: destination.address, amount: lamports(1n) })],
    signers: [feePayer],
    lifetime: { blockhash: BLOCKHASH as never, lastValidBlockHeight: 1n },
  });
}

/** Builds a valid `Payment` account's raw bytes for a given `(held, refundable)`. */
function paymentAccount(held: bigint, refundable: bigint): LedgerAccount {
  const data = new Uint8Array(PAYMENT_LEN);
  data.set(DISCRIMINATOR, 0);
  data.set(new Uint8Array(32).fill(1), 8);
  data.set(new Uint8Array(32).fill(2), 40);
  data.set(new Uint8Array(32).fill(3), 72);
  const view = new DataView(data.buffer);
  view.setBigUint64(136, 1_000n, true);
  view.setBigInt64(144, 2_000n, true);
  view.setBigInt64(152, 3_000n, true);
  view.setBigUint64(160, held, true);
  view.setBigUint64(168, refundable, true);
  return { owner: LOCAL_PROGRAM_ID, data, lamports: 1n, executable: false };
}

type Fake = {
  statuses?: Record<string, SignatureLookup>;
  search?: MessageSearch;
  blockhash?: BlockhashCheck;
  account?: LedgerAccount | null | "unavailable";
  accountSlot?: bigint;
};

function fakeReader(f: Fake): ChainReader & { accountReads: bigint[]; searches: number } {
  const reader = {
    accountReads: [] as bigint[],
    searches: 0,
    getSignatureStatus: async (sig: string): Promise<SignatureLookup> => f.statuses?.[sig] ?? { kind: "not-found" },
    findSignaturesByMessage: async (): Promise<MessageSearch> => {
      reader.searches += 1;
      return f.search ?? { kind: "ok", signatures: [], truncated: false };
    },
    isBlockhashValid: async (): Promise<BlockhashCheck> => f.blockhash ?? { kind: "ok", valid: false, slot: 500n },
    getAccountAtLeast: async (_a: Address, minContextSlot: bigint): Promise<SlotAccount> => {
      reader.accountReads.push(minContextSlot);
      if (f.account === "unavailable") return { kind: "unavailable", detail: "rpc down" };
      return { kind: "ok", slot: f.accountSlot ?? minContextSlot, account: f.account ?? null };
    },
  };
  return reader;
}

async function storeWith(o: { authorize?: Partial<PreSubmission>; terminal?: Partial<PreSubmission> & { op: "capture" | "void" } }) {
  const store = new OperationStore(mkdtempSync(join(tmpdir(), "sac006-reconcile-")));
  store.reserve("fp", "payer", "/resource");
  const sub = async (over: Partial<PreSubmission> | undefined, held: string): Promise<PreSubmission | undefined> => {
    if (!over) return undefined;
    const tx = await journaledTransaction();
    return { transactionBase64: getBase64EncodedWireTransaction(tx), signature: "", blockhash: BLOCKHASH, payment: PAYMENT, expectedHeld: held, expectedRefundable: "0", ...over };
  };
  const authorize = await sub(o.authorize, "0");
  const terminal = o.terminal ? { ...(await sub(o.terminal, "100"))!, op: o.terminal.op } : undefined;
  store.update("fp", { status: terminal ? "terminal-pending" : "authorize-pending", ...(authorize ? { authorize } : {}), ...(terminal ? { terminal } : {}) });
  return store;
}

const finalized = (slot: bigint, err: string | null = null): SignatureLookup => ({ kind: "found", slot, commitment: "finalized", err });

describe("reconcileEntry: identifying the original transaction", () => {
  test("a record that never journaled a submission has nothing to reconcile", async () => {
    const store = new OperationStore(mkdtempSync(join(tmpdir(), "sac006-reconcile-")));
    store.reserve("fp", "payer", "/resource");
    const report = await reconcileEntry(store, fakeReader({}), LOCAL_PROGRAM_ID, "fp");
    expect(report.submissions).toEqual([]);
    expect(report.conclusion).toBe("definitive");
  });

  test("uses a receipt's signature and reads the payment no older than its finalized slot", async () => {
    const store = await storeWith({ authorize: { signature: "authSig" } });
    const reader = fakeReader({ statuses: { authSig: finalized(300n) }, account: paymentAccount(100n, 0n), accountSlot: 301n });
    const report = await reconcileEntry(store, reader, LOCAL_PROGRAM_ID, "fp");
    expect(report.submissions[0]).toMatchObject({ op: "authorize", signature: "authSig", signatureSource: "receipt", verdict: "landed-succeeded" });
    expect(reader.accountReads).toEqual([300n]);
    expect(report.payment).toEqual({ kind: "ok", slot: "301", exists: true, held: "100", refundable: "0" });
    expect(report.conclusion).toBe("definitive");
  });

  test("a lost response is resolved through the facilitator's pre-broadcast journal by message hash", async () => {
    const store = await storeWith({ authorize: {} });
    const record = store.read("fp")!;
    const tx = getTransactionDecoder().decode(Buffer.from(record.authorize!.transactionBase64, "base64"));
    const hash = messageHash(tx.messageBytes);
    const reader = fakeReader({ statuses: { journalSig: finalized(10n, '{"InstructionError":[0,{"Custom":6}]}') } });
    const report = await reconcileEntry(store, reader, LOCAL_PROGRAM_ID, "fp", (h) => (h === hash ? ["journalSig"] : []));
    expect(report.submissions[0]).toMatchObject({ signature: "journalSig", signatureSource: "facilitator-journal", verdict: "landed-failed" });
    expect(reader.searches).toBe(0);
  });

  test("a lost response is resolved by matching the exact message bytes in the payment's history", async () => {
    const store = await storeWith({ authorize: {} });
    const reader = fakeReader({ search: { kind: "ok", signatures: ["chainSig"], truncated: false }, statuses: { chainSig: finalized(20n) } });
    const report = await reconcileEntry(store, reader, LOCAL_PROGRAM_ID, "fp");
    expect(report.submissions[0]).toMatchObject({ signature: "chainSig", signatureSource: "chain-search", verdict: "landed-succeeded" });
  });

  test("a status below finalized stays pending", async () => {
    const store = await storeWith({ authorize: { signature: "s" } });
    const reader = fakeReader({ statuses: { s: { kind: "found", slot: 5n, commitment: "confirmed", err: null } } });
    const report = await reconcileEntry(store, reader, LOCAL_PROGRAM_ID, "fp");
    expect(report.submissions[0]!.verdict).toBe("not-final");
    expect(report.conclusion).toBe("pending");
  });
});

describe("reconcileEntry: absence is never assumed", () => {
  test("not found while the blockhash is still valid: may still land", async () => {
    const store = await storeWith({ authorize: {} });
    const reader = fakeReader({ blockhash: { kind: "ok", valid: true, slot: 50n } });
    const report = await reconcileEntry(store, reader, LOCAL_PROGRAM_ID, "fp");
    expect(report.submissions[0]!.verdict).toBe("may-still-land");
    expect(report.conclusion).toBe("pending");
  });

  test("an unknown but still-live blockhash cannot prove expiry", async () => {
    const store = await storeWith({ authorize: {} });
    const reader = fakeReader({ blockhash: { kind: "ok", valid: false, slot: 500n } });
    const report = await reconcileEntry(store, reader, LOCAL_PROGRAM_ID, "fp");
    expect(report.submissions[0]!.verdict).toBe("unknown");
    expect(reader.accountReads).toEqual([500n]);
    expect(report.conclusion).toBe("pending");
  });

  test("not found but the payment exists: history is missing, not absence", async () => {
    const store = await storeWith({ authorize: {} });
    const reader = fakeReader({ account: paymentAccount(100n, 0n) });
    const report = await reconcileEntry(store, reader, LOCAL_PROGRAM_ID, "fp");
    expect(report.submissions[0]!.verdict).toBe("payment-exists-history-missing");
    expect(report.conclusion).toBe("pending");
  });

  test("an unknown blockhash and unchanged pair cannot rule out later execution", async () => {
    const store = await storeWith({ authorize: { signature: "a" }, terminal: { op: "capture" } });
    const reader = fakeReader({ statuses: { a: finalized(10n) }, account: paymentAccount(100n, 0n) });
    const report = await reconcileEntry(store, reader, LOCAL_PROGRAM_ID, "fp");
    expect(report.submissions.map((s) => s.verdict)).toEqual(["landed-succeeded", "unknown"]);
  });

  test("an expired terminal whose pair moved is not attributed (payer reclaim also moves it)", async () => {
    const store = await storeWith({ authorize: { signature: "a" }, terminal: { op: "capture" } });
    const reader = fakeReader({ statuses: { a: finalized(10n) }, account: paymentAccount(0n, 0n) });
    const report = await reconcileEntry(store, reader, LOCAL_PROGRAM_ID, "fp");
    expect(report.submissions[1]!.verdict).toBe("unknown");
    expect(report.conclusion).toBe("pending");
  });

  test("unavailable history or account evidence stays unknown", async () => {
    const unavailableSearch = await reconcileEntry(
      await storeWith({ authorize: {} }),
      fakeReader({ search: { kind: "unavailable", detail: "429" } }),
      LOCAL_PROGRAM_ID,
      "fp",
    );
    expect(unavailableSearch.submissions[0]!.verdict).toBe("unknown");
    const unavailableAccount = await reconcileEntry(await storeWith({ authorize: {} }), fakeReader({ account: "unavailable" }), LOCAL_PROGRAM_ID, "fp");
    expect(unavailableAccount.submissions[0]!.verdict).toBe("unknown");
    expect(unavailableAccount.conclusion).toBe("pending");
  });

  test("a bounded search that was truncated does not count as absence", async () => {
    const store = await storeWith({ authorize: {} });
    const report = await reconcileEntry(store, fakeReader({ search: { kind: "ok", signatures: [], truncated: true } }), LOCAL_PROGRAM_ID, "fp");
    expect(report.submissions[0]!.verdict).toBe("unknown");
  });

  test("never modifies the store", async () => {
    const store = await storeWith({ authorize: { signature: "s" } });
    const dir = (store as unknown as { dir: string }).dir;
    const before = readFileSync(join(dir, "fp.json"), "utf8");
    await reconcileEntry(store, fakeReader({ statuses: { s: finalized(1n) } }), LOCAL_PROGRAM_ID, "fp");
    expect(readFileSync(join(dir, "fp.json"), "utf8")).toBe(before);
  });

  test("throws for a fingerprint with no reservation", async () => {
    const store = new OperationStore(mkdtempSync(join(tmpdir(), "sac006-reconcile-")));
    await expect(reconcileEntry(store, fakeReader({}), LOCAL_PROGRAM_ID, "missing")).rejects.toThrow(/no reservation/);
  });
});
