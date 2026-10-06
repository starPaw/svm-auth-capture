// Unit tests for `OperationStore` and `reconcileEntry` (SAC-006 gap #3) — no network access.
// Exercises atomic reservation/conflict, update/read round-tripping, `pending()` filtering, and
// `reconcileEntry`'s read-only reporting against a fake `Ledger`.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Address } from "@solana/kit";
import { describe, expect, test } from "vitest";
import type { Ledger, LedgerAccount, SimulationOutcome, SubmitResult } from "../src/ledger.js";
import { DISCRIMINATOR, LOCAL_PROGRAM_ID, PAYMENT_LEN } from "../src/program.js";
import { fingerprint, OperationStore, reconcileEntry, ReservationConflict } from "../src/operation-store.js";

const PAYMENT = "11111111111111111111111111111112" as Address;

function freshDir(): string {
  return mkdtempSync(join(tmpdir(), "sac006-store-"));
}

/** Builds a valid `Payment` account's raw bytes for a given `(held, refundable)`. */
function paymentBytes(held: bigint, refundable: bigint): Uint8Array {
  const data = new Uint8Array(PAYMENT_LEN);
  data.set(DISCRIMINATOR, 0);
  const payer = new Uint8Array(32).fill(1);
  const server = new Uint8Array(32).fill(2);
  const mint = new Uint8Array(32).fill(3);
  data.set(payer, 8);
  data.set(server, 40);
  data.set(mint, 72);
  const view = new DataView(data.buffer);
  view.setBigUint64(136, 1_000n, true); // maximum
  view.setBigInt64(144, 2_000n, true); // captureDeadline
  view.setBigInt64(152, 3_000n, true); // refundDeadline
  view.setBigUint64(160, held, true);
  view.setBigUint64(168, refundable, true);
  return data;
}

/** A fake `Ledger` whose `getAccount` is configurable per test; the other methods are unused here. */
function fakeLedger(getAccount: (address: Address) => Promise<LedgerAccount | null>): Ledger {
  return {
    network: "solana:fake",
    now: () => Promise.resolve(0n),
    getAccount,
    simulate: (): Promise<SimulationOutcome> => Promise.resolve({ ok: true }),
    submit: (): Promise<SubmitResult> => Promise.resolve({ kind: "submitted" }),
  };
}

describe("fingerprint", () => {
  test("is stable for the same inputs and differs when any input changes", () => {
    const salt = new Uint8Array(32).fill(7);
    const a = fingerprint("payer-1", "/resource", salt);
    const b = fingerprint("payer-1", "/resource", salt);
    expect(a).toBe(b);
    expect(fingerprint("payer-2", "/resource", salt)).not.toBe(a);
    expect(fingerprint("payer-1", "/other", salt)).not.toBe(a);
    expect(fingerprint("payer-1", "/resource", new Uint8Array(32).fill(8))).not.toBe(a);
  });
});

describe("OperationStore.reserve", () => {
  test("claims a fresh fingerprint with status reserved", () => {
    const store = new OperationStore(freshDir());
    const record = store.reserve("fp-1", "payer-1", "/resource");
    expect(record.status).toBe("reserved");
    expect(record.caller).toBe("payer-1");
    expect(record.resource).toBe("/resource");
    expect(store.read("fp-1")).toEqual(record);
  });

  test("rejects a second reservation of the same fingerprint with ReservationConflict", () => {
    const store = new OperationStore(freshDir());
    store.reserve("fp-1", "payer-1", "/resource");
    expect(() => store.reserve("fp-1", "payer-1", "/resource")).toThrow(ReservationConflict);
  });
});

describe("OperationStore.read", () => {
  test("returns undefined for an unreserved fingerprint", () => {
    const store = new OperationStore(freshDir());
    expect(store.read("missing")).toBeUndefined();
  });
});

describe("OperationStore.update", () => {
  test("merges a patch and advances updatedAt without touching createdAt or fingerprint", async () => {
    const store = new OperationStore(freshDir());
    const reserved = store.reserve("fp-1", "payer-1", "/resource");
    await new Promise((r) => setTimeout(r, 2));
    const updated = store.update("fp-1", { status: "authorized" });
    expect(updated.status).toBe("authorized");
    expect(updated.fingerprint).toBe("fp-1");
    expect(updated.createdAt).toBe(reserved.createdAt);
    expect(updated.updatedAt).not.toBe(reserved.updatedAt);
    expect(store.read("fp-1")?.status).toBe("authorized");
  });

  test("throws for a fingerprint with no reservation", () => {
    const store = new OperationStore(freshDir());
    expect(() => store.update("missing", { status: "completed" })).toThrow(/no reservation/);
  });
});

describe("OperationStore.list / pending", () => {
  test("pending() returns only non-terminal-stop statuses", () => {
    const store = new OperationStore(freshDir());
    store.reserve("fp-done", "payer-1", "/resource");
    store.update("fp-done", { status: "completed" });
    store.reserve("fp-pending-1", "payer-2", "/resource");
    store.update("fp-pending-1", { status: "authorize-pending" });
    store.reserve("fp-pending-2", "payer-3", "/resource");
    store.update("fp-pending-2", { status: "pending" });
    store.reserve("fp-reserved", "payer-4", "/resource");

    expect(store.list()).toHaveLength(4);
    const pendingFingerprints = store.pending().map((r) => r.fingerprint).sort();
    expect(pendingFingerprints).toEqual(["fp-pending-1", "fp-pending-2"]);
  });
});

describe("reconcileEntry", () => {
  test("reports no on-chain payment when the record never reached an authorize attempt", async () => {
    const store = new OperationStore(freshDir());
    store.reserve("fp-1", "payer-1", "/resource");
    const ledger = fakeLedger(() => Promise.resolve(null));
    const result = await reconcileEntry(store, ledger, LOCAL_PROGRAM_ID, "fp-1");
    expect(result.onchainPayment).toBeUndefined();
  });

  test("reports exists:false when the payment account is absent", async () => {
    const store = new OperationStore(freshDir());
    store.reserve("fp-1", "payer-1", "/resource");
    store.update("fp-1", {
      status: "authorizing",
      authorize: { transactionBase64: "x", signature: "sig", blockhash: "bh", payment: PAYMENT, expectedHeld: "0", expectedRefundable: "0" },
    });
    const ledger = fakeLedger(() => Promise.resolve(null));
    const result = await reconcileEntry(store, ledger, LOCAL_PROGRAM_ID, "fp-1");
    expect(result.onchainPayment).toEqual({ exists: false });
  });

  test("reports held/refundable from a decoded on-chain payment", async () => {
    const store = new OperationStore(freshDir());
    store.reserve("fp-1", "payer-1", "/resource");
    store.update("fp-1", {
      status: "authorized",
      authorize: { transactionBase64: "x", signature: "sig", blockhash: "bh", payment: PAYMENT, expectedHeld: "0", expectedRefundable: "0" },
    });
    const account: LedgerAccount = { owner: LOCAL_PROGRAM_ID, data: paymentBytes(500n, 0n), lamports: 1n, executable: false };
    const ledger = fakeLedger(() => Promise.resolve(account));
    const result = await reconcileEntry(store, ledger, LOCAL_PROGRAM_ID, "fp-1");
    expect(result.onchainPayment).toEqual({ exists: true, held: "500", refundable: "0" });
  });

  test("throws for a fingerprint with no reservation", async () => {
    const store = new OperationStore(freshDir());
    const ledger = fakeLedger(() => Promise.resolve(null));
    await expect(reconcileEntry(store, ledger, LOCAL_PROGRAM_ID, "missing")).rejects.toThrow(/no reservation/);
  });
});
