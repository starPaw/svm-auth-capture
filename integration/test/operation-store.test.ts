// Unit tests for `OperationStore` (SAC-006 gap #3) — no network access. Exercises atomic
// reservation/conflict, update/read round-tripping, and `unresolved()` listing every status a
// crash or lost response can leave behind.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "vitest";
import { fingerprint, type OperationStatus, OperationStore, ReservationConflict } from "../src/operation-store.js";

function freshDir(): string {
  return mkdtempSync(join(tmpdir(), "sac006-store-"));
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

describe("OperationStore.list / unresolved", () => {
  test("unresolved() lists every status except settled ones, including crash-interrupted intermediates", () => {
    const store = new OperationStore(freshDir());
    const statuses: OperationStatus[] = [
      "reserved",
      "authorizing",
      "authorize-rejected",
      "authorize-pending",
      "authorized",
      "handler-started",
      "handler-succeeded",
      "handler-failed",
      "terminal-settling",
      "terminal-pending",
      "terminal-rejected",
      "completed",
    ];
    for (const status of statuses) {
      store.reserve(`fp-${status}`, "payer", "/resource");
      store.update(`fp-${status}`, { status });
    }
    expect(store.list()).toHaveLength(statuses.length);
    const unresolved = store.unresolved().map((r) => r.status).sort();
    expect(unresolved).toEqual(statuses.filter((s) => s !== "completed" && s !== "authorize-rejected").sort());
  });
});
