// Unit tests for `SponsorshipGuard`/`requireSponsorshipBudget` (SAC-006 gap #3) against a fake
// `Ledger` — no network access.
import type { Address } from "@solana/kit";
import { Hono } from "hono";
import { describe, expect, test } from "vitest";
import type { Ledger, SimulationOutcome, SubmitResult } from "../src/ledger.js";
import { requireSponsorshipBudget, SponsorshipGuard } from "../src/sponsorship.js";

const FEE_PAYER = "11111111111111111111111111111112" as Address;

function fakeLedger(balance: bigint): Ledger {
  return {
    network: "solana:fake",
    now: () => Promise.resolve(0n),
    getAccount: () => Promise.resolve({ owner: FEE_PAYER, data: new Uint8Array(0), lamports: balance, executable: false }),
    simulate: (): Promise<SimulationOutcome> => Promise.resolve({ ok: true }),
    submit: (): Promise<SubmitResult> => Promise.resolve({ kind: "submitted" }),
  };
}

describe("SponsorshipGuard.check", () => {
  test.each([NaN, Infinity, -1, 1.5, Number.MAX_SAFE_INTEGER + 1])("rejects an invalid attempt limit: %s", (maxAttempts) => {
    expect(() => new SponsorshipGuard({ ledger: fakeLedger(10n), feePayer: FEE_PAYER, maxAttempts, minLamportsBalance: 1n })).toThrow(/maxAttempts/);
  });

  test("rejects a negative balance floor", () => {
    expect(() => new SponsorshipGuard({ ledger: fakeLedger(10n), feePayer: FEE_PAYER, maxAttempts: 1, minLamportsBalance: -1n })).toThrow(/minLamportsBalance/);
  });
  test("authorizes attempts while under the cap and above the balance floor", async () => {
    const guard = new SponsorshipGuard({ ledger: fakeLedger(10_000n), feePayer: FEE_PAYER, maxAttempts: 2, minLamportsBalance: 1_000n });
    expect(await guard.check()).toBeUndefined();
    expect(guard.attemptCount).toBe(1);
    expect(await guard.check()).toBeUndefined();
    expect(guard.attemptCount).toBe(2);
  });

  test("denies once the attempt cap is reached, without consulting the ledger again", async () => {
    const guard = new SponsorshipGuard({ ledger: fakeLedger(10_000n), feePayer: FEE_PAYER, maxAttempts: 1, minLamportsBalance: 1_000n });
    expect(await guard.check()).toBeUndefined();
    const denied = await guard.check();
    expect(denied).toMatch(/attempt cap reached/);
    expect(guard.attemptCount).toBe(1);
  });

  test("denies when the sponsor balance is below the configured floor", async () => {
    const guard = new SponsorshipGuard({ ledger: fakeLedger(500n), feePayer: FEE_PAYER, maxAttempts: 10, minLamportsBalance: 1_000n });
    const denied = await guard.check();
    expect(denied).toMatch(/below the configured floor/);
    expect(guard.attemptCount).toBe(0);
  });

  test("treats a missing fee-payer account as zero balance", async () => {
    const ledger: Ledger = {
      network: "solana:fake",
      now: () => Promise.resolve(0n),
      getAccount: () => Promise.resolve(null),
      simulate: (): Promise<SimulationOutcome> => Promise.resolve({ ok: true }),
      submit: (): Promise<SubmitResult> => Promise.resolve({ kind: "submitted" }),
    };
    const guard = new SponsorshipGuard({ ledger, feePayer: FEE_PAYER, maxAttempts: 10, minLamportsBalance: 1n });
    expect(await guard.check()).toMatch(/below the configured floor/);
  });
});

describe("SponsorshipGuard.check under concurrency", () => {
  /** A ledger whose balance read yields to the event loop, so concurrent checks interleave. */
  function slowLedger(balance: bigint): Ledger {
    return {
      ...fakeLedger(balance),
      getAccount: () =>
        new Promise((resolve) => setTimeout(() => resolve({ owner: FEE_PAYER, data: new Uint8Array(0), lamports: balance, executable: false }), 5)),
    };
  }

  test("admits at most maxAttempts of many concurrent checks", async () => {
    const guard = new SponsorshipGuard({ ledger: slowLedger(10_000n), feePayer: FEE_PAYER, maxAttempts: 1, minLamportsBalance: 1_000n });
    const results = await Promise.all(Array.from({ length: 20 }, () => guard.check()));
    expect(results.filter((r) => r === undefined)).toHaveLength(1);
    expect(guard.attemptCount).toBe(1);
  });

  test("admits exactly the cap through the HTTP middleware when requests race", async () => {
    const guard = new SponsorshipGuard({ ledger: slowLedger(10_000n), feePayer: FEE_PAYER, maxAttempts: 3, minLamportsBalance: 1_000n });
    const app = new Hono();
    let reached = 0;
    app.use("/settle", requireSponsorshipBudget(guard));
    app.post("/settle", (c) => {
      reached += 1;
      return c.json({ ok: true });
    });
    const statuses = await Promise.all(Array.from({ length: 20 }, async () => (await app.request("/settle", { method: "POST" })).status));
    expect(statuses.filter((s) => s === 200)).toHaveLength(3);
    expect(statuses.filter((s) => s === 429)).toHaveLength(17);
    expect(reached).toBe(3);
  });

  test("releases a slot the balance floor denies, without exceeding the cap", async () => {
    let balance = 500n;
    const ledger: Ledger = {
      ...fakeLedger(0n),
      getAccount: async () => ({ owner: FEE_PAYER, data: new Uint8Array(0), lamports: balance, executable: false }),
    };
    const guard = new SponsorshipGuard({ ledger, feePayer: FEE_PAYER, maxAttempts: 1, minLamportsBalance: 1_000n });
    expect(await guard.check()).toMatch(/below the configured floor/);
    expect(guard.attemptCount).toBe(0);
    balance = 10_000n;
    expect(await guard.check()).toBeUndefined();
    expect(await guard.check()).toMatch(/attempt cap reached/);
  });

  test("denies, and releases the slot, when the balance cannot be read", async () => {
    const ledger: Ledger = { ...fakeLedger(0n), getAccount: () => Promise.reject(new Error("rpc down")) };
    const guard = new SponsorshipGuard({ ledger, feePayer: FEE_PAYER, maxAttempts: 1, minLamportsBalance: 1n });
    expect(await guard.check()).toMatch(/balance unavailable/);
    expect(guard.attemptCount).toBe(0);
  });
});

describe("requireSponsorshipBudget", () => {
  function appWith(guard: SponsorshipGuard): Hono {
    const app = new Hono();
    app.use("/settle", requireSponsorshipBudget(guard));
    app.post("/settle", (c) => c.json({ ok: true }));
    return app;
  }

  test("passes through requests while the guard authorizes them", async () => {
    const guard = new SponsorshipGuard({ ledger: fakeLedger(10_000n), feePayer: FEE_PAYER, maxAttempts: 1, minLamportsBalance: 1_000n });
    const res = await appWith(guard).request("/settle", { method: "POST" });
    expect(res.status).toBe(200);
  });

  test("returns 429 once the guard denies the request", async () => {
    const guard = new SponsorshipGuard({ ledger: fakeLedger(10_000n), feePayer: FEE_PAYER, maxAttempts: 0, minLamportsBalance: 1_000n });
    const res = await appWith(guard).request("/settle", { method: "POST" });
    expect(res.status).toBe(429);
  });
});
