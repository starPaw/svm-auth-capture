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
