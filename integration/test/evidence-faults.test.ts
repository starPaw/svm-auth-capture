import { describe, expect, it, vi } from "vitest";
import type { Transaction } from "@solana/kit";
import { FaultyLedger } from "../operators/fault-injection.ts";
import type { Ledger, SubmitResult } from "../src/ledger.ts";

const tx = {} as Transaction;
function adapter(result: SubmitResult) {
  const submit = vi.fn(async () => result);
  const real = { network: "test", submit } as unknown as Ledger;
  return { faulty: new FaultyLedger(real), submit };
}

describe("Devnet controlled fault evidence", () => {
  it.each([
    { kind: "submitted" },
    { kind: "submitted", outcome: { status: "failed", commitment: "finalized", error: "failed" } },
    { kind: "submitted", outcome: { status: "succeeded", commitment: "confirmed" } },
    { kind: "not-submitted", reason: "blocked before broadcast" },
  ])("never turns an unproved natural result into injected confirmed success: %j", async (result) => {
    const { faulty, submit } = adapter(result as SubmitResult);
    faulty.arm("weak");
    await expect(faulty.submit(tx)).rejects.toThrow("requires a real finalized success");
    // A facilitator may catch the adapter error. The driver must still refuse to continue.
    expect(() => faulty.requireFinalizedOriginal()).toThrow("requires a real finalized success");
    expect(submit).toHaveBeenCalledTimes(1);
  });

  it.each(["lost", "weak"] as const)("downgrades only a proved finalized success for %s", async (fault) => {
    const { faulty, submit } = adapter({ kind: "submitted", outcome: { status: "succeeded", commitment: "finalized" } });
    faulty.arm(fault);
    const result = await faulty.submit(tx);
    expect(() => faulty.requireFinalizedOriginal()).not.toThrow();
    expect(result).toEqual(fault === "lost" ? { kind: "submitted" } : { kind: "submitted", outcome: { status: "succeeded", commitment: "confirmed" } });
    expect(submit).toHaveBeenCalledTimes(1);
  });
});
