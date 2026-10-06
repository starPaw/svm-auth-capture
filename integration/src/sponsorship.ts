// Bounds the facilitator sponsor's exposure (SAC-006 gap #3). A small test-SOL balance alone is
// not a cap: a trusted-but-compromised caller could still exhaust it one request at a time with
// no limit on how many attempts it gets. This guard enforces two independent bounds in front of
// `/settle`, the only route that ever submits a sponsor-signed transaction:
//
//  - a hard cap on the number of settle attempts this process will authorize, so a runaway
//    caller cannot loop indefinitely even within the sponsor's balance;
//  - a floor on the sponsor's live lamport balance, read fresh from the ledger before every
//    attempt, so the guard never authorizes an attempt once the sponsor is close to unable to
//    pay for it.
//
// Both bounds are process-local and not durable (the same limitation as the facilitator's
// in-process duplicate guard; ARCHITECTURE, "Relay, recovery, and separation from application
// state"). A denied request is rejected here, before it reaches `Facilitator.settle`, so it
// never reaches sponsor signing or submission.
import type { Address } from "@solana/kit";
import type { MiddlewareHandler } from "hono";
import type { Ledger } from "./ledger.js";

export type SponsorshipGuardConfig = {
  ledger: Ledger;
  feePayer: Address;
  /** Hard cap on the number of settle attempts this process will authorize. */
  maxAttempts: number;
  /** Minimum sponsor lamport balance required before authorizing another attempt. */
  minLamportsBalance: bigint;
};

export class SponsorshipGuard {
  private attempts = 0;

  constructor(private readonly config: SponsorshipGuardConfig) {}

  get attemptCount(): number {
    return this.attempts;
  }

  /** Returns a rejection reason, or `undefined` if another settle attempt is authorized. */
  async check(): Promise<string | undefined> {
    if (this.attempts >= this.config.maxAttempts) {
      return `sponsorship attempt cap reached (${this.config.maxAttempts})`;
    }
    const account = await this.config.ledger.getAccount(this.config.feePayer);
    const balance = account?.lamports ?? 0n;
    if (balance < this.config.minLamportsBalance) {
      return `sponsor balance ${balance} is below the configured floor ${this.config.minLamportsBalance}`;
    }
    this.attempts += 1;
    return undefined;
  }
}

/** Hono middleware form of `SponsorshipGuard.check`, for mounting in front of `/settle`. */
export function requireSponsorshipBudget(guard: SponsorshipGuard): MiddlewareHandler {
  return async (c, next) => {
    const denied = await guard.check();
    if (denied) return c.json({ error: "sponsorship budget exhausted", detail: denied }, 429);
    await next();
  };
}
