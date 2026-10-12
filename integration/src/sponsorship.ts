// Bounds the facilitator sponsor's exposure (SAC-006 gap #3). A small test-SOL balance alone is
// not a cap: a trusted-but-compromised caller could still exhaust it one request at a time with
// no limit on how many attempts it gets. This guard enforces two independent bounds in front of
// `/settle`, the only route that ever submits a sponsor-signed transaction:
//
//  - a hard cap on the number of settle attempts this process will authorize, so a runaway
//    caller cannot loop indefinitely even within the sponsor's balance;
//  - a floor on the sponsor's live lamport balance, read fresh from the ledger before every
//    attempt, so the guard never authorizes an attempt once the sponsor is close to unable to
//    pay for it. Concurrent admissions read the same balance, so the floor is a stop signal; the
//    attempt cap, reserved atomically, is the hard bound on how many attempts are ever signed.
//
// Both bounds are process-local and not durable (the same limitation as the facilitator's
// in-process duplicate guard; ARCHITECTURE, "Relay, recovery, and separation from application
// state"). A denied request is rejected here, before it reaches `Facilitator.settle`, so it
// never reaches sponsor signing or submission.
import type { Address } from "@solana/kit";
import type { MiddlewareHandler } from "hono";
import type { Ledger } from "./ledger.ts";
import type { AdmissionJournal } from './admission-journal.ts';

export type SponsorshipGuardConfig = {
  ledger: Ledger;
  feePayer: Address;
  /** Hard cap on the number of settle attempts this process will authorize. */
  maxAttempts: number;
  /** Minimum sponsor lamport balance required before authorizing another attempt. */
  minLamportsBalance: bigint;
  admission?: AdmissionJournal;
};

export class SponsorshipGuard {
  private attempts = 0;
  private readonly config: SponsorshipGuardConfig;

  // Plain-field assignment, not a TS constructor parameter property: this file must stay runnable
  // under Node's `--experimental-strip-types`, which does not support parameter properties.
  constructor(config: SponsorshipGuardConfig) {
    if (!Number.isSafeInteger(config.maxAttempts) || config.maxAttempts < 0) throw new Error("maxAttempts must be a nonnegative safe integer");
    if (config.minLamportsBalance < 0n) throw new Error("minLamportsBalance must be nonnegative");
    if (config.admission && config.admission.policy.maximum !== config.maxAttempts) throw Error('sponsorship admission/guard cap mismatch');
    this.config = config;
  }

  get attemptCount(): number {
    return this.config.admission?.summary().used ?? this.attempts;
  }

  /**
   * Returns a rejection reason, or `undefined` if another settle attempt is authorized. The
   * attempt slot is reserved synchronously, before the balance read yields: concurrent requests
   * can never all observe the same count and exceed the cap. A slot is released only when the
   * balance floor denies the attempt, which never reaches the facilitator.
   */
  async check(): Promise<string | undefined> {
    if (this.config.admission) {
      try { this.config.admission.reserve(); }
      catch { return 'durable sponsorship admission unavailable or exhausted'; }
      try {
        const balance = (await this.config.ledger.getAccount(this.config.feePayer))?.lamports ?? 0n;
        return balance < this.config.minLamportsBalance ? 'sponsor balance below configured floor' : undefined;
      } catch { return 'sponsor balance unavailable'; }
    }
    if (this.attempts >= this.config.maxAttempts) {
      return `sponsorship attempt cap reached (${this.config.maxAttempts})`;
    }
    this.attempts += 1;
    let balance: bigint;
    try {
      balance = (await this.config.ledger.getAccount(this.config.feePayer))?.lamports ?? 0n;
    } catch (e) {
      this.attempts -= 1;
      return `sponsor balance unavailable: ${e instanceof Error ? e.message : String(e)}`;
    }
    if (balance < this.config.minLamportsBalance) {
      this.attempts -= 1;
      return `sponsor balance ${balance} is below the configured floor ${this.config.minLamportsBalance}`;
    }
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
