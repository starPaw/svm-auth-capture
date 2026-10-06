// Unit tests for the demo client's challenge binding (SAC-006; ARCHITECTURE: the client pins
// the program ID for the network and never accepts one supplied by an arbitrary 402). A 402
// that substitutes the network, program, merchant, mint, or a larger ceiling must make the
// client refuse before it signs anything — no network access, nothing signed.
import { type Address, generateKeyPairSigner } from "@solana/kit";
import { describe, expect, test, vi } from "vitest";
import { type ClientPolicy, payForResource, selectOffer } from "../src/client.js";
import { encodeHeader, PAYMENT_REQUIRED_HEADER, type PaymentRequired } from "../src/http-transport.js";
import type { PaymentRequirements } from "../src/types.js";

const NETWORK = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
const PROGRAM = "992QmwmwCebawRJsTCgvc8qnzGivbFaD39ZQE7VhHp7o" as Address;
const MERCHANT = "2aRqXzYGovLXvx9xogqLm3if9JMEryTXHT6QBd4UUT7w" as Address;
const MINT = "3qiQ5BMY7xLwDVkP42fdXyhCG8fVDucxyC1T9NDUKG9q" as Address;
const SPONSOR = "BV2EDv7gCR8X7mWTYtCCguqrj2HdCjx8AFww8Q1MJYtY" as Address;
const ATTACKER = "4bhbRAJi2PNGVFc5f49nVeaQeM7k7syqpNZZpPtdDTf9" as Address;
const NOW = 1_000n;

const policy: ClientPolicy = { network: NETWORK, programId: PROGRAM, payTo: MERCHANT, asset: MINT, maxAmount: 100n, maxCaptureWindowSeconds: 300 };

function offer(over: Partial<PaymentRequirements> = {}, extra: Record<string, unknown> = {}): PaymentRequirements {
  return {
    scheme: "auth-capture",
    network: NETWORK,
    amount: "100",
    asset: MINT,
    payTo: MERCHANT,
    maxTimeoutSeconds: 60,
    ...over,
    extra: { paymentFlow: "escrow", captureDeadline: 1_120, refundDeadline: 1_720, programId: PROGRAM, feePayer: SPONSOR, ...extra },
  };
}

const required = (...accepts: PaymentRequirements[]): PaymentRequired => ({ x402Version: 2, resource: { url: "http://127.0.0.1/resource" }, accepts });

describe("selectOffer", () => {
  test("accepts an offer bound to the accepted deployment, merchant, mint, and ceiling", () => {
    const selected = selectOffer(required(offer()), policy, NOW);
    expect(selected).toMatchObject({ feePayer: SPONSOR, maximum: 100n, captureDeadline: 1_120n, refundDeadline: 1_720n });
  });

  test.each([
    ["a substituted program", offer({}, { programId: ATTACKER }), /not the accepted deployment/],
    ["another network", offer({ network: "solana:wrongnetwork" }), /no auth-capture offer/],
    ["another merchant", offer({ payTo: ATTACKER }), /not the trusted merchant/],
    ["another mint", offer({ asset: ATTACKER }), /not the trusted mint/],
    ["a larger ceiling", offer({ amount: "101" }), /exceeds this payer's ceiling/],
    ["a non-escrow flow", offer({}, { paymentFlow: "direct" }), /not escrow/],
    ["an unsupported extra field", offer({}, { feeBps: 5 }), /unsupported extra/],
    ["an expired capture deadline", offer({}, { captureDeadline: 1_000 }), /not open and ordered/],
    ["misordered deadlines", offer({}, { captureDeadline: 1_800, refundDeadline: 1_700 }), /not open and ordered/],
    ["a hold locked beyond the payer's window", offer({}, { captureDeadline: 1_301, refundDeadline: 1_901 }), /locks the hold longer than 300s/],
  ])("refuses %s", (_label, bad, reason) => {
    expect(() => selectOffer(required(bad), policy, NOW)).toThrow(reason);
  });

  test("refuses an unexpected sponsor when the payer pins one", () => {
    expect(() => selectOffer(required(offer({}, { feePayer: ATTACKER })), { ...policy, feePayer: SPONSOR }, NOW)).toThrow(/expected sponsor/);
  });

  test("skips a substituted offer and selects the bound one listed after it", () => {
    const selected = selectOffer(required(offer({}, { programId: ATTACKER }), offer()), policy, NOW);
    expect(selected.requirements.extra?.programId).toBe(PROGRAM);
  });
});

describe("payForResource", () => {
  test("a wrong-network challenge with a substituted program is refused before any signature or retry", async () => {
    const payer = await generateKeyPairSigner();
    const calls: RequestInit[] = [];
    const fetchImpl: typeof fetch = async (_url, init) => {
      calls.push(init ?? {});
      const challenge = required(offer({ network: "solana:wrongnetwork" }, { programId: ATTACKER }));
      return new Response(JSON.stringify(challenge), { status: 402, headers: { [PAYMENT_REQUIRED_HEADER]: encodeHeader(challenge) } });
    };
    const latestBlockhash = vi.fn();
    await expect(
      payForResource({ resourceUrl: "http://127.0.0.1/resource", policy, payer, now: async () => NOW, latestBlockhash, fetchImpl }),
    ).rejects.toThrow(/no auth-capture offer/);
    expect(calls).toHaveLength(1); // only the challenge; no PAYMENT-SIGNATURE retry
    expect(latestBlockhash).not.toHaveBeenCalled(); // never reached transaction building or signing
  });

  test("a 402 without the PAYMENT-REQUIRED header is refused", async () => {
    const payer = await generateKeyPairSigner();
    const fetchImpl: typeof fetch = async () => new Response(JSON.stringify(required(offer())), { status: 402 });
    await expect(
      payForResource({ resourceUrl: "http://127.0.0.1/resource", policy, payer, now: async () => NOW, latestBlockhash: vi.fn(), fetchImpl }),
    ).rejects.toThrow(/no PAYMENT-REQUIRED header/);
  });
});
