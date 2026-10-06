// Integration test for the SAC-006 gap #2/#3 escrow flow: `createGatewayApp` (bearer auth +
// merchant/mint allowlist + sponsorship cap) in front of the LiteSVM-backed `Facilitator`, and
// `createResourceApp` driving the real `402 -> PAYMENT-SIGNATURE -> settle(authorize) -> handler
// -> settle(capture|void) -> PAYMENT-RESPONSE` flow against it over real HTTP. Exercises: a full
// authorize->handler-success->capture flow; a handler failure taking the void path; replay
// rejection (the handler runs at most once per fingerprint); unauthenticated/non-allowlisted
// requests never reaching the facilitator; and the sponsorship cap denying an over-budget
// request before it reaches `Facilitator.settle`.
import type { AddressInfo } from "node:net";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { serve, type ServerType } from "@hono/node-server";
import type { Address, KeyPairSigner } from "@solana/kit";
import { Hono } from "hono";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { createGatewayApp } from "../src/gateway.js";
import { OperationStore } from "../src/operation-store.js";
import { SponsorshipGuard } from "../src/sponsorship.js";
import { authorizeInstruction, authorizePayload, buildTransaction, type Lifetime } from "../src/transactions.js";
import { createResourceApp, decodeHeaderPayload, encodeHeaderPayload, type HandlerResult } from "../src/resource-server.js";
import type { PaymentRequirements } from "../src/types.js";
import { createHarness, type Harness } from "./fixture.js";

async function startServer(app: Hono): Promise<{ url: string; close: () => Promise<void> }> {
  const s: ServerType = await new Promise((resolve) => {
    const srv = serve({ fetch: app.fetch, port: 0, hostname: "127.0.0.1" }, () => resolve(srv));
  });
  const url = `http://127.0.0.1:${(s.address() as AddressInfo).port}`;
  return { url, close: () => new Promise<void>((resolve) => s.close(() => resolve())) };
}

let h: Harness;
let gateway: { url: string; close: () => Promise<void> };
let resource: { url: string; close: () => Promise<void> };
let store: OperationStore;
let handlerCalls = 0;
let handlerImpl: (ctx: { payer: Address; payment: Address }) => Promise<HandlerResult>;
const BEARER_TOKEN = "test-bearer-token";

beforeAll(async () => {
  h = await createHarness();
  const sponsorship = new SponsorshipGuard({
    ledger: h.ledger,
    feePayer: h.facilitatorKey.address,
    maxAttempts: 1000,
    minLamportsBalance: 1n,
  });
  const gatewayApp = createGatewayApp(h.facilitator, {
    bearerToken: BEARER_TOKEN,
    sponsorship,
    allowlist: { merchant: h.server.address, mint: h.mint },
  });
  gateway = await startServer(gatewayApp);

  store = new OperationStore(mkdtempSync(join(tmpdir(), "sac006-resource-flow-")));
  handlerImpl = async () => ({ ok: true, amount: 100n, releaseRemainder: true });
  const resourceApp = createResourceApp({
    facilitatorUrl: gateway.url,
    bearerToken: BEARER_TOKEN,
    network: h.ledger.network,
    programId: h.facilitator.programId,
    feePayer: h.facilitatorKey.address,
    server: h.server,
    asset: h.mint,
    amount: 100n,
    captureDeadlineSeconds: 120,
    refundDeadlineSeconds: 600,
    store,
    getLatestBlockhash: async () => h.lifetime(),
    now: () => h.svm.getClock().unixTimestamp,
    handler: async (ctx) => {
      handlerCalls += 1;
      return handlerImpl(ctx);
    },
  });
  resource = await startServer(resourceApp);
});

afterAll(async () => {
  await resource.close();
  await gateway.close();
  await h.close();
});

/** Fetches the 402 challenge and signs an authorize transaction against its own terms. */
async function clientAuthorize(payer: KeyPairSigner, salt: Uint8Array): Promise<{ tx: Awaited<ReturnType<typeof buildTransaction>>; requirements: PaymentRequirements }> {
  const challenge = await fetch(`${resource.url}/resource`);
  expect(challenge.status).toBe(402);
  const { accepts } = (await challenge.json()) as { accepts: PaymentRequirements[] };
  const requirements = accepts[0]!;
  expect(requirements.scheme).toBe("auth-capture");
  expect(requirements.extra?.paymentFlow).toBe("escrow");
  const extra = requirements.extra as { programId: Address; feePayer: Address; captureDeadline: number; refundDeadline: number };
  const ix = await authorizeInstruction({
    programId: extra.programId,
    payer: payer.address,
    server: requirements.payTo as Address,
    mint: requirements.asset as Address,
    funder: extra.feePayer,
    salt,
    maximum: BigInt(requirements.amount),
    captureDeadline: BigInt(extra.captureDeadline),
    refundDeadline: BigInt(extra.refundDeadline),
  });
  const lifetime: Lifetime = h.lifetime();
  const tx = await buildTransaction({ feePayer: extra.feePayer, instructions: [ix], signers: [payer], lifetime });
  return { tx, requirements };
}

async function requestResource(tx: Awaited<ReturnType<typeof buildTransaction>>) {
  return fetch(`${resource.url}/resource`, { headers: { "payment-signature": encodeHeaderPayload(authorizePayload(tx)) } });
}

describe("resource flow: authorize -> handler success -> capture", () => {
  test("completes end to end and settles the full amount to the server", async () => {
    const payerBefore = h.tokens(await h.payerAta());
    const serverBefore = h.tokens(await h.serverAta());
    const calledBefore = handlerCalls;
    handlerImpl = async () => ({ ok: true, amount: 100n, releaseRemainder: true });

    const salt = h.newSalt();
    const { tx } = await clientAuthorize(h.payer, salt);
    const res = await requestResource(tx);

    expect(res.status).toBe(200);
    expect(handlerCalls).toBe(calledBefore + 1);
    const body = (await res.json()) as { ok: boolean; payment: string; settlement: { success: boolean } };
    expect(body.ok).toBe(true);
    expect(body.settlement.success).toBe(true);

    const responseHeader = res.headers.get("payment-response");
    expect(responseHeader).toBeTruthy();
    const decoded = decodeHeaderPayload<{ success: boolean }>(responseHeader!);
    expect(decoded.success).toBe(true);

    expect(h.tokens(await h.serverAta())).toBe(serverBefore + 100n);
    expect(h.tokens(await h.payerAta())).toBe(payerBefore - 100n);

    const persisted = store.list().find((r) => r.authorize?.payment === body.payment);
    expect(persisted?.status).toBe("completed");
  });
});

describe("resource flow: handler failure -> void", () => {
  test("voids the hold and returns the full amount to the payer, reporting a failure", async () => {
    const payerBefore = h.tokens(await h.payerAta());
    const serverBefore = h.tokens(await h.serverAta());
    const calledBefore = handlerCalls;
    handlerImpl = async () => ({ ok: false, detail: "protected work failed" });

    const salt = h.newSalt();
    const { tx } = await clientAuthorize(h.payer, salt);
    const res = await requestResource(tx);

    expect(res.status).toBe(500);
    expect(handlerCalls).toBe(calledBefore + 1);
    const body = (await res.json()) as { error: string; detail: string };
    expect(body.detail).toBe("protected work failed");

    const responseHeader = res.headers.get("payment-response");
    expect(responseHeader).toBeTruthy(); // the void still settles and is reported.

    // The hold is fully released back to the payer; the server receives nothing.
    expect(h.tokens(await h.payerAta())).toBe(payerBefore);
    expect(h.tokens(await h.serverAta())).toBe(serverBefore);
  });
});

describe("resource flow: replay rejection", () => {
  test("a duplicate request with the same signed authorize is rejected and the handler runs at most once", async () => {
    handlerImpl = async () => ({ ok: true, amount: 100n, releaseRemainder: true });
    const calledBefore = handlerCalls;

    const salt = h.newSalt();
    const { tx } = await clientAuthorize(h.payer, salt);
    const first = await requestResource(tx);
    expect(first.status).toBe(200);
    expect(handlerCalls).toBe(calledBefore + 1);

    const second = await requestResource(tx);
    expect(second.status).toBe(409);
    expect(handlerCalls).toBe(calledBefore + 1); // no second execution
  });
});

describe("gateway: authentication and allowlist precede the facilitator", () => {
  test("a request with no bearer token is rejected before reaching the facilitator", async () => {
    const before = h.ledger.submissions.length;
    const res = await fetch(`${gateway.url}/settle`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(h.body(authorizePayload(await h.signedAuthorize({ salt: h.newSalt() })))),
    });
    expect(res.status).toBe(401);
    expect(h.ledger.submissions.length).toBe(before);
  });

  test("a request with the wrong bearer token is rejected before reaching the facilitator", async () => {
    const before = h.ledger.submissions.length;
    const res = await fetch(`${gateway.url}/settle`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer wrong-token" },
      body: JSON.stringify(h.body(authorizePayload(await h.signedAuthorize({ salt: h.newSalt() })))),
    });
    expect(res.status).toBe(401);
    expect(h.ledger.submissions.length).toBe(before);
  });

  test("a non-allowlisted merchant is rejected before reaching the facilitator", async () => {
    const before = h.ledger.submissions.length;
    const req = h.requirements({ payTo: h.outsider.address });
    const res = await fetch(`${gateway.url}/settle`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${BEARER_TOKEN}` },
      body: JSON.stringify(h.body(authorizePayload(await h.signedAuthorize({ salt: h.newSalt(), server: h.outsider.address })), req)),
    });
    expect(res.status).toBe(403);
    expect(h.ledger.submissions.length).toBe(before);
  });

  test("/supported stays public and reachable with no bearer token", async () => {
    const res = await fetch(`${gateway.url}/supported`);
    expect(res.status).toBe(200);
  });
});

describe("gateway: sponsorship cap", () => {
  test("denies a settle attempt once the attempt cap is reached, before reaching the facilitator", async () => {
    const cappedGuard = new SponsorshipGuard({ ledger: h.ledger, feePayer: h.facilitatorKey.address, maxAttempts: 0, minLamportsBalance: 1n });
    const cappedApp = createGatewayApp(h.facilitator, {
      bearerToken: BEARER_TOKEN,
      sponsorship: cappedGuard,
      allowlist: { merchant: h.server.address, mint: h.mint },
    });
    const capped = await startServer(cappedApp);
    try {
      const before = h.ledger.submissions.length;
      const res = await fetch(`${capped.url}/settle`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${BEARER_TOKEN}` },
        body: JSON.stringify(h.body(authorizePayload(await h.signedAuthorize({ salt: h.newSalt() })))),
      });
      expect(res.status).toBe(429);
      expect(h.ledger.submissions.length).toBe(before);
    } finally {
      await capped.close();
    }
  });
});
