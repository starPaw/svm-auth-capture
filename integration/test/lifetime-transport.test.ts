import { mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { createHarness, type Harness } from "./fixture.ts";
import { attestObservation, LIFETIME_EXTENSION, relayProvenance, retainObservation, transactionObservation } from "../src/lifetime-provenance.ts";
import { authorizePaymentPayload } from "../src/client.ts";
import { settle, type ResourceServerConfig } from "../src/resource-server.ts";
import type { PaymentPayload } from "../src/types.ts";
import { OperationStore } from "../src/operation-store.ts";
import { getBase64Encoder, getTransactionDecoder, getBase64EncodedWireTransaction } from "@solana/kit";
const KEY = "synthetic-existing-server-bearer";
const GENESIS = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
const NETWORK = `solana:${GENESIS.slice(0, 32)}`;
let h: Harness;
beforeEach(async () => { h = await createHarness(); });
afterEach(async () => { await h.close(); });
function config(fetchImpl: typeof fetch): ResourceServerConfig {
  return { facilitatorUrl: "http://synthetic.invalid", bearerToken: KEY, network: NETWORK,
    programId: h.facilitator.programId, feePayer: h.facilitatorKey.address, server: h.server, asset: h.mint, amount: 100n,
    captureDeadlineSeconds: 100, refundDeadlineSeconds: 200, store: new OperationStore(mkdtempSync(join(tmpdir(), "relay-transport-"))),
    getLatestBlockhash: vi.fn(), now: () => h.ledger.now(), handler: vi.fn(), fetchImpl };
}
const retained = (tx: Parameters<typeof retainObservation>[0]) => {
  retainObservation(tx, { ...h.lifetime(), contextSlot: 9007199254740993n, network: NETWORK, genesisHash: GENESIS, commitment: "finalized" });
  return transactionObservation(tx)!;
};

test.each(["client", "forged-mac", "changed-message", "null", "scalar"])("%s extension forwards as request evidence only", async kind => {
  const original = await h.signedAuthorize({ salt: h.newSalt() }); const value = retained(original);
  const wire = getBase64EncodedWireTransaction(original);
  const payload = authorizePaymentPayload({ x402Version: 2, resource: { url: "http://resource.test/resource" }, accepts: [h.requirements()] }, h.requirements(), original);
  expect(payload.extensions?.[LIFETIME_EXTENSION]).toEqual({ observation: value });
  if (kind === "forged-mac") payload.extensions![LIFETIME_EXTENSION] = { ...attestObservation(value, KEY), source: "first-party" };
  if (kind === "changed-message") payload.extensions![LIFETIME_EXTENSION] = { observation: { ...value, messageHash: "a".repeat(64) } };
  if (kind === "null") payload.extensions![LIFETIME_EXTENSION] = null;
  if (kind === "scalar") payload.extensions![LIFETIME_EXTENSION] = "forged";
  const decoded = getTransactionDecoder().decode(getBase64Encoder().encode(wire));
  let sent: any;
  const fetchImpl = vi.fn(async (_url, init) => { sent = JSON.parse(init!.body as string);
    return Response.json({ success: false, errorReason: "settlement_pending", transaction: "synthetic", network: NETWORK }); }) as typeof fetch;
  const c = config(fetchImpl);
  const result = await settle(c, { x402Version: 2, paymentPayload: payload, paymentRequirements: payload.accepted }, decoded, h.payer.address);
  expect(result.kind).toBe("unresolved"); expect(fetchImpl).toHaveBeenCalledTimes(1);
  expect(sent.paymentPayload.payload.transaction).toBe(wire); expect(sent.lifetimeObservation.attestation).toBeUndefined();
  const proof = await relayProvenance(decoded, sent.lifetimeObservation, NETWORK, undefined, KEY);
  if (["client", "forged-mac"].includes(kind)) expect(proof.observation).toMatchObject({ state: "recorded", source: "request", value });
  else expect(proof.observation.state).toBe("unavailable");
  expect(c.getLatestBlockhash).not.toHaveBeenCalled();
});

test("server observation wins over a client extension and survives JSON transport unchanged", async () => {
  const tx = await h.signedAuthorize({ salt: h.newSalt() }); const value = retained(tx);
  const request = h.body({ transaction: getBase64EncodedWireTransaction(tx) });
  (request.paymentPayload as PaymentPayload).extensions = { [LIFETIME_EXTENSION]: { observation: { ...value, lastValidBlockHeight: "1" } } };
  let sent: any;
  const fetchImpl = vi.fn(async (_url, init) => { sent = JSON.parse(init!.body as string);
    return Response.json({ success: false, errorReason: "settlement_pending", transaction: "synthetic", network: NETWORK }); }) as typeof fetch;
  await settle(config(fetchImpl), request, tx, h.payer.address);
  expect(sent.lifetimeObservation).toEqual(attestObservation(value, KEY));
  const proof = await relayProvenance(tx, sent.lifetimeObservation, NETWORK, undefined, KEY);
  expect(proof.observation).toEqual({ state: "recorded", source: "first-party", value });
});
