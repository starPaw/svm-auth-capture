// Demo client (SAC-006 gap #2): drives `GET /resource` over the x402 v2 HTTP transport
// (`http-transport.ts`). It reads the `PAYMENT-REQUIRED` header of the 402, and before signing
// anything binds the challenge to what this client independently trusts (ARCHITECTURE: "The
// client/verifier pins the allowed program ID for the network and checks the RPC genesis
// identity"): the accepted SAC-007 deployment record's network and program, the RPC's genesis,
// and the merchant, mint, and spend ceiling this payer consents to. Only then does it sign the
// authorize transaction and retry with a `PAYMENT-SIGNATURE` `PaymentPayload`, and decode the
// `PAYMENT-RESPONSE` header.
import { LIFETIME_EXTENSION, transactionObservation } from "./lifetime-provenance.ts";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { type Address, createKeyPairSignerFromBytes, isAddress, type KeyPairSigner, type Transaction } from "@solana/kit";
import { loadDeploymentRecord } from "./deployment-record.ts";
import {
  decodeHeader,
  encodeHeader,
  PAYMENT_REQUIRED_HEADER,
  PAYMENT_RESPONSE_HEADER,
  PAYMENT_SIGNATURE_HEADER,
  type PaymentRequired,
  parsePaymentRequired,
} from "./http-transport.ts";
import { RpcLedger } from "./rpc-ledger.ts";
import { authorizeInstruction, authorizePayload, buildTransaction, type Lifetime } from "./transactions.ts";
import { EXTRA_KEYS, isObject, type PaymentPayload, type PaymentRequirements } from "./types.ts";

/** What this payer independently trusts and consents to; nothing here comes from the 402. */
export type ClientPolicy = {
  /** CAIP-2 network and program ID from the accepted deployment record. */
  network: string;
  programId: Address;
  /** The merchant wallet whose capture authority up to the ceiling this payer accepts. */
  payTo: Address;
  asset: Address;
  /** Largest authorized maximum `M` this payer will sign. */
  maxAmount: bigint;
  /**
   * Longest this payer lets a hold stay locked: payer reclaim opens only at `captureDeadline`,
   * so a challenge may not set it further than this from now.
   */
  maxCaptureWindowSeconds: number;
  /** Sponsor the payer expects; when absent any valid address distinct from the payer is accepted. */
  feePayer?: Address;
};


export type SelectedOffer = {
  requirements: PaymentRequirements;
  feePayer: Address;
  maximum: bigint;
  captureDeadline: bigint;
  refundDeadline: bigint;
};

/**
 * Picks the one offer in a 402 this client will sign, or throws. Every bound field must equal
 * the client's own policy; a challenge cannot substitute the network, program, merchant, mint,
 * or a larger ceiling. Deadlines must be ordered and still open on the cluster clock `now`.
 */
export function selectOffer(paymentRequired: PaymentRequired, policy: ClientPolicy, now: bigint): SelectedOffer {
  const offers = paymentRequired.accepts.filter((r) => r.scheme === "auth-capture" && r.network === policy.network);
  if (offers.length === 0) throw new Error(`no auth-capture offer for ${policy.network}`);
  const reasons: string[] = [];
  for (const r of offers) {
    const extra = r.extra;
    const fail = (why: string) => reasons.push(why);
    if (!isObject(extra) || Object.keys(extra).sort().join(",") !== EXTRA_KEYS.join(",")) { fail("unsupported extra fields"); continue; }
    if (extra.paymentFlow !== "escrow") { fail("paymentFlow is not escrow"); continue; }
    if (extra.programId !== policy.programId) { fail(`program ${String(extra.programId)} is not the accepted deployment ${policy.programId}`); continue; }
    if (r.payTo !== policy.payTo) { fail(`payTo ${r.payTo} is not the trusted merchant`); continue; }
    if (r.asset !== policy.asset) { fail(`asset ${r.asset} is not the trusted mint`); continue; }
    if (typeof extra.feePayer !== "string" || !isAddress(extra.feePayer)) { fail("feePayer is not an address"); continue; }
    if (policy.feePayer !== undefined && extra.feePayer !== policy.feePayer) { fail("feePayer is not the expected sponsor"); continue; }
    if (typeof r.amount !== "string" || !/^[1-9][0-9]*$/.test(r.amount)) { fail("amount is not a positive integer"); continue; }
    const maximum = BigInt(r.amount);
    if (maximum > policy.maxAmount) { fail(`amount ${maximum} exceeds this payer's ceiling ${policy.maxAmount}`); continue; }
    if (!Number.isSafeInteger(extra.captureDeadline) || !Number.isSafeInteger(extra.refundDeadline)) { fail("deadlines are not integers"); continue; }
    const captureDeadline = BigInt(extra.captureDeadline as number);
    const refundDeadline = BigInt(extra.refundDeadline as number);
    if (!(now < captureDeadline && captureDeadline <= refundDeadline)) { fail("deadlines are not open and ordered"); continue; }
    if (captureDeadline - now > BigInt(policy.maxCaptureWindowSeconds)) { fail(`captureDeadline locks the hold longer than ${policy.maxCaptureWindowSeconds}s`); continue; }
    return { requirements: r, feePayer: extra.feePayer, maximum, captureDeadline, refundDeadline };
  }
  throw new Error(`no acceptable offer: ${reasons.join("; ")}`);
}

/** The x402 v2 `PaymentPayload` a client sends in `PAYMENT-SIGNATURE` for an authorize. */
export function authorizePaymentPayload(paymentRequired: PaymentRequired, accepted: PaymentRequirements, tx: Transaction): PaymentPayload {
  const observation = transactionObservation(tx);
  return { x402Version: 2, resource: paymentRequired.resource, accepted, payload: authorizePayload(tx),
    ...(observation ? { extensions: { [LIFETIME_EXTENSION]: { observation } } } : {}) };
}

/** Signs the authorize for a selected offer: the payer is the only economic signer. */
export async function signAuthorize(payer: KeyPairSigner, offer: SelectedOffer, policy: ClientPolicy, salt: Uint8Array, lifetime: Lifetime): Promise<Transaction> {
  if (offer.feePayer === payer.address) throw new Error("the sponsor cannot be the payer");
  const ix = await authorizeInstruction({
    programId: policy.programId,
    payer: payer.address,
    server: policy.payTo,
    mint: policy.asset,
    funder: offer.feePayer,
    salt,
    maximum: offer.maximum,
    captureDeadline: offer.captureDeadline,
    refundDeadline: offer.refundDeadline,
  });
  return buildTransaction({ feePayer: offer.feePayer, instructions: [ix], signers: [payer], lifetime });
}

export type PaidResponse = { status: number; body: unknown; paymentResponse?: unknown; offer: SelectedOffer };

/**
 * One paid request: fetch the 402, decode `PAYMENT-REQUIRED`, select an offer under `policy`
 * (throwing, before anything is signed, if none is acceptable), sign the authorize, and retry
 * with `PAYMENT-SIGNATURE`. `now` and `latestBlockhash` must come from an RPC whose genesis the
 * caller has already verified against the accepted deployment record.
 */
export async function payForResource(o: {
  resourceUrl: string;
  policy: ClientPolicy;
  payer: KeyPairSigner;
  now: () => Promise<bigint>;
  latestBlockhash: () => Promise<Lifetime>;
  salt?: Uint8Array;
  fetchImpl?: typeof fetch;
  /**
   * Bound on each HTTP request, body included. The paid request spans two facilitator settles
   * (each bounded by the resource server at 180s by default), a blockhash read, and the handler,
   * so the default is 450s. On expiry this throws; the payment may still complete, and the
   * resource server's journal and `PAYMENT-RESPONSE` on a retry are not available to the client.
   */
  requestTimeoutMs?: number;
}): Promise<PaidResponse> {
  const fetchImpl = o.fetchImpl ?? fetch;
  const timeoutMs = o.requestTimeoutMs ?? 450_000;
  const challenge = await fetchImpl(o.resourceUrl, { signal: AbortSignal.timeout(timeoutMs) });
  if (challenge.status !== 402) throw new Error(`expected 402 Payment Required, got ${challenge.status}`);
  const header = challenge.headers.get(PAYMENT_REQUIRED_HEADER);
  if (!header) throw new Error(`402 carried no ${PAYMENT_REQUIRED_HEADER} header`);
  const paymentRequired = parsePaymentRequired(decodeHeader(header));
  const offer = selectOffer(paymentRequired, o.policy, await o.now());

  const tx = await signAuthorize(o.payer, offer, o.policy, o.salt ?? new Uint8Array(randomBytes(32)), await o.latestBlockhash());
  const res = await fetchImpl(o.resourceUrl, {
    headers: { [PAYMENT_SIGNATURE_HEADER]: encodeHeader(authorizePaymentPayload(paymentRequired, offer.requirements, tx)) },
    signal: AbortSignal.timeout(timeoutMs),
  });
  const responseHeader = res.headers.get(PAYMENT_RESPONSE_HEADER);
  return { status: res.status, body: await res.json(), ...(responseHeader ? { paymentResponse: decodeHeader(responseHeader) } : {}), offer };
}

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`missing required environment variable ${name}`);
  return value;
}

async function loadKeypair(path: string): Promise<KeyPairSigner> {
  const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (!Array.isArray(parsed) || parsed.length !== 64) throw new Error(`${path} must be a solana-keygen 64-byte secret key JSON array`);
  return createKeyPairSignerFromBytes(new Uint8Array(parsed as number[]));
}

async function main(): Promise<void> {
  const record = loadDeploymentRecord(requireEnv("SAC006_DEPLOYMENT_RECORD_PATH"));
  const policy: ClientPolicy = {
    network: record.network.caip2,
    programId: record.programId,
    payTo: requireEnv("SAC006_CLIENT_TRUSTED_MERCHANT") as Address,
    asset: requireEnv("SAC006_CLIENT_TRUSTED_MINT") as Address,
    maxAmount: BigInt(requireEnv("SAC006_CLIENT_MAX_AMOUNT")),
    maxCaptureWindowSeconds: Number(process.env.SAC006_CLIENT_MAX_CAPTURE_WINDOW_SECONDS ?? "600"),
    ...(process.env.SAC006_CLIENT_EXPECTED_FEE_PAYER ? { feePayer: process.env.SAC006_CLIENT_EXPECTED_FEE_PAYER as Address } : {}),
  };
  // The RPC this client reads the clock and blockhash from must be the record's cluster.
  const ledger = new RpcLedger({ deployment: record, network: record.network.caip2, genesisHash: record.network.genesisHash, rpcUrl: requireEnv("SOLANA_RPC_URL") });
  await ledger.verifyGenesis();

  const result = await payForResource({
    resourceUrl: `${requireEnv("SAC006_RESOURCE_URL")}/resource`,
    policy,
    payer: await loadKeypair(requireEnv("SAC006_PAYER_KEYPAIR_PATH")),
    now: () => ledger.now(),
    latestBlockhash: () => ledger.latestBlockhash(),
  });
  console.log("accepted offer:", JSON.stringify(result.offer.requirements));
  console.log(`status=${result.status}`);
  console.log(JSON.stringify(result.body, null, 2));
  if (result.paymentResponse) console.log(`${PAYMENT_RESPONSE_HEADER}:`, JSON.stringify(result.paymentResponse, null, 2));
}

if (process.argv[1]?.endsWith("client.ts")) {
  main().catch((error) => {
    console.error(error instanceof Error ? (error.stack ?? error.message) : String(error));
    process.exitCode = 1;
  });
}
