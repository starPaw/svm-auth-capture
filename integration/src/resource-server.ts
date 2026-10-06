// Demo protected resource server (SAC-006 gap #2): the actual `402 / PAYMENT-REQUIRED →
// PAYMENT-SIGNATURE → settle(authorize) → handler → settle(capture|capture+void|void) →
// PAYMENT-RESPONSE` flow, calling a trusted facilitator (`gateway.ts`) over HTTP with the
// bearer token it alone holds. `/verify` is never called here: it is a read-only preflight
// endpoint, not a required step of this ordering (integration/README.md).
//
// Resource-replay binding (SAC-006 gap #3): before the handler ever runs, this server derives
// the caller/resource/payment fingerprint from the client's own signed authorize transaction
// (the payer's signature *is* this demo's caller authentication — there is no separate login)
// and reserves it in the `OperationStore`. A conflicting reuse of the same fingerprint is
// rejected before the handler runs, so a duplicate or replayed request can execute the handler
// at most once. A rejected or unresolved authorize never starts the handler. A handler failure
// takes the intended void path; a failed or unresolved terminal settle never becomes a
// completed-payment response — the client sees the failure, not a resource execution it was not
// actually charged (and granted) for.
import {
  type Address,
  getBase64Encoder,
  getCompiledTransactionMessageDecoder,
  getTransactionDecoder,
  type KeyPairSigner,
  type Transaction,
} from "@solana/kit";
import { Hono } from "hono";
import { fingerprint, OperationStore, type PreSubmission, ReservationConflict } from "./operation-store.ts";
import { decodeInstructionData, paymentAddress } from "./program.ts";
import { buildTransaction, captureInstruction, capturePayload, type Lifetime, voidInstruction, voidPayload } from "./transactions.ts";
import type { PaymentRequirements, SettleResponse } from "./types.ts";

const base64 = getBase64Encoder();
const transactionDecoder = getTransactionDecoder();
const messageDecoder = getCompiledTransactionMessageDecoder();

export function encodeHeaderPayload(payload: unknown): string {
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64");
}

export function decodeHeaderPayload<T>(header: string): T {
  return JSON.parse(Buffer.from(header, "base64").toString("utf8")) as T;
}

/** The result of the protected work this resource actually guards. */
export type HandlerResult = { ok: true; amount: bigint; releaseRemainder: boolean } | { ok: false; detail: string };

export type ResourceServerConfig = {
  facilitatorUrl: string;
  bearerToken: string;
  network: string;
  programId: Address;
  /** Facilitator's sponsor address; advertised in `extra.feePayer` so the client signs for it. */
  feePayer: Address;
  /** The merchant: `payTo` and the lifecycle signer for capture/void/refund. */
  server: KeyPairSigner;
  asset: Address;
  amount: bigint;
  captureDeadlineSeconds: number;
  refundDeadlineSeconds: number;
  maxTimeoutSeconds?: number;
  store: OperationStore;
  getLatestBlockhash: () => Promise<Lifetime>;
  now: () => bigint;
  handler: (ctx: { payer: Address; payment: Address }) => Promise<HandlerResult>;
  fetchImpl?: typeof fetch;
};

function requirementsFor(config: ResourceServerConfig): PaymentRequirements {
  const now = config.now();
  return {
    scheme: "auth-capture",
    network: config.network,
    amount: config.amount.toString(),
    asset: config.asset,
    payTo: config.server.address,
    maxTimeoutSeconds: config.maxTimeoutSeconds ?? 60,
    extra: {
      paymentFlow: "escrow",
      captureDeadline: Number(now) + config.captureDeadlineSeconds,
      refundDeadline: Number(now) + config.captureDeadlineSeconds + config.refundDeadlineSeconds,
      programId: config.programId,
      feePayer: config.feePayer,
    },
  };
}

function facilitatorBody(payload: Record<string, unknown>, requirements: PaymentRequirements, resourceUrl: string) {
  return {
    x402Version: 2,
    paymentPayload: { x402Version: 2, resource: { url: resourceUrl }, accepted: requirements, payload },
    paymentRequirements: requirements,
  };
}

async function callFacilitator(config: ResourceServerConfig, body: unknown): Promise<SettleResponse> {
  const fetchImpl = config.fetchImpl ?? fetch;
  const res = await fetchImpl(`${config.facilitatorUrl}/settle`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${config.bearerToken}` },
    body: JSON.stringify(body),
  });
  return (await res.json()) as SettleResponse;
}

function decode(transactionBase64: string): { transaction: Transaction; blockhash: string } {
  const transaction = transactionDecoder.decode(base64.encode(transactionBase64));
  const message = messageDecoder.decode(transaction.messageBytes);
  return { transaction, blockhash: message.lifetimeToken };
}

/** Derives the payer, salt, and the client's own signed deadlines from its authorize transaction. */
function peekAuthorize(
  programId: Address,
  transaction: Transaction,
): { payer: Address; salt: Uint8Array; captureDeadline: bigint; refundDeadline: bigint } {
  const message = messageDecoder.decode(transaction.messageBytes);
  if (message.version !== "legacy") throw new Error("only legacy transactions are accepted");
  const payer = message.staticAccounts[1];
  if (!payer || message.header.numSignerAccounts < 2) throw new Error("missing economic signer");
  const ix = message.instructions.find((i) => message.staticAccounts[i.programAddressIndex] === programId);
  if (!ix) throw new Error("no auth-capture instruction");
  const decoded = decodeInstructionData(new Uint8Array(ix.data ?? []));
  if (!decoded || decoded.op !== "authorize") throw new Error("payload must carry exactly the authorize instruction");
  return { payer, salt: decoded.salt, captureDeadline: decoded.captureDeadline, refundDeadline: decoded.refundDeadline };
}

/**
 * Requirements for an already-signed authorize, pinned to the exact deadlines the client signed
 * rather than a fresh `config.now()` reading. `requirementsFor` offers a fresh window on the
 * initial 402 challenge; recomputing it again here would drift from what the client actually
 * signed by however long the client took to build and return its transaction, and the facilitator
 * would then reject a perfectly valid authorize as a terms mismatch.
 */
function requirementsForSigned(config: ResourceServerConfig, captureDeadline: bigint, refundDeadline: bigint): PaymentRequirements {
  return {
    scheme: "auth-capture",
    network: config.network,
    amount: config.amount.toString(),
    asset: config.asset,
    payTo: config.server.address,
    maxTimeoutSeconds: config.maxTimeoutSeconds ?? 60,
    extra: {
      paymentFlow: "escrow",
      captureDeadline: Number(captureDeadline),
      refundDeadline: Number(refundDeadline),
      programId: config.programId,
      feePayer: config.feePayer,
    },
  };
}

export function createResourceApp(config: ResourceServerConfig): Hono {
  const app = new Hono();
  const resourcePath = "/resource";

  app.get(resourcePath, async (c) => {
    const header = c.req.header("payment-signature");
    const requirements = requirementsFor(config);
    if (!header) {
      return c.json({ x402Version: 2, accepts: [requirements] }, 402);
    }

    let payload: Record<string, unknown>;
    try {
      payload = decodeHeaderPayload(header);
    } catch {
      return c.json({ error: "payment-signature header is not valid base64 JSON" }, 400);
    }
    const transactionBase64 = payload.transaction;
    if (typeof transactionBase64 !== "string") return c.json({ error: "payload.transaction is required" }, 400);

    const { transaction, blockhash: authorizeBlockhash } = decode(transactionBase64);
    let payer: Address;
    let salt: Uint8Array;
    let captureDeadline: bigint;
    let refundDeadline: bigint;
    try {
      ({ payer, salt, captureDeadline, refundDeadline } = peekAuthorize(config.programId, transaction));
    } catch (e) {
      return c.json({ error: e instanceof Error ? e.message : "could not decode the authorize transaction" }, 400);
    }
    // Pinned to the deadlines the client actually signed, not a fresh `now()` reading: real time
    // elapses between this request and the terminal settle below, so recomputing would drift from
    // what was signed and the facilitator would reject a valid authorize as a terms mismatch.
    const signedRequirements = requirementsForSigned(config, captureDeadline, refundDeadline);
    const payment = await paymentAddress(config.programId, payer, salt);
    const fp = fingerprint(payer, resourcePath, salt);

    try {
      config.store.reserve(fp, payer, resourcePath);
    } catch (e) {
      if (e instanceof ReservationConflict) {
        return c.json({ error: "this authorization/request was already reserved; it will not be executed again" }, 409);
      }
      throw e;
    }

    // The client's bytes carry only the payer's signature; the sponsor's (fee payer's) signature
    // is added by the facilitator at `/settle`, so no signature exists on this transaction yet —
    // it is recorded once the facilitator reports it below. The bytes, blockhash, and payment
    // identity are the pre-submission facts durable *before* the call.
    const authorizeRecord: PreSubmission = {
      transactionBase64,
      signature: "",
      blockhash: authorizeBlockhash,
      payment,
      // Before an authorize lands, the payment does not exist: expected (H,F) is (0,0).
      expectedHeld: "0",
      expectedRefundable: "0",
    };
    config.store.update(fp, { status: "authorizing", authorize: authorizeRecord });

    const settleAuthorize = await callFacilitator(config, facilitatorBody(payload, signedRequirements, `${config.facilitatorUrl}${resourcePath}`));
    if (!settleAuthorize.success) {
      // A rejected or ambiguous authorize never starts the handler.
      const status = settleAuthorize.errorReason === "settlement_pending" ? "authorize-pending" : "authorize-rejected";
      config.store.update(fp, { status, note: settleAuthorize.errorReason });
      return c.json({ error: "authorization failed", errorReason: settleAuthorize.errorReason }, 402);
    }
    authorizeRecord.signature = settleAuthorize.transaction;
    config.store.update(fp, { status: "authorized", authorize: authorizeRecord });
    config.store.update(fp, { status: "handler-started" });

    let result: HandlerResult;
    try {
      result = await config.handler({ payer, payment });
    } catch (e) {
      result = { ok: false, detail: e instanceof Error ? e.message : "handler threw" };
    }
    // `OperationRecord.handlerResult` is JSON-persisted: only its `{ ok, detail }` shape, never
    // the `bigint` fields a successful `HandlerResult` also carries.
    config.store.update(fp, {
      status: result.ok ? "handler-succeeded" : "handler-failed",
      handlerResult: result.ok ? { ok: true } : { ok: false, detail: result.detail },
    });

    const lifetime = await config.getLatestBlockhash();
    const common = { programId: config.programId, payment, payer, server: config.server.address, mint: config.asset };
    const terminalOp: "capture" | "void" = result.ok ? "capture" : "void";
    const terminalInstruction = result.ok
      ? await captureInstruction(common, result.amount, result.releaseRemainder, config.amount, 0n)
      : await voidInstruction(common, config.amount, 0n);
    const terminalTx = await buildTransaction({ feePayer: config.feePayer, instructions: [terminalInstruction], signers: [config.server], lifetime });
    const terminalPayload = result.ok
      ? capturePayload(payment, terminalTx, result.amount, result.releaseRemainder, config.amount, 0n)
      : voidPayload(payment, terminalTx, config.amount, 0n);

    // Same reasoning as the authorize record above: `terminalTx` carries only the server's
    // signature, not the sponsor's; the signature is recorded once the facilitator reports it.
    const terminalRecord: PreSubmission & { op: "capture" | "void" } = {
      op: terminalOp,
      transactionBase64: terminalPayload.transaction,
      signature: "",
      blockhash: lifetime.blockhash,
      payment,
      expectedHeld: config.amount.toString(),
      expectedRefundable: "0",
    };
    config.store.update(fp, { status: "terminal-settling", terminal: terminalRecord });

    const settleTerminal = await callFacilitator(config, facilitatorBody(terminalPayload, signedRequirements, `${config.facilitatorUrl}${resourcePath}`));
    if (!settleTerminal.success) {
      const status = settleTerminal.errorReason === "settlement_pending" ? "terminal-pending" : "pending";
      config.store.update(fp, { status, note: settleTerminal.errorReason });
      // Failed/unresolved finalization never becomes a completed-payment response, even if the
      // handler itself succeeded: the client must not be told its payment is final when it is not.
      return c.json({ error: "settlement did not finalize", errorReason: settleTerminal.errorReason }, 502);
    }
    terminalRecord.signature = settleTerminal.transaction;
    config.store.update(fp, { status: "completed", terminal: terminalRecord });

    c.header("payment-response", encodeHeaderPayload(settleTerminal));
    if (!result.ok) return c.json({ error: "handler failed", detail: result.detail }, 500);
    return c.json({ ok: true, payment, settlement: settleTerminal });
  });

  return app;
}
