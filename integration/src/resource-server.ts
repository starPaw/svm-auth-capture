// Demo protected resource server (SAC-006 gap #2): the actual x402 v2 HTTP escrow flow
// (`http-transport.ts`): `402 + PAYMENT-REQUIRED → PAYMENT-SIGNATURE (PaymentPayload) →
// settle(authorize) → handler → settle(capture|capture+void|void) → PAYMENT-RESPONSE`, calling a
// trusted facilitator (`gateway.ts`) over HTTP with the bearer token it alone holds. `/verify`
// is never called here: it is a read-only preflight endpoint, not a required step of this
// ordering (integration/README.md).
//
// Resource-replay binding (SAC-006 gap #3): before the handler ever runs, this server verifies
// the payer's signature on the client's authorize transaction (that signature *is* this demo's
// caller authentication — there is no separate login), derives the caller/resource/payment
// fingerprint from it, and reserves it in the `OperationStore`. A conflicting reuse is rejected
// before the handler runs, so a duplicate or replayed request executes the handler at most once.
// A rejected or unresolved authorize never starts the handler. A handler failure takes the void
// path; a refused or unresolved terminal settle never becomes a completed-payment response.
// Every facilitator receipt — including a pending one and its signature — is journaled; a lost
// facilitator response stays unresolved for manual reconciliation (`reconciliation.ts`).
import {
  type Address,
  getBase64Encoder,
  getCompiledTransactionMessageDecoder,
  getPublicKeyFromAddress,
  getTransactionDecoder,
  type KeyPairSigner,
  type SignatureBytes,
  type Transaction,
  verifySignature,
} from "@solana/kit";
import { Hono } from "hono";
import {
  encodeHeader,
  decodeHeader,
  PAYMENT_REQUIRED_HEADER,
  PAYMENT_RESPONSE_HEADER,
  PAYMENT_SIGNATURE_HEADER,
  type PaymentRequired,
  parsePaymentPayload,
} from "./http-transport.ts";
import { fingerprint, type OperationRecord, OperationStore, type PreSubmission, ReservationConflict } from "./operation-store.ts";
import { decodeInstructionData, paymentAddress } from "./program.ts";
import { buildTransaction, captureInstruction, capturePayload, type Lifetime, voidInstruction, voidPayload } from "./transactions.ts";
import { EXTRA_KEYS, isObject, type PaymentPayload, type PaymentRequirements, Reason, type ReasonCode, type SettleResponse } from "./types.ts";

const base64 = getBase64Encoder();
const transactionDecoder = getTransactionDecoder();
const messageDecoder = getCompiledTransactionMessageDecoder();

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
  /** How long an offered challenge stays acceptable; also its `maxTimeoutSeconds`. */
  maxTimeoutSeconds?: number;
  description?: string;
  store: OperationStore;
  getLatestBlockhash: () => Promise<Lifetime>;
  /** Clock used for offered deadlines; the Devnet runtime reads the cluster Clock. */
  now: () => bigint | Promise<bigint>;
  handler: (ctx: { payer: Address; payment: Address }) => Promise<HandlerResult>;
  fetchImpl?: typeof fetch;
};

const RESOURCE_PATH = "/resource";

/**
 * What each facilitator reason proves about the operation. `definitive`: refused before any
 * broadcast, or finalized as failed — it did not and will not execute. `unresolved`: it may have
 * executed or may still. Typed over every `ReasonCode`, so a new reason cannot be added without
 * classifying it here; a reason string not in this table is treated as unresolved.
 */
const SETTLE_REASON_CLASS: Record<ReasonCode, "definitive" | "unresolved"> = {
  [Reason.x402Version]: "definitive",
  [Reason.unsupportedScheme]: "definitive",
  [Reason.invalidNetwork]: "definitive",
  [Reason.invalidPayload]: "definitive",
  [Reason.invalidRequirements]: "definitive",
  [Reason.insufficientFunds]: "definitive",
  [Reason.transactionState]: "definitive", // finalized with an execution error
  [Reason.settlementPending]: "unresolved",
  [Reason.settlementNotSubmitted]: "definitive",
  [Reason.duplicateSettlement]: "unresolved", // joined another in-flight broadcast of the same bytes
  [Reason.unexpectedVerify]: "definitive",
  [Reason.unexpectedSettle]: "definitive", // raised only by validation, before signing
  [Reason.networkMismatch]: "definitive",
  [Reason.acceptedMismatch]: "definitive",
  [Reason.paymentFlow]: "definitive",
  [Reason.unsupportedExtra]: "definitive",
  [Reason.programMismatch]: "definitive",
  [Reason.feePayerMismatch]: "definitive",
  [Reason.unsupportedAsset]: "definitive",
  [Reason.deadlineOrdering]: "definitive",
  [Reason.payloadType]: "definitive",
  [Reason.reclaimNotRelayed]: "definitive",
  [Reason.transaction]: "definitive",
  [Reason.instructions]: "definitive",
  [Reason.instructionData]: "definitive",
  [Reason.accounts]: "definitive",
  [Reason.signature]: "definitive",
  [Reason.termsMismatch]: "definitive",
  [Reason.payloadMismatch]: "definitive",
  [Reason.paymentNotFound]: "definitive",
  [Reason.paymentExists]: "definitive",
  [Reason.unexpectedState]: "definitive",
  [Reason.captureExpired]: "definitive",
  [Reason.refundExpired]: "definitive",
  [Reason.amount]: "definitive",
  [Reason.emptyHold]: "definitive",
  [Reason.tokenAccount]: "definitive",
  [Reason.serverInsufficientFunds]: "definitive",
  [Reason.vaultShortfall]: "definitive",
  [Reason.simulationFailed]: "definitive",
};

const isDefinitiveReason = (reason: string | undefined): boolean =>
  reason !== undefined && Object.hasOwn(SETTLE_REASON_CLASS, reason) && SETTLE_REASON_CLASS[reason as ReasonCode] === "definitive";

/** Tolerated backward step between two cluster-clock reads (RPC nodes behind a load balancer differ by a slot or two). */
const CLOCK_SKEW_SECONDS = 10n;
/** Gateway refusals that happen before `Facilitator.settle` is reached (`gateway.ts`). */
const GATEWAY_REFUSALS: ReadonlySet<number> = new Set([401, 403, 429]);

const timeout = (config: ResourceServerConfig) => config.maxTimeoutSeconds ?? 60;

function requirements(config: ResourceServerConfig, captureDeadline: bigint, refundDeadline: bigint): PaymentRequirements {
  return {
    scheme: "auth-capture",
    network: config.network,
    amount: config.amount.toString(),
    asset: config.asset,
    payTo: config.server.address,
    maxTimeoutSeconds: timeout(config),
    extra: {
      paymentFlow: "escrow",
      captureDeadline: Number(captureDeadline),
      refundDeadline: Number(refundDeadline),
      programId: config.programId,
      feePayer: config.feePayer,
    },
  };
}

async function freshRequirements(config: ResourceServerConfig): Promise<PaymentRequirements> {
  const now = BigInt(await config.now());
  const captureDeadline = now + BigInt(config.captureDeadlineSeconds);
  return requirements(config, captureDeadline, captureDeadline + BigInt(config.refundDeadlineSeconds));
}

function paymentRequired(config: ResourceServerConfig, resourceUrl: string, offer: PaymentRequirements, error: string): PaymentRequired {
  return {
    x402Version: 2,
    error,
    resource: { url: resourceUrl, description: config.description ?? "SAC-006 escrow-protected demo resource", mimeType: "application/json" },
    accepts: [offer],
  };
}

/**
 * The client's `accepted` must be exactly an offer this server makes: every field equal to this
 * server's configuration, and deadlines it issued no more than `maxTimeoutSeconds` ago (the
 * deadlines are the only per-challenge values). Without the freshness bound a client could pick
 * a capture deadline too short for the terminal settle to land after the handler runs.
 */
async function acceptedDeadlines(config: ResourceServerConfig, accepted: unknown): Promise<{ captureDeadline: bigint; refundDeadline: bigint } | string> {
  if (!isObject(accepted) || !isObject(accepted.extra)) return "accepted must carry extra";
  const extra = accepted.extra;
  const dc = extra.captureDeadline;
  const dr = extra.refundDeadline;
  if (!Number.isSafeInteger(dc) || !Number.isSafeInteger(dr)) return "accepted deadlines must be integers";
  const captureDeadline = BigInt(dc as number);
  const refundDeadline = BigInt(dr as number);
  const expected = requirements(config, captureDeadline, refundDeadline);
  const sameExtra =
    Object.keys(extra).sort().join(",") === EXTRA_KEYS.join(",") &&
    EXTRA_KEYS.every((k) => extra[k] === expected.extra![k]);
  const same =
    sameExtra &&
    accepted.scheme === expected.scheme &&
    accepted.network === expected.network &&
    accepted.amount === expected.amount &&
    accepted.asset === expected.asset &&
    accepted.payTo === expected.payTo &&
    accepted.maxTimeoutSeconds === expected.maxTimeoutSeconds &&
    Object.keys(accepted).every((k) => ["scheme", "network", "amount", "asset", "payTo", "maxTimeoutSeconds", "extra"].includes(k));
  if (!same) return "accepted is not an offer of this resource";
  const now = BigInt(await config.now());
  const issuedAgo = BigInt(config.captureDeadlineSeconds) - (captureDeadline - now);
  if (refundDeadline - captureDeadline !== BigInt(config.refundDeadlineSeconds) || issuedAgo < -CLOCK_SKEW_SECONDS || issuedAgo > BigInt(timeout(config))) {
    return "accepted deadlines are not from a current offer";
  }
  return { captureDeadline, refundDeadline };
}

function decodeTransaction(transactionBase64: string): Transaction {
  return transactionDecoder.decode(base64.encode(transactionBase64));
}

/**
 * Reads the authorize instruction the payer signed and verifies that signature over the exact
 * message bytes: only the payer's own signed request can claim its fingerprint.
 */
async function peekAuthorize(
  config: ResourceServerConfig,
  transaction: Transaction,
): Promise<{ payer: Address; salt: Uint8Array; maximum: bigint; captureDeadline: bigint; refundDeadline: bigint; blockhash: string }> {
  const message = messageDecoder.decode(transaction.messageBytes);
  if (message.version !== "legacy") throw new Error("only legacy transactions are accepted");
  if (message.staticAccounts[0] !== config.feePayer) throw new Error("fee payer must be the advertised sponsor");
  const payer = message.staticAccounts[1];
  if (!payer || message.header.numSignerAccounts !== 2) throw new Error("signers must be exactly the sponsor and the payer");
  const signature = transaction.signatures[payer];
  if (!signature || !(await verifySignature(await getPublicKeyFromAddress(payer), signature as SignatureBytes, transaction.messageBytes))) {
    throw new Error("payer signature does not cover this transaction");
  }
  const ixs = message.instructions.filter((i) => message.staticAccounts[i.programAddressIndex] === config.programId);
  if (ixs.length !== 1) throw new Error("exactly one auth-capture instruction is required");
  const decoded = decodeInstructionData(new Uint8Array(ixs[0]!.data ?? []));
  if (!decoded || decoded.op !== "authorize") throw new Error("payload must carry the authorize instruction");
  return { payer, salt: decoded.salt, maximum: decoded.maximum, captureDeadline: decoded.captureDeadline, refundDeadline: decoded.refundDeadline, blockhash: message.lifetimeToken };
}

function facilitatorBody(paymentPayload: PaymentPayload, paymentRequirements: PaymentRequirements) {
  return { x402Version: 2, paymentPayload, paymentRequirements };
}

type SettleOutcome =
  | { kind: "succeeded"; receipt: SettleResponse }
  | { kind: "rejected"; receipt: SettleResponse } // definitive: the operation did not and will not execute
  | { kind: "unresolved"; receipt: SettleResponse; detail: string }; // it may have executed or may still

function isSettleResponse(v: unknown): v is SettleResponse {
  return isObject(v) && typeof v.success === "boolean" && typeof v.transaction === "string" && typeof v.network === "string";
}

/**
 * Calls `/settle` and classifies the answer without guessing: only a well-formed definitive
 * refusal (or a gateway refusal that never reached the facilitator) counts as "did not execute";
 * a lost, malformed, pending, or unrecognized answer stays unresolved.
 */
async function settle(config: ResourceServerConfig, body: unknown): Promise<SettleOutcome> {
  const pending = (detail: string): SettleOutcome => ({
    kind: "unresolved",
    receipt: { success: false, errorReason: Reason.settlementPending, transaction: "", network: config.network },
    detail,
  });
  let res: Response;
  try {
    res = await (config.fetchImpl ?? fetch)(`${config.facilitatorUrl}/settle`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${config.bearerToken}` },
      body: JSON.stringify(body),
    });
  } catch (e) {
    return pending(`facilitator response lost: ${e instanceof Error ? e.message : String(e)}`);
  }
  let json: unknown;
  try {
    json = await res.json();
  } catch {
    return pending(`facilitator answered HTTP ${res.status} without a readable JSON body`);
  }
  if (!isSettleResponse(json)) {
    if (GATEWAY_REFUSALS.has(res.status)) {
      const detail = isObject(json) && typeof json.error === "string" ? json.error : `HTTP ${res.status}`;
      return { kind: "rejected", receipt: { success: false, errorReason: `facilitator_refused: ${detail}`, transaction: "", network: config.network } };
    }
    return pending(`malformed settle response (HTTP ${res.status})`);
  }
  if (json.success) {
    return json.transaction ? { kind: "succeeded", receipt: json } : { kind: "unresolved", receipt: json, detail: "success without a signature" };
  }
  if (isDefinitiveReason(json.errorReason)) return { kind: "rejected", receipt: json };
  return { kind: "unresolved", receipt: json, detail: `unresolved settle: ${json.errorReason ?? "no errorReason"}` };
}

export function createResourceApp(config: ResourceServerConfig): Hono {
  const app = new Hono();

  app.get(RESOURCE_PATH, async (c) => {
    const resourceUrl = `${new URL(c.req.url).origin}${RESOURCE_PATH}`;
    const challenge = async (error: string) => {
      const required = paymentRequired(config, resourceUrl, await freshRequirements(config), error);
      c.header(PAYMENT_REQUIRED_HEADER, encodeHeader(required));
      return c.json(required, 402);
    };

    const header = c.req.header(PAYMENT_SIGNATURE_HEADER);
    if (!header) return challenge(`${PAYMENT_SIGNATURE_HEADER} header is required`);

    // --- Parse and bind the payment before anything is reserved.
    let paymentPayload: PaymentPayload;
    let transaction: Transaction;
    try {
      paymentPayload = parsePaymentPayload(decodeHeader(header));
      const keys = Object.keys(paymentPayload.payload);
      if (keys.length !== 1 || typeof paymentPayload.payload.transaction !== "string") throw new Error("payload must carry exactly the authorize transaction");
      transaction = decodeTransaction(paymentPayload.payload.transaction);
    } catch (e) {
      return c.json({ error: `invalid ${PAYMENT_SIGNATURE_HEADER}: ${e instanceof Error ? e.message : String(e)}` }, 400);
    }
    let signed: Awaited<ReturnType<typeof peekAuthorize>>;
    try {
      signed = await peekAuthorize(config, transaction);
    } catch (e) {
      return c.json({ error: `invalid authorize transaction: ${e instanceof Error ? e.message : String(e)}` }, 400);
    }
    const deadlines = await acceptedDeadlines(config, paymentPayload.accepted);
    if (typeof deadlines === "string") return challenge(deadlines);
    if (signed.maximum !== config.amount || signed.captureDeadline !== deadlines.captureDeadline || signed.refundDeadline !== deadlines.refundDeadline) {
      return challenge("the signed authorize does not match the accepted offer");
    }
    const accepted = requirements(config, deadlines.captureDeadline, deadlines.refundDeadline);
    const { payer } = signed;
    const payment = await paymentAddress(config.programId, payer, signed.salt);
    const fp = fingerprint(payer, RESOURCE_PATH, signed.salt);

    try {
      config.store.reserve(fp, payer, RESOURCE_PATH);
    } catch (e) {
      if (e instanceof ReservationConflict) {
        return c.json({ error: "this authorization/request was already reserved; it will not be executed again" }, 409);
      }
      throw e;
    }

    const record = (patch: Partial<OperationRecord>) => config.store.update(fp, patch);
    const respond = (status: 200 | 402 | 500, receipt: SettleResponse, body: Record<string, unknown>) => {
      c.header(PAYMENT_RESPONSE_HEADER, encodeHeader(receipt));
      return c.json(body, status);
    };

    try {
      // --- Authorize: the client's exact bytes, durable before the facilitator ever sees them.
      const authorize: PreSubmission = {
        transactionBase64: paymentPayload.payload.transaction as string,
        signature: "",
        blockhash: signed.blockhash,
        payment,
        // Before an authorize lands, the payment does not exist: expected (H,F) is (0,0).
        expectedHeld: "0",
        expectedRefundable: "0",
      };
      record({ status: "authorizing", authorize });
      const settledAuthorize = await settle(config, facilitatorBody(paymentPayload, accepted));
      authorize.signature = settledAuthorize.receipt.transaction;
      if (settledAuthorize.kind !== "succeeded") {
        // A refused or unresolved authorize never starts the handler.
        const unresolved = settledAuthorize.kind === "unresolved";
        record({
          status: unresolved ? "authorize-pending" : "authorize-rejected",
          authorize,
          authorizeReceipt: settledAuthorize.receipt,
          ...(unresolved ? { note: settledAuthorize.detail } : {}),
        });
        return respond(402, settledAuthorize.receipt, { error: "authorization did not settle", errorReason: settledAuthorize.receipt.errorReason });
      }
      record({ status: "authorized", authorize, authorizeReceipt: settledAuthorize.receipt });

      // --- Handler: started and finished are recorded separately.
      record({ status: "handler-started" });
      let result: HandlerResult;
      try {
        result = await config.handler({ payer, payment });
      } catch (e) {
        result = { ok: false, detail: e instanceof Error ? e.message : "handler threw" };
      }
      // `handlerResult` is JSON-persisted: only `{ ok, detail }`, never the bigint fields.
      record({ status: result.ok ? "handler-succeeded" : "handler-failed", handlerResult: result.ok ? { ok: true } : { ok: false, detail: result.detail } });

      // --- Terminal settle: this server's consent, durable before the facilitator sees it.
      const lifetime = await config.getLatestBlockhash();
      const common = { programId: config.programId, payment, payer, server: config.server.address, mint: config.asset };
      const terminalInstruction = result.ok
        ? await captureInstruction(common, result.amount, result.releaseRemainder, config.amount, 0n)
        : await voidInstruction(common, config.amount, 0n);
      const terminalTx = await buildTransaction({ feePayer: config.feePayer, instructions: [terminalInstruction], signers: [config.server], lifetime });
      const terminalPayload = result.ok
        ? capturePayload(payment, terminalTx, result.amount, result.releaseRemainder, config.amount, 0n)
        : voidPayload(payment, terminalTx, config.amount, 0n);
      const terminal: PreSubmission & { op: "capture" | "void" } = {
        op: result.ok ? "capture" : "void",
        transactionBase64: terminalPayload.transaction,
        signature: "",
        blockhash: lifetime.blockhash,
        lastValidBlockHeight: lifetime.lastValidBlockHeight.toString(),
        payment,
        expectedHeld: config.amount.toString(),
        expectedRefundable: "0",
      };
      record({ status: "terminal-settling", terminal });
      const terminalBody = facilitatorBody({ x402Version: 2, resource: { url: resourceUrl }, accepted, payload: terminalPayload }, accepted);
      const settledTerminal = await settle(config, terminalBody);
      terminal.signature = settledTerminal.receipt.transaction;
      if (settledTerminal.kind !== "succeeded") {
        // Never a completed-payment response, even if the handler succeeded.
        const unresolved = settledTerminal.kind === "unresolved";
        record({
          status: unresolved ? "terminal-pending" : "terminal-rejected",
          terminal,
          terminalReceipt: settledTerminal.receipt,
          ...(unresolved ? { note: settledTerminal.detail } : {}),
        });
        return respond(500, settledTerminal.receipt, { error: "settlement did not finalize", errorReason: settledTerminal.receipt.errorReason });
      }
      record({ status: "completed", terminal, terminalReceipt: settledTerminal.receipt });
      if (!result.ok) return respond(500, settledTerminal.receipt, { error: "handler failed", detail: result.detail });
      return respond(200, settledTerminal.receipt, { ok: true, payment });
    } catch (e) {
      // An unexpected failure leaves the record at its last durable status (listed by
      // `unresolved()`); it is never retried here.
      const detail = e instanceof Error ? e.message : String(e);
      try {
        record({ note: `interrupted: ${detail}` });
      } catch {
        // The original failure is what the caller needs; the status already on disk stands.
      }
      return c.json({ error: "payment processing interrupted; held for manual reconciliation" }, 500);
    }
  });

  return app;
}
