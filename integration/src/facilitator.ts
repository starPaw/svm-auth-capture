// SAC-004 facilitator: x402 v2 `/verify` and `/settle` for scheme="auth-capture",
// extra.paymentFlow="escrow" against the accepted SVM program. Contract: docs/ARCHITECTURE.md,
// "Relay, recovery, and separation from application state". Preflight only: the program's
// onchain guards remain authoritative, and no economic term is ever taken from the request
// when the signed transaction or stored payment state defines it.
import {
  type Address,
  type CompiledTransactionMessage,
  getBase64Encoder,
  getCompiledTransactionMessageDecoder,
  getPublicKeyFromAddress,
  getSignatureFromTransaction,
  getTransactionDecoder,
  isAddress,
  isNone,
  type KeyPairSigner,
  partiallySignTransaction,
  type SignatureBytes,
  type Transaction,
  verifySignature,
} from "@solana/kit";
import { AccountState, getMintDecoder, getTokenDecoder } from "@solana-program/token";
import type { Ledger } from "./ledger.js";
import {
  type AccountSlot,
  ata,
  authorizeAccounts,
  captureAccounts,
  decodeInstructionData,
  decodePayment,
  type DecodedInstruction,
  I64_MAX,
  NATIVE_MINT,
  type Payment,
  paymentAddress,
  refundAccounts,
  SYSTEM_PROGRAM_ADDRESS,
  TOKEN_PROGRAM_ADDRESS,
  U64_MAX,
  voidAccounts,
} from "./program.js";
import {
  type FacilitatorRequest,
  type OperationResult,
  type PaymentRequirements,
  Reason,
  type ReasonCode,
  RESULT_KEY,
  SCHEME,
  type SettleResponse,
  type VerifyResponse,
} from "./types.js";

export const COMPUTE_BUDGET_PROGRAM_ADDRESS = "ComputeBudget111111111111111111111111111111" as Address;

export type FacilitatorConfig = {
  /** CAIP-2 network this facilitator serves; must equal the ledger's identity. */
  network: string;
  /** Pinned program ID for `network`; never taken from a 402 challenge. */
  programId: Address;
  /** Facilitator transaction sponsor: fee payer, and rent funder for authorize only. */
  feePayer: KeyPairSigner;
  ledger: Ledger;
  /** Bounds on the optional compute-budget instructions the sponsor pays for. */
  maxComputeUnitLimit?: number;
  maxComputeUnitPriceMicroLamports?: bigint;
};

class Rejection extends Error {
  constructor(
    readonly reason: ReasonCode,
    detail: string,
    readonly payer?: string,
  ) {
    super(detail);
  }
}

function reject(reason: ReasonCode, detail: string, payer?: string): never {
  throw new Rejection(reason, detail, payer);
}

/** Everything `/settle` needs after a successful preflight. */
type Verified = {
  transaction: Transaction;
  payer: Address;
  result: OperationResult;
};

type Terms = {
  maximum: bigint;
  asset: Address;
  payTo: Address;
  captureDeadline: bigint;
  refundDeadline: bigint;
};

const transactionDecoder = getTransactionDecoder();
const messageDecoder = getCompiledTransactionMessageDecoder();
const tokenDecoder = getTokenDecoder();
const mintDecoder = getMintDecoder();
const base64 = getBase64Encoder();

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

function parseU64(value: unknown, reason: ReasonCode, field: string): bigint {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) reject(reason, `${field} must be a u64 decimal string`);
  const n = BigInt(value);
  if (n > U64_MAX) reject(reason, `${field} exceeds u64`);
  return n;
}

function parseDeadline(value: unknown, field: string): bigint {
  // JSON numbers lose precision beyond 2^53; larger deadlines must be decimal strings.
  let n: bigint;
  if (typeof value === "number" && Number.isSafeInteger(value)) n = BigInt(value);
  else if (typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value)) n = BigInt(value);
  else reject(Reason.invalidRequirements, `extra.${field} must be an integer Unix timestamp`);
  if (n <= 0n || n > I64_MAX) reject(Reason.deadlineOrdering, `extra.${field} out of range`);
  return n;
}

function parseAddress(value: unknown, reason: ReasonCode, field: string): Address {
  if (typeof value !== "string" || !isAddress(value)) reject(reason, `${field} must be a base58 address`);
  return value;
}

export class Facilitator {
  readonly network: string;
  readonly programId: Address;
  private readonly feePayer: KeyPairSigner;
  private readonly ledger: Ledger;
  private readonly maxUnitLimit: number;
  private readonly maxUnitPrice: bigint;

  constructor(config: FacilitatorConfig) {
    if (config.ledger.network !== config.network) {
      throw new Error(`ledger serves ${config.ledger.network}, facilitator is pinned to ${config.network}`);
    }
    this.network = config.network;
    this.programId = config.programId;
    this.feePayer = config.feePayer;
    this.ledger = config.ledger;
    this.maxUnitLimit = config.maxComputeUnitLimit ?? 400_000;
    this.maxUnitPrice = config.maxComputeUnitPriceMicroLamports ?? 10_000n;
  }

  get feePayerAddress(): Address {
    return this.feePayer.address;
  }

  /** Read-only preflight: never signs anything it returns, never submits. */
  async verify(body: unknown): Promise<VerifyResponse> {
    try {
      const v = await this.check(body);
      return { isValid: true, payer: v.payer, extra: { [RESULT_KEY]: v.result } };
    } catch (e) {
      if (e instanceof Rejection) return { isValid: false, invalidReason: e.reason, ...(e.payer ? { payer: e.payer } : {}) };
      return { isValid: false, invalidReason: Reason.unexpectedVerify };
    }
  }

  /**
   * Re-verifies, co-signs only as fee payer, submits the exact bytes once, and reports the
   * confirmed outcome. No retry, blockhash replacement, or re-signing: an unknown outcome is
   * returned as `settlement_pending` with the broadcast signature.
   */
  async settle(body: unknown): Promise<SettleResponse> {
    let verified: Verified;
    try {
      verified = await this.check(body);
    } catch (e) {
      const reason = e instanceof Rejection ? e.reason : Reason.unexpectedSettle;
      const payer = e instanceof Rejection ? e.payer : undefined;
      return { success: false, errorReason: reason, transaction: "", network: this.network, ...(payer ? { payer } : {}) };
    }
    const signed = await partiallySignTransaction([this.feePayer.keyPair], verified.transaction);
    const signature = getSignatureFromTransaction(signed);
    const base = { transaction: signature, network: this.network, payer: verified.payer };
    let outcome;
    try {
      outcome = await this.ledger.submit(signed);
    } catch {
      return { success: false, errorReason: Reason.settlementPending, ...base };
    }
    if (outcome.status !== "succeeded") {
      return { success: false, errorReason: Reason.transactionState, ...base };
    }
    return { success: true, ...base, amount: verified.result.amount, extensions: { [RESULT_KEY]: verified.result } };
  }

  private async check(body: unknown): Promise<Verified> {
    if (!isObject(body)) reject(Reason.invalidPayload, "request body must be an object");
    if (body.x402Version !== 2) reject(Reason.x402Version, "x402Version must be 2");
    const payload = body.paymentPayload;
    const requirements = body.paymentRequirements;
    if (!isObject(payload) || !isObject(requirements)) reject(Reason.invalidPayload, "paymentPayload and paymentRequirements are required");
    if (payload.x402Version !== 2) reject(Reason.x402Version, "paymentPayload.x402Version must be 2");
    const request = body as FacilitatorRequest;
    const terms = this.checkRequirements(request.paymentRequirements);
    this.checkAccepted(request.paymentPayload.accepted, request.paymentRequirements);
    const scheme = request.paymentPayload.payload;
    if (!isObject(scheme)) reject(Reason.invalidPayload, "payload must be an object");

    if (scheme.type === undefined) return this.checkAuthorize(scheme, terms);
    if (scheme.type === "reclaim") reject(Reason.reclaimNotRelayed, "reclaim is payer-direct and never relayed through /settle");
    if (scheme.type === "capture" || scheme.type === "void" || scheme.type === "refund") {
      return this.checkLifecycle(scheme.type, scheme, terms);
    }
    return reject(Reason.payloadType, "payload.type must be absent (authorize), capture, void, or refund");
  }

  private checkRequirements(r: PaymentRequirements): Terms {
    if (!isObject(r)) reject(Reason.invalidRequirements, "paymentRequirements must be an object");
    if (r.scheme !== SCHEME) reject(Reason.unsupportedScheme, `scheme must be ${SCHEME}`);
    if (typeof r.network !== "string" || !/^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/.test(r.network)) {
      reject(Reason.invalidNetwork, "network must be CAIP-2");
    }
    if (r.network !== this.network) reject(Reason.networkMismatch, `network must be ${this.network}`);
    const extra = r.extra ?? {};
    if (!isObject(extra)) reject(Reason.invalidRequirements, "extra must be an object");
    // Escrow is the scheme default; any other flow or an unknown value is unsupported.
    if (extra.paymentFlow !== undefined && extra.paymentFlow !== "escrow") reject(Reason.paymentFlow, "only paymentFlow=escrow is supported");
    if (extra.programId !== this.programId) reject(Reason.programMismatch, "extra.programId must equal the pinned program");
    if (extra.feePayer !== this.feePayer.address) reject(Reason.feePayerMismatch, "extra.feePayer must be this facilitator's sponsor");
    if (typeof r.maxTimeoutSeconds !== "number" || !Number.isSafeInteger(r.maxTimeoutSeconds) || r.maxTimeoutSeconds <= 0) {
      reject(Reason.invalidRequirements, "maxTimeoutSeconds must be a positive integer");
    }
    const maximum = parseU64(r.amount, Reason.invalidRequirements, "amount");
    if (maximum === 0n) reject(Reason.invalidRequirements, "amount (authorized maximum M) must be positive");
    const asset = parseAddress(r.asset, Reason.invalidRequirements, "asset");
    if (asset === NATIVE_MINT) reject(Reason.unsupportedAsset, "wrapped SOL is unsupported");
    const payTo = parseAddress(r.payTo, Reason.invalidRequirements, "payTo");
    const captureDeadline = parseDeadline(extra.captureDeadline, "captureDeadline");
    const refundDeadline = parseDeadline(extra.refundDeadline, "refundDeadline");
    if (captureDeadline > refundDeadline) reject(Reason.deadlineOrdering, "captureDeadline must not exceed refundDeadline");
    return { maximum, asset, payTo, captureDeadline, refundDeadline };
  }

  /** The client's accepted requirements must be the verified requirements, field for field. */
  private checkAccepted(accepted: unknown, r: PaymentRequirements): void {
    if (!isObject(accepted)) reject(Reason.invalidPayload, "paymentPayload.accepted is required");
    const a = accepted as PaymentRequirements;
    const flow = (x: PaymentRequirements) => (isObject(x.extra) ? (x.extra.paymentFlow ?? "escrow") : undefined);
    const same =
      a.scheme === r.scheme &&
      a.network === r.network &&
      a.amount === r.amount &&
      a.asset === r.asset &&
      a.payTo === r.payTo &&
      a.maxTimeoutSeconds === r.maxTimeoutSeconds &&
      isObject(a.extra) &&
      flow(a) === flow(r) &&
      String(a.extra.captureDeadline) === String(r.extra?.captureDeadline) &&
      String(a.extra.refundDeadline) === String(r.extra?.refundDeadline) &&
      a.extra.programId === r.extra?.programId &&
      a.extra.feePayer === r.extra?.feePayer;
    if (!same) reject(Reason.acceptedMismatch, "paymentPayload.accepted differs from paymentRequirements");
  }

  private async checkAsset(asset: Address): Promise<void> {
    const mint = await this.ledger.getAccount(asset);
    if (!mint) reject(Reason.unsupportedAsset, "asset mint does not exist");
    // Only the fixed classic Token Program; Token-2022 and other owners are unsupported in v1.
    if (mint.owner !== TOKEN_PROGRAM_ADDRESS) reject(Reason.unsupportedAsset, "asset must be a classic SPL Token mint");
    if (mint.data.length !== mintDecoder.fixedSize) reject(Reason.unsupportedAsset, "asset is not a mint");
    if (!mintDecoder.decode(mint.data).isInitialized) reject(Reason.unsupportedAsset, "asset mint is not initialized");
  }

  /** Decodes the wire transaction and enforces the sponsor, signer set, and instruction allowlist. */
  private async decodeTransaction(
    value: unknown,
    roleSigner: Address,
  ): Promise<{ transaction: Transaction; message: CompiledTransactionMessage; data: Uint8Array; accounts: AccountSlot[] }> {
    if (typeof value !== "string" || value.length === 0) reject(Reason.invalidPayload, "payload.transaction must be base64");
    let transaction: Transaction;
    let message: CompiledTransactionMessage;
    try {
      transaction = transactionDecoder.decode(base64.encode(value));
      message = messageDecoder.decode(transaction.messageBytes);
    } catch {
      return reject(Reason.transaction, "payload.transaction is not a decodable Solana transaction");
    }
    // Legacy messages only: every account is visible and no lookup table can supply addresses.
    if (message.version !== "legacy") reject(Reason.transaction, "only legacy transaction messages are accepted");
    const keys = message.staticAccounts;
    const { numSignerAccounts, numReadonlySignerAccounts, numReadonlyNonSignerAccounts } = message.header;
    if (keys[0] !== this.feePayer.address) reject(Reason.feePayerMismatch, "fee payer must be this facilitator's sponsor");
    // Exactly two required signers: the sponsor and the one economic party for this operation.
    if (numSignerAccounts !== 2 || keys[1] !== roleSigner) reject(Reason.signature, "signers must be exactly the sponsor and the economic signer");
    if (roleSigner === this.feePayer.address) reject(Reason.signature, "the sponsor cannot be the economic signer");
    const signature = transaction.signatures[roleSigner];
    if (!signature) reject(Reason.signature, "missing economic signer signature");
    const key = await getPublicKeyFromAddress(roleSigner);
    if (!(await verifySignature(key, signature as SignatureBytes, transaction.messageBytes))) {
      reject(Reason.signature, "economic signer signature does not cover these message bytes");
    }

    const isSigner = (i: number) => i < numSignerAccounts;
    const isWritable = (i: number) =>
      i < numSignerAccounts ? i < numSignerAccounts - numReadonlySignerAccounts : i < keys.length - numReadonlyNonSignerAccounts;
    let program: { data: Uint8Array; accounts: AccountSlot[] } | undefined;
    let unitLimit = false;
    let unitPrice = false;
    for (const ix of message.instructions) {
      const programAddress = keys[ix.programAddressIndex];
      const indices = ix.accountIndices ?? [];
      const data = new Uint8Array(ix.data ?? []);
      if (programAddress === COMPUTE_BUDGET_PROGRAM_ADDRESS) {
        const view = new DataView(data.buffer);
        if (indices.length !== 0) reject(Reason.instructions, "compute-budget instructions take no accounts");
        if (data[0] === 2 && data.length === 5 && !unitLimit) {
          unitLimit = true;
          if (view.getUint32(1, true) > this.maxUnitLimit) reject(Reason.instructions, "compute unit limit exceeds the sponsor bound");
        } else if (data[0] === 3 && data.length === 9 && !unitPrice) {
          unitPrice = true;
          if (view.getBigUint64(1, true) > this.maxUnitPrice) reject(Reason.instructions, "compute unit price exceeds the sponsor bound");
        } else {
          reject(Reason.instructions, "only one SetComputeUnitLimit and one SetComputeUnitPrice are allowed");
        }
        continue;
      }
      if (programAddress !== this.programId || program) {
        reject(Reason.instructions, "exactly one auth-capture instruction and no other spending instruction is allowed");
      }
      program = {
        data,
        accounts: indices.map((i) => {
          const address = keys[i];
          if (address === undefined) reject(Reason.transaction, "account index out of range");
          return { address, signer: isSigner(i), writable: isWritable(i) };
        }),
      };
    }
    if (!program) reject(Reason.instructions, "no auth-capture instruction");
    return { transaction, message, ...program };
  }

  private expectAccounts(actual: AccountSlot[], expected: AccountSlot[]): void {
    const same =
      actual.length === expected.length &&
      actual.every((a, i) => {
        const e = expected[i]!;
        return a.address === e.address && a.signer === e.signer && a.writable === e.writable;
      });
    if (!same) reject(Reason.accounts, "instruction accounts or roles differ from the required layout");
  }

  private async tokenAccount(address: Address, owner: Address, mint: Address, label: string) {
    const account = await this.ledger.getAccount(address);
    if (!account || account.owner !== TOKEN_PROGRAM_ADDRESS || account.data.length !== tokenDecoder.fixedSize) {
      reject(Reason.tokenAccount, `${label} token account is missing`);
    }
    const t = tokenDecoder.decode(account.data);
    if (t.owner !== owner || t.mint !== mint || t.state !== AccountState.Initialized || !isNone(t.isNative)) {
      reject(Reason.tokenAccount, `${label} token account cannot transfer`);
    }
    return t;
  }

  private async simulate(transaction: Transaction, payer: string): Promise<void> {
    const signed = await partiallySignTransaction([this.feePayer.keyPair], transaction);
    const outcome = await this.ledger.simulate(signed);
    if (!outcome.ok) reject(Reason.simulationFailed, outcome.error, payer);
  }

  private async checkAuthorize(scheme: Record<string, unknown>, terms: Terms): Promise<Verified> {
    if (Object.keys(scheme).some((k) => k !== "transaction")) reject(Reason.invalidPayload, "authorize payload carries only the client transaction");
    // The payer is the second required signer; the signed instruction and account layout bind it.
    const payer = await this.peekSecondSigner(scheme.transaction);
    const { transaction, data, accounts } = await this.decodeTransaction(scheme.transaction, payer);
    const ix = decodeInstructionData(data);
    if (ix?.op === "reclaim") reject(Reason.reclaimNotRelayed, "reclaim is payer-direct and never relayed through /settle", payer);
    if (ix?.op !== "authorize") reject(Reason.instructionData, "client payload must carry exactly the authorize instruction", payer);
    if (
      ix.maximum !== terms.maximum ||
      ix.captureDeadline !== terms.captureDeadline ||
      ix.refundDeadline !== terms.refundDeadline
    ) {
      reject(Reason.termsMismatch, "signed M, captureDeadline, or refundDeadline differs from the requirements", payer);
    }
    if (payer === terms.payTo) reject(Reason.accounts, "payer and payTo must differ", payer);
    // The signed server and mint accounts are the payTo and asset terms the program will store.
    if (accounts[1]?.address !== terms.payTo || accounts[3]?.address !== terms.asset) {
      reject(Reason.termsMismatch, "signed payTo or asset differs from the requirements", payer);
    }
    const payment = await paymentAddress(this.programId, payer, ix.salt);
    const source = await ata(payer, terms.asset);
    const vault = await ata(payment, terms.asset);
    this.expectAccounts(
      accounts,
      authorizeAccounts({ payer, server: terms.payTo, payment, mint: terms.asset, source, vault, funder: this.feePayer.address }),
    );
    await this.checkAsset(terms.asset);
    if ((await this.ledger.now()) >= terms.captureDeadline) reject(Reason.captureExpired, "authorize requires now < captureDeadline", payer);
    const existing = await this.ledger.getAccount(payment);
    if (existing && (existing.owner !== SYSTEM_PROGRAM_ADDRESS || existing.data.length !== 0 || existing.executable)) {
      reject(Reason.paymentExists, "payment identity is already used", payer);
    }
    const sourceState = await this.tokenAccount(source, payer, terms.asset, "payer");
    if (sourceState.amount < terms.maximum) reject(Reason.insufficientFunds, "payer cannot fund the authorized maximum", payer);
    await this.simulate(transaction, payer);
    return {
      transaction,
      payer,
      result: { operation: "authorize", payment, amount: terms.maximum.toString(), held: terms.maximum.toString(), refundable: "0" },
    };
  }

  /** The authorize payer is not known before decoding; read it from the signed header only. */
  private async peekSecondSigner(value: unknown): Promise<Address> {
    if (typeof value !== "string" || value.length === 0) reject(Reason.invalidPayload, "payload.transaction must be base64");
    try {
      const message = messageDecoder.decode(transactionDecoder.decode(base64.encode(value)).messageBytes);
      const signer = message.staticAccounts[1];
      if (message.header.numSignerAccounts >= 2 && signer) return signer;
    } catch {
      return reject(Reason.transaction, "payload.transaction is not a decodable Solana transaction");
    }
    return reject(Reason.signature, "signers must be exactly the sponsor and the economic signer");
  }

  private async checkLifecycle(type: "capture" | "void" | "refund", scheme: Record<string, unknown>, terms: Terms): Promise<Verified> {
    const allowed: Record<typeof type, string[]> = {
      capture: ["type", "payment", "transaction", "amount", "releaseRemainder", "expectedHeld", "expectedRefundable"],
      void: ["type", "payment", "transaction", "expectedHeld", "expectedRefundable"],
      refund: ["type", "payment", "transaction", "amount", "expectedHeld", "expectedRefundable"],
    };
    const keys = Object.keys(scheme);
    if (keys.length !== allowed[type].length || !keys.every((k) => allowed[type].includes(k))) {
      reject(Reason.invalidPayload, `${type} payload must carry exactly: ${allowed[type].join(", ")}`);
    }
    if (type === "capture" && typeof scheme.releaseRemainder !== "boolean") reject(Reason.invalidPayload, "releaseRemainder must be an explicit boolean");
    const paymentKey = parseAddress(scheme.payment, Reason.invalidPayload, "payload.payment");
    const expectedHeld = parseU64(scheme.expectedHeld, Reason.invalidPayload, "expectedHeld");
    const expectedRefundable = parseU64(scheme.expectedRefundable, Reason.invalidPayload, "expectedRefundable");
    const amount = type === "void" ? undefined : parseU64(scheme.amount, Reason.invalidPayload, "amount");

    // Stored immutable terms are authoritative for every later operation.
    const stored = await this.storedPayment(paymentKey);
    const payer = stored.payer;
    if (
      stored.server !== terms.payTo ||
      stored.mint !== terms.asset ||
      stored.maximum !== terms.maximum ||
      stored.captureDeadline !== terms.captureDeadline ||
      stored.refundDeadline !== terms.refundDeadline
    ) {
      reject(Reason.termsMismatch, "requirements differ from the stored payment terms (payTo, asset, M, Dc, Dr)", payer);
    }

    const { transaction, data, accounts } = await this.decodeTransaction(scheme.transaction, stored.server);
    const ix = decodeInstructionData(data);
    if (ix?.op === "reclaim") reject(Reason.reclaimNotRelayed, "reclaim is payer-direct and never relayed through /settle", payer);
    if (!ix || ix.op !== type) reject(Reason.instructionData, `signed instruction is not ${type}`, payer);
    this.checkSignedMatchesPayload(ix, { amount, releaseRemainder: scheme.releaseRemainder as boolean | undefined, expectedHeld, expectedRefundable }, payer);

    const vault = await ata(paymentKey, stored.mint);
    const serverAta = await ata(stored.server, stored.mint);
    const payerAta = await ata(stored.payer, stored.mint);
    const common = { server: stored.server, payment: paymentKey, mint: stored.mint };
    const expected =
      type === "capture"
        ? captureAccounts({ ...common, vault, serverAta, payerAta })
        : type === "void"
          ? voidAccounts({ ...common, vault, payerAta })
          : refundAccounts({ ...common, serverAta, payerAta });
    this.expectAccounts(accounts, expected);
    await this.checkAsset(stored.mint);

    // State preflight against the exact signed pair; the program re-checks it atomically.
    if (stored.held !== expectedHeld || stored.refundable !== expectedRefundable) {
      reject(Reason.unexpectedState, "stored (H,F) differs from the signed expected pair", payer);
    }
    const now = await this.ledger.now();
    let result: OperationResult;
    if (ix.op === "capture") {
      if (now >= stored.captureDeadline) reject(Reason.captureExpired, "capture requires now < captureDeadline", payer);
      if (ix.amount === 0n || ix.amount > stored.held) reject(Reason.amount, "capture requires 0 < amount <= H", payer);
      const vaultState = await this.tokenAccount(vault, paymentKey, stored.mint, "vault");
      if (vaultState.amount < stored.held) reject(Reason.insufficientFunds, "vault does not back the hold", payer);
      await this.tokenAccount(serverAta, stored.server, stored.mint, "server");
      const remainder = stored.held - ix.amount;
      if (ix.releaseRemainder && remainder > 0n) await this.tokenAccount(payerAta, stored.payer, stored.mint, "payer");
      result = {
        operation: "capture",
        payment: paymentKey,
        amount: ix.amount.toString(),
        releaseRemainder: ix.releaseRemainder,
        ...(ix.releaseRemainder ? { released: remainder.toString() } : {}),
        held: (ix.releaseRemainder ? 0n : remainder).toString(),
        refundable: (stored.refundable + ix.amount).toString(),
      };
    } else if (ix.op === "void") {
      if (stored.held === 0n) reject(Reason.emptyHold, "void requires a positive hold", payer);
      const vaultState = await this.tokenAccount(vault, paymentKey, stored.mint, "vault");
      if (vaultState.amount < stored.held) reject(Reason.insufficientFunds, "vault does not back the hold", payer);
      await this.tokenAccount(payerAta, stored.payer, stored.mint, "payer");
      result = { operation: "void", payment: paymentKey, amount: stored.held.toString(), held: "0", refundable: stored.refundable.toString() };
    } else if (ix.op === "refund") {
      if (now >= stored.refundDeadline) reject(Reason.refundExpired, "refund requires now < refundDeadline", payer);
      if (ix.amount === 0n || ix.amount > stored.refundable) reject(Reason.amount, "refund requires 0 < amount <= F", payer);
      const source = await this.tokenAccount(serverAta, stored.server, stored.mint, "server");
      // Refunds are server-funded; a facilitator never becomes a fallback source of value.
      if (source.amount < ix.amount) reject(Reason.insufficientFunds, "server ATA cannot fund the refund", payer);
      await this.tokenAccount(payerAta, stored.payer, stored.mint, "payer");
      result = {
        operation: "refund",
        payment: paymentKey,
        amount: ix.amount.toString(),
        held: stored.held.toString(),
        refundable: (stored.refundable - ix.amount).toString(),
      };
    } else {
      return reject(Reason.instructionData, "unsupported instruction", payer);
    }
    await this.simulate(transaction, payer);
    return { transaction, payer, result };
  }

  /** Explicit payload fields must equal the signed instruction; the signed bytes are what executes. */
  private checkSignedMatchesPayload(
    ix: DecodedInstruction,
    p: { amount?: bigint; releaseRemainder?: boolean; expectedHeld: bigint; expectedRefundable: bigint },
    payer: string,
  ): void {
    if (ix.op !== "capture" && ix.op !== "void" && ix.op !== "refund") return;
    if (ix.expectedHeld !== p.expectedHeld || ix.expectedRefundable !== p.expectedRefundable) {
      reject(Reason.payloadMismatch, "payload expected pair differs from the signed expected pair", payer);
    }
    if ((ix.op === "capture" || ix.op === "refund") && ix.amount !== p.amount) {
      reject(Reason.payloadMismatch, "payload amount differs from the signed amount", payer);
    }
    if (ix.op === "capture" && ix.releaseRemainder !== p.releaseRemainder) {
      reject(Reason.payloadMismatch, "payload releaseRemainder differs from the signed flag", payer);
    }
  }

  private async storedPayment(address: Address): Promise<Payment> {
    const account = await this.ledger.getAccount(address);
    if (!account || account.owner !== this.programId) reject(Reason.paymentNotFound, "payment account is not owned by the pinned program");
    const stored = decodePayment(account.data);
    if (!stored) reject(Reason.paymentNotFound, "payment account data is invalid");
    if ((await paymentAddress(this.programId, stored.payer, stored.salt)) !== address) {
      reject(Reason.paymentNotFound, "payment account is not the canonical PDA for its stored payer and salt");
    }
    return stored;
  }
}
