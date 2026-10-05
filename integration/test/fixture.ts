// Local SVM-backed fixture: LiteSVM executes the actual SBF binary built by the existing
// component runner. No native processor or mocked program is substituted.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";
import { serve, type ServerType } from "@hono/node-server";
import {
  type Address,
  generateKeyPairSigner,
  getCompiledTransactionMessageDecoder,
  getSignatureFromTransaction,
  type Instruction,
  type KeyPairSigner,
  lamports,
  type Transaction,
} from "@solana/kit";
import { getCreateAccountInstruction } from "@solana-program/system";
import {
  getCreateAssociatedTokenIdempotentInstruction,
  getInitializeMint2Instruction,
  getMintSize,
  getMintToInstruction,
  getTokenDecoder,
} from "@solana-program/token";
import { FailedTransactionMetadata, LiteSVM } from "litesvm";
import { createApp } from "../src/app.js";
import { Facilitator } from "../src/facilitator.js";
import type { Ledger, LedgerAccount, SimulationOutcome, SubmitOutcome } from "../src/ledger.js";
import { ata, decodePayment, LOCAL_PROGRAM_ID, type Payment, paymentAddress, TOKEN_PROGRAM_ADDRESS } from "../src/program.js";
import {
  authorizeInstruction,
  authorizePayload,
  buildTransaction,
  captureInstruction,
  capturePayload,
  type Lifetime,
  refundInstruction,
  refundPayload,
  voidInstruction,
  voidPayload,
} from "../src/transactions.js";
import type { PaymentRequirements } from "../src/types.js";

export const BINARY = fileURLToPath(new URL("../../target/deploy/svm_auth_capture.so", import.meta.url));
export const BINARY_SHA256 = createHash("sha256").update(readFileSync(BINARY)).digest("hex");
export const NETWORK = "solana:litesvm-sac004-local";
export const NOW = 1_000n;
export const DC = 1_100n;
export const DR = 1_200n;
export const M = 100n;

const tokenDecoder = getTokenDecoder();
const messageDecoder = getCompiledTransactionMessageDecoder();

/** A recorded facilitator submission and its decoded program instruction. */
export type Submission = { signature: string; status: "succeeded" | "failed" | "unknown"; transaction: Transaction };

/**
 * LiteSVM-backed ledger. `beforeSubmit`/`afterSubmit` hooks model concurrent landings and
 * lost responses; they never alter the facilitator's bytes.
 */
export class LiteSvmLedger implements Ledger {
  readonly network = NETWORK;
  readonly submissions: Submission[] = [];
  beforeSubmit?: () => void | Promise<void>;
  /** Throw before broadcasting (nothing lands) or after landing (response lost). */
  failSubmit?: "before-landing" | "after-landing";

  constructor(readonly svm: LiteSVM) {}

  async now(): Promise<bigint> {
    return this.svm.getClock().unixTimestamp;
  }

  async getAccount(address: Address): Promise<LedgerAccount | null> {
    const a = this.svm.getAccount(address);
    if (!a.exists) return null;
    return { owner: a.programAddress, data: new Uint8Array(a.data), lamports: a.lamports, executable: a.executable };
  }

  async simulate(transaction: Transaction): Promise<SimulationOutcome> {
    const r = this.svm.simulateTransaction(transaction);
    if (r instanceof FailedTransactionMetadata) return { ok: false, error: r.toString(), logs: r.meta().logs() };
    return { ok: true };
  }

  async submit(transaction: Transaction): Promise<SubmitOutcome> {
    await this.beforeSubmit?.();
    const signature = getSignatureFromTransaction(transaction);
    if (this.failSubmit === "before-landing") {
      this.submissions.push({ signature, status: "unknown", transaction });
      throw new Error("RPC unavailable before broadcast confirmation");
    }
    const r = this.svm.sendTransaction(transaction);
    const failed = r instanceof FailedTransactionMetadata;
    this.submissions.push({ signature, status: this.failSubmit ? "unknown" : failed ? "failed" : "succeeded", transaction });
    if (this.failSubmit === "after-landing") throw new Error("confirmation response lost");
    if (failed) return { status: "failed", error: r.toString(), logs: r.meta().logs() };
    return { status: "succeeded" };
  }
}

/** Decodes a submitted transaction to its single auth-capture instruction and required signers. */
export function inspect(tx: Transaction) {
  const message = messageDecoder.decode(tx.messageBytes);
  if (message.version !== "legacy") throw new Error("expected a legacy message");
  const keys = message.staticAccounts;
  const ixs = message.instructions.filter((ix) => keys[ix.programAddressIndex] === LOCAL_PROGRAM_ID);
  if (ixs.length !== 1) throw new Error("expected exactly one program instruction");
  const ix = ixs[0]!;
  return {
    feePayer: keys[0],
    signers: keys.slice(0, message.header.numSignerAccounts),
    data: new Uint8Array(ix.data ?? []),
    accounts: (ix.accountIndices ?? []).map((i) => keys[i]!),
  };
}

export type Harness = Awaited<ReturnType<typeof createHarness>>;

export async function createHarness() {
  const svm = new LiteSVM().withSigverify(true);
  // Fail loudly if the binary is missing; never substitute a native processor.
  svm.addProgramFromFile(LOCAL_PROGRAM_ID, BINARY);
  const [payer, server, facilitatorKey, outsider, mintKey, setup] = await Promise.all(
    Array.from({ length: 6 }, () => generateKeyPairSigner()),
  ) as [KeyPairSigner, KeyPairSigner, KeyPairSigner, KeyPairSigner, KeyPairSigner, KeyPairSigner];
  for (const k of [payer, server, facilitatorKey, outsider, setup]) svm.airdrop(k.address, lamports(10_000_000_000n));
  const mint = mintKey.address;
  const ledger = new LiteSvmLedger(svm);
  const facilitator = new Facilitator({ network: NETWORK, programId: LOCAL_PROGRAM_ID, feePayer: facilitatorKey, ledger });
  const app = createApp(facilitator);
  const server_: ServerType = await new Promise((resolve) => {
    const s = serve({ fetch: app.fetch, port: 0, hostname: "127.0.0.1" }, () => resolve(s));
  });
  const url = `http://127.0.0.1:${(server_.address() as AddressInfo).port}`;

  const lifetime = (): Lifetime => ({ blockhash: svm.latestBlockhash(), lastValidBlockHeight: 1_000_000n });

  // LiteSVM accepts only the latest blockhash, so builders never expire it implicitly: prepared
  // transactions stay valid until a test explicitly calls `svm.expireBlockhash()`.

  /** Out-of-band setup/adversary transactions, paid by a separate setup key (never the facilitator). */
  const direct = async (instructions: Instruction[], signers: KeyPairSigner[] = []) => {
    const tx = await buildTransaction({ feePayer: setup.address, instructions, signers: [setup, ...signers], lifetime: lifetime() });
    return svm.sendTransaction(tx);
  };

  const ok = (r: ReturnType<LiteSVM["sendTransaction"]>) => {
    if (r instanceof FailedTransactionMetadata) throw new Error(r.toString());
    return r;
  };

  ok(
    await direct(
      [
        getCreateAccountInstruction({
          payer: setup,
          newAccount: mintKey,
          lamports: svm.minimumBalanceForRentExemption(BigInt(getMintSize())),
          space: getMintSize(),
          programAddress: TOKEN_PROGRAM_ADDRESS,
        }),
        getInitializeMint2Instruction({ mint, decimals: 6, mintAuthority: setup.address, freezeAuthority: setup.address }),
        getCreateAssociatedTokenIdempotentInstruction({ payer: setup, owner: payer.address, mint, ata: await ata(payer.address, mint) }),
        getCreateAssociatedTokenIdempotentInstruction({ payer: setup, owner: server.address, mint, ata: await ata(server.address, mint) }),
        getMintToInstruction({ mint, token: await ata(payer.address, mint), mintAuthority: setup, amount: 1_000n }),
      ],
      [mintKey],
    ),
  );

  const setTime = (t: bigint) => {
    const clock = svm.getClock();
    clock.unixTimestamp = t;
    svm.setClock(clock);
  };
  setTime(NOW);

  const requirements = (over: Partial<PaymentRequirements> = {}, extra: Record<string, unknown> = {}): PaymentRequirements => ({
    scheme: "auth-capture",
    network: NETWORK,
    amount: M.toString(),
    asset: mint,
    payTo: server.address,
    maxTimeoutSeconds: 60,
    ...over,
    extra: {
      paymentFlow: "escrow",
      captureDeadline: Number(DC),
      refundDeadline: Number(DR),
      programId: LOCAL_PROGRAM_ID,
      feePayer: facilitatorKey.address,
      ...extra,
    },
  });

  /** A complete x402 v2 facilitator request body; `accepted` mirrors the requirements. */
  const body = (payload: Record<string, unknown>, req: PaymentRequirements = requirements()) => ({
    x402Version: 2,
    paymentPayload: { x402Version: 2, resource: { url: "https://resource.example/metered" }, accepted: req, payload },
    paymentRequirements: req,
  });

  const post = async (path: "/verify" | "/settle", b: unknown) => {
    const res = await fetch(url + path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(b) });
    return { status: res.status, json: (await res.json()) as Record<string, any> };
  };

  let saltCounter = 0;
  const newSalt = () => new Uint8Array(32).fill(++saltCounter);

  const signedAuthorize = async (o: {
    salt: Uint8Array;
    maximum?: bigint;
    dc?: bigint;
    dr?: bigint;
    server?: Address;
    mint?: Address;
    signers?: KeyPairSigner[];
    feePayer?: Address;
    extra?: Instruction[];
  }) => {
    const ix = await authorizeInstruction({
      programId: LOCAL_PROGRAM_ID,
      payer: payer.address,
      server: o.server ?? server.address,
      mint: o.mint ?? mint,
      funder: facilitatorKey.address,
      salt: o.salt,
      maximum: o.maximum ?? M,
      captureDeadline: o.dc ?? DC,
      refundDeadline: o.dr ?? DR,
    });
    return buildTransaction({
      feePayer: o.feePayer ?? facilitatorKey.address,
      instructions: [...(o.extra ?? []), ix],
      signers: o.signers ?? [payer],
      lifetime: lifetime(),
    });
  };

  const paymentFor = (salt: Uint8Array) => paymentAddress(LOCAL_PROGRAM_ID, payer.address, salt);
  const stored = async (payment: Address) => ({
    programId: LOCAL_PROGRAM_ID,
    payment,
    payer: payer.address,
    server: server.address,
    mint,
  });

  /** Authorizes a fresh payment through the facilitator and returns its PDA. */
  const authorized = async () => {
    const salt = newSalt();
    const r = await post("/settle", body(authorizePayload(await signedAuthorize({ salt }))));
    if (!r.json.success) throw new Error(`authorize failed: ${JSON.stringify(r.json)}`);
    return paymentFor(salt);
  };

  const signedCapture = async (payment: Address, amount: bigint, release: boolean, h: bigint, f: bigint, signers = [server]) => {
    const ix = await captureInstruction(await stored(payment), amount, release, h, f);
    return buildTransaction({ feePayer: facilitatorKey.address, instructions: [ix], signers, lifetime: lifetime() });
  };
  const signedVoid = async (payment: Address, h: bigint, f: bigint, signers = [server]) => {
    const ix = await voidInstruction(await stored(payment), h, f);
    return buildTransaction({ feePayer: facilitatorKey.address, instructions: [ix], signers, lifetime: lifetime() });
  };
  const signedRefund = async (payment: Address, amount: bigint, h: bigint, f: bigint, signers = [server]) => {
    const ix = await refundInstruction(await stored(payment), amount, h, f);
    return buildTransaction({ feePayer: facilitatorKey.address, instructions: [ix], signers, lifetime: lifetime() });
  };

  const capture = async (payment: Address, amount: bigint, release: boolean, h: bigint, f: bigint) =>
    capturePayload(payment, await signedCapture(payment, amount, release, h, f), amount, release, h, f);
  const voidOp = async (payment: Address, h: bigint, f: bigint) => voidPayload(payment, await signedVoid(payment, h, f), h, f);
  const refund = async (payment: Address, amount: bigint, h: bigint, f: bigint) =>
    refundPayload(payment, await signedRefund(payment, amount, h, f), amount, h, f);

  const tokens = (address: Address): bigint => {
    const a = svm.getAccount(address);
    return a.exists ? tokenDecoder.decode(a.data).amount : 0n;
  };
  const state = (payment: Address): Payment => {
    const a = svm.getAccount(payment);
    if (!a.exists || a.programAddress !== LOCAL_PROGRAM_ID) throw new Error("payment missing");
    const p = decodePayment(new Uint8Array(a.data));
    if (!p) throw new Error("payment invalid");
    return p;
  };

  /** Whole-account snapshot of every account a payment touches, for no-write assertions. */
  const snapshot = async (payment?: Address) => {
    const addresses: Address[] = [
      payer.address,
      server.address,
      facilitatorKey.address,
      mint,
      await ata(payer.address, mint),
      await ata(server.address, mint),
    ];
    if (payment) addresses.push(payment, await ata(payment, mint));
    return JSON.stringify(
      addresses.map((a) => {
        const acc = svm.getAccount(a);
        return acc.exists ? [a, acc.lamports.toString(), acc.programAddress, Buffer.from(acc.data).toString("hex")] : [a, null];
      }),
    );
  };

  const close = () => new Promise<void>((resolve) => server_.close(() => resolve()));

  return {
    svm,
    ledger,
    facilitator,
    url,
    payer,
    server,
    facilitatorKey,
    outsider,
    setup,
    mint,
    direct,
    ok,
    setTime,
    lifetime,
    requirements,
    body,
    post,
    newSalt,
    signedAuthorize,
    paymentFor,
    stored,
    authorized,
    signedCapture,
    signedVoid,
    signedRefund,
    capture,
    voidOp,
    refund,
    tokens,
    state,
    snapshot,
    close,
    payerAta: () => ata(payer.address, mint),
    serverAta: () => ata(server.address, mint),
    vault: (payment: Address) => ata(payment, mint),
  };
}
