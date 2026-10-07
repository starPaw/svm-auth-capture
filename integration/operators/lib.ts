// Shared helpers for the SAC-006 live Devnet evidence drivers (`run-all.sh`). Drivers call only
// committed `src/` modules. Nothing here prints the RPC URL, a keypair path, or a secret: keys are
// identified by public key, and the RPC only through `redactRpcUrl`.
import { appendFileSync, readFileSync } from "node:fs";
import { type Address, createKeyPairSignerFromBytes, createSolanaRpc, type KeyPairSigner } from "@solana/kit";
import { AccountState, getTokenDecoder } from "@solana-program/token";
import { loadDeploymentRecord, type DeploymentRecord } from "../src/deployment-record.ts";
import { ata, decodePayment, TOKEN_PROGRAM_ADDRESS } from "../src/program.ts";
import { redactRpcUrl, RpcLedger } from "../src/rpc-ledger.ts";

export function env(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`missing required environment variable ${name}`);
  return value;
}

export async function loadKeypair(path: string): Promise<KeyPairSigner> {
  const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (!Array.isArray(parsed) || parsed.length !== 64) throw new Error("keypair file must be a solana-keygen 64-byte secret key JSON array");
  return createKeyPairSignerFromBytes(new Uint8Array(parsed as number[]));
}

const json = (v: unknown) => JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? x.toString() : x));

/** Human-readable line to stdout, plus one JSON event per line to `SAC006_EVIDENCE_EVENTS` when set. */
export function emit(event: string, data: Record<string, unknown> = {}): void {
  console.log(`${event}${Object.keys(data).length ? " " + json(data) : ""}`);
  const file = process.env.SAC006_EVIDENCE_EVENTS;
  if (file) appendFileSync(file, json({ at: new Date().toISOString(), event, ...data }) + "\n");
}

export function check(condition: boolean, what: string, data: Record<string, unknown> = {}): void {
  if (!condition) {
    emit("CHECK FAILED", { what, ...data });
    throw new Error(`check failed: ${what}`);
  }
  emit("ok", { what });
}

export type Context = {
  record: DeploymentRecord;
  ledger: RpcLedger;
  rpcUrl: string;
  sponsor: KeyPairSigner;
  payer: KeyPairSigner;
  server: KeyPairSigner;
  mint: Address;
};

/** Loads the pinned record, verifies the RPC genesis, and loads the role keypairs. */
export async function context(): Promise<Context> {
  const record = loadDeploymentRecord(env("SAC006_DEPLOYMENT_RECORD_PATH"));
  const rpcUrl = env("SOLANA_RPC_URL");
  // Drivers may allow a longer settlement window than the 60s runtime default: Devnet finalization
  // (or RPC status rate limiting) has been observed to exceed it, and a driver step that is not
  // the scenario under test should not fail on that.
  const confirmTimeoutMs = Number(process.env.SAC006_CONFIRM_TIMEOUT_MS ?? "60000");
  const ledger = new RpcLedger({ deployment: record, network: record.network.caip2, genesisHash: record.network.genesisHash, rpcUrl, confirmTimeoutMs });
  await ledger.verifyGenesis();
  const [sponsor, payer, server] = await Promise.all([
    loadKeypair(env("SAC006_FACILITATOR_KEYPAIR_PATH")),
    loadKeypair(env("SAC006_PAYER_KEYPAIR_PATH")),
    loadKeypair(env("SAC006_SERVER_KEYPAIR_PATH")),
  ]);
  const mint = env("SAC006_ASSET_MINT") as Address;
  emit("context", {
    network: record.network.caip2,
    programId: record.programId,
    recordSha256: record.sha256,
    rpc: redactRpcUrl(rpcUrl),
    sponsor: sponsor.address,
    payer: payer.address,
    server: server.address,
    mint,
    confirmTimeoutMs,
  });
  return { record, ledger, rpcUrl, sponsor, payer, server, mint };
}

export type Snapshot = {
  label: string;
  clock: string;
  /** Finalized context slot of the token balance reads. */
  balanceSlot: string;
  payerAta: string;
  serverAta: string;
  payment?: { address: string; slot: string; exists: boolean; held?: string; refundable?: string; captureDeadline?: string; refundDeadline?: string };
};

/**
 * Finalized state: payer/server token balances with their context slot, the cluster Clock, and,
 * for a payment, its `(H,F)` and deadlines read at a finalized slot no older than `minSlot`.
 */
export async function snapshot(c: Context, label: string, payment?: Address, minSlot = 0n): Promise<Snapshot> {
  const balance = async (owner: Address) => {
    const read = await c.ledger.getAccountAtLeast(await ata(owner, c.mint), minSlot);
    if (read.kind !== "ok") throw new Error(`balance snapshot unavailable: ${read.detail}`);
    if (read.slot < minSlot) throw new Error("balance snapshot predates the required slot");
    if (!read.account || read.account.owner !== TOKEN_PROGRAM_ADDRESS) throw new Error("balance snapshot requires an existing classic SPL token account");
    const token = getTokenDecoder().decode(read.account.data);
    if (token.mint !== c.mint || token.owner !== owner || token.state !== AccountState.Initialized) throw new Error("balance snapshot token account is unusable or has substituted terms");
    return { slot: read.slot, amount: token.amount.toString() };
  };
  const [p, s, clock] = await Promise.all([balance(c.payer.address), balance(c.server.address), c.ledger.now()]);
  const snap: Snapshot = { label, clock: clock.toString(), balanceSlot: (p.slot < s.slot ? p.slot : s.slot).toString(), payerAta: p.amount, serverAta: s.amount };
  if (payment) {
    const read = await c.ledger.getAccountAtLeast(payment, minSlot);
    if (read.kind !== "ok") throw new Error(`payment snapshot unavailable: ${read.detail}`);
    if (read.slot < minSlot) throw new Error("payment snapshot predates the required slot");
    const decoded = read.account && read.account.owner === c.record.programId ? decodePayment(read.account.data) : undefined;
    snap.payment = decoded
      ? {
          address: payment,
          slot: read.slot.toString(),
          exists: true,
          held: decoded.held.toString(),
          refundable: decoded.refundable.toString(),
          captureDeadline: decoded.captureDeadline.toString(),
          refundDeadline: decoded.refundDeadline.toString(),
        }
      : { address: payment, slot: read.slot.toString(), exists: false };
  }
  emit("snapshot", snap);
  return snap;
}

/** Same balances and payment state: a rejected operation changed nothing it guards. */
export function unchanged(before: Snapshot, after: Snapshot): boolean {
  // A historical snapshot with missing/unknown balances cannot prove preservation either.
  if (![before.payerAta, before.serverAta, after.payerAta, after.serverAta].every((v) => /^(0|[1-9][0-9]*)$/.test(v))) return false;
  return (
    before.payerAta === after.payerAta &&
    before.serverAta === after.serverAta &&
    json(before.payment && { ...before.payment, slot: 0 }) === json(after.payment && { ...after.payment, slot: 0 })
  );
}

/** Success evidence must identify the exact signature's finalized slot, not a local clock. */
export async function finalizedSlot(c: Context, signature: string): Promise<bigint> {
  const status = await c.ledger.getSignatureStatus(signature);
  if (status.kind !== "found" || status.commitment !== "finalized" || status.err !== null) throw new Error("finalized success slot unavailable; evidence remains unknown");
  return status.slot;
}

/** Finalized history sets a read fence for the CLI's post-transaction payment snapshots. */
export async function paymentHistorySlot(c: Context, payment: Address): Promise<bigint> {
  const entries = await createSolanaRpc(c.rpcUrl).getSignaturesForAddress(payment, { commitment: "finalized", limit: 1 }).send({ abortSignal: AbortSignal.timeout(10_000) });
  if (entries.length !== 1) throw new Error("payment history unavailable; cannot fence a post-transaction snapshot");
  return entries[0]!.slot;
}

export async function waitForClock(c: Context, atLeast: bigint, why: string): Promise<bigint> {
  emit("waiting for cluster clock", { atLeast, why });
  let now = await c.ledger.now();
  while (now < atLeast) {
    await new Promise((r) => setTimeout(r, 3_000));
    now = await c.ledger.now();
  }
  emit("cluster clock reached", { clock: now, atLeast, why });
  return now;
}

export async function slotOf(c: Context, signature: string): Promise<string> {
  const s = await c.ledger.getSignatureStatus(signature);
  return s.kind === "found" ? `${s.slot}/${s.commitment}` : s.kind;
}
