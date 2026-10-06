// Shared helpers for the SAC-006 live Devnet evidence drivers (`run-all.sh`). Drivers call only
// committed `src/` modules. Nothing here prints the RPC URL, a keypair path, or a secret: keys are
// identified by public key, and the RPC only through `redactRpcUrl`.
import { appendFileSync, readFileSync } from "node:fs";
import { type Address, createKeyPairSignerFromBytes, createSolanaRpc, type KeyPairSigner } from "@solana/kit";
import { loadDeploymentRecord, type DeploymentRecord } from "../src/deployment-record.ts";
import { ata, decodePayment } from "../src/program.ts";
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
  const ledger = new RpcLedger({ network: record.network.caip2, genesisHash: record.network.genesisHash, rpcUrl });
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
  const rpc = createSolanaRpc(c.rpcUrl);
  const balance = async (owner: Address) => {
    const signal = AbortSignal.timeout(10_000);
    try {
      const { context, value } = await rpc.getTokenAccountBalance(await ata(owner, c.mint), { commitment: "finalized" }).send({ abortSignal: signal });
      return { slot: BigInt(context.slot), amount: value.amount as string };
    } catch {
      return { slot: 0n, amount: "absent" };
    }
  };
  const [p, s, clock] = await Promise.all([balance(c.payer.address), balance(c.server.address), c.ledger.now()]);
  const snap: Snapshot = { label, clock: clock.toString(), balanceSlot: (p.slot < s.slot ? p.slot : s.slot).toString(), payerAta: p.amount, serverAta: s.amount };
  if (payment) {
    const read = await c.ledger.getAccountAtLeast(payment, minSlot);
    if (read.kind !== "ok") throw new Error(`payment snapshot unavailable: ${read.detail}`);
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
  return (
    before.payerAta === after.payerAta &&
    before.serverAta === after.serverAta &&
    json(before.payment && { ...before.payment, slot: 0 }) === json(after.payment && { ...after.payment, slot: 0 })
  );
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
