// Manual reconciliation command (SAC-006 gap #3). Inspects an `OperationStore` entry and the
// live chain state for its payment identity, and prints both. Never resubmits, re-signs, or
// marks anything resolved on its own: an unresolved outcome stays `pending`, and only an
// operator decides, from the printed evidence, what the real outcome was and whether/how to
// update the record.
import { loadDeploymentRecord } from "./deployment-record.ts";
import { OperationStore, reconcileEntry } from "./operation-store.ts";
import { RpcLedger } from "./rpc-ledger.ts";

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`missing required environment variable ${name}`);
  return value;
}

const replacer = (_k: string, v: unknown) => (typeof v === "bigint" ? v.toString() : v);

async function main(): Promise<void> {
  const dir = requireEnv("SAC006_STORE_DIR");
  const store = new OperationStore(dir);
  const fp = process.argv[2];

  if (!fp) {
    const pending = store.pending();
    console.log(`${pending.length} pending entries:`);
    for (const r of pending) console.log(`  ${r.fingerprint}  status=${r.status}  caller=${r.caller}  resource=${r.resource}`);
    console.log("usage: node reconcile.ts <fingerprint>   to inspect one entry against live chain state");
    return;
  }

  const record = loadDeploymentRecord(requireEnv("SAC006_DEPLOYMENT_RECORD_PATH"));
  const ledger = new RpcLedger({ network: record.network.caip2, genesisHash: record.network.genesisHash, rpcUrl: requireEnv("SOLANA_RPC_URL") });
  await ledger.verifyGenesis();
  const result = await reconcileEntry(store, ledger, record.programId, fp);
  console.log(JSON.stringify(result, replacer, 2));
}

if (process.argv[1]?.endsWith("reconcile.ts")) {
  main().catch((error) => {
    console.error(error instanceof Error ? (error.stack ?? error.message) : String(error));
    process.exitCode = 1;
  });
}
