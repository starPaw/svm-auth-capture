// Run from integration: node --experimental-strip-types src/restaurant-reconcile.ts <order-id>
// Public deployment/network identities only; no signer key, bearer or capability is loaded.
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { loadDeploymentRecord } from "./deployment-record.ts";
import { RpcLedger } from "./rpc-ledger.ts";
import { reconcileRestaurantOrder } from "./restaurant-reconciliation.ts";

export async function restaurantReconcileMain(
  argv: readonly string[] = process.argv.slice(2),
  env: NodeJS.ProcessEnv = process.env,
  output: (text: string) => void = console.log,
): Promise<void> {
  const id = argv[0];
  if (argv.length !== 1 || !id || !/^[a-f0-9]{32}$/.test(id)) throw new Error("usage: restaurant-reconcile.ts <32-character hex order-id>");
  const requireEnv = (name: string) => { const value = env[name]; if (!value) throw new Error("reconciliation configuration incomplete"); return value; };
  const ordersDir = env.SAC006_RESTAURANT_ORDERS_DIR ?? `${requireEnv("SAC006_STORE_DIR")}-restaurant`;
  const record = loadDeploymentRecord(requireEnv("SAC006_DEPLOYMENT_RECORD_PATH"));
  const ledger = new RpcLedger({ deployment: record, network: record.network.caip2, genesisHash: record.network.genesisHash, rpcUrl: requireEnv("SOLANA_RPC_URL") });
  await ledger.verifyGenesis();
  const report = await reconcileRestaurantOrder({
    ordersDir, orderId: id, programId: record.programId, network: record.network.caip2, reader: ledger,
    journalDirs: [env.SAC006_FACILITATOR_JOURNAL_DIR, env.SAC006_RECLAIM_JOURNAL_DIR ??
      (env.SAC006_STORE_DIR ? `${env.SAC006_STORE_DIR}-restaurant-reclaim` : undefined)].filter((d): d is string => !!d),
  });
  output(JSON.stringify({ ...report, network: record.network.caip2, genesisHash: record.network.genesisHash,
    programId: record.programId, deploymentRecordSha256: record.sha256, observedAt: new Date().toISOString() }, null, 2));
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  restaurantReconcileMain().catch(() => {
    console.error("Restaurant reconciliation could not read valid local or chain evidence; no recovery was performed.");
    process.exitCode = 1;
  });
}
