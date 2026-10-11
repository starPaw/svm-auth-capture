import { withShared } from "./coordination.ts";
// Manual reconciliation command (SAC-006 gap #3). Lists every unresolved `OperationStore` record,
// or reports for one record what happened to its original transactions (`reconciliation.ts`).
// Never resubmits, re-signs, or marks anything resolved on its own: an operator decides, from
// the printed evidence, what the real outcome was and whether/how to update the record.
import { loadDeploymentRecord } from "./deployment-record.ts";
import { OperationStore } from "./operation-store.ts";
import { type JournalLookup, reconcileEntry } from "./reconciliation.ts";
import { RpcLedger } from "./rpc-ledger.ts";
import { FileSubmissionJournal } from "./submission-journal.ts";

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`missing required environment variable ${name}`);
  return value;
}

const replacer = (_k: string, v: unknown) => (typeof v === "bigint" ? v.toString() : v);

async function main(): Promise<void> {
  const store = new OperationStore(requireEnv("SAC006_STORE_DIR"));
  await withShared(store.coordination, async () => inspectStore(store));
}

async function inspectStore(store: OperationStore): Promise<void> {
  store.assertAccess();
  const fp = process.argv[2];

  if (!fp) {
    const unresolved = store.unresolved();
    console.log(`${unresolved.length} unresolved entries:`);
    for (const r of unresolved) console.log(`  ${r.fingerprint}  status=${r.status}  caller=${r.caller}  resource=${r.resource}`);
    console.log("usage: node reconcile.ts <fingerprint>   to inspect one entry against live chain state");
    return;
  }

  const record = loadDeploymentRecord(requireEnv("SAC006_DEPLOYMENT_RECORD_PATH"));
  const ledger = new RpcLedger({ deployment: record, network: record.network.caip2, genesisHash: record.network.genesisHash, rpcUrl: requireEnv("SOLANA_RPC_URL") });
  await ledger.verifyGenesis();
  // Optional: the facilitator's pre-broadcast journal identifies a signature whose receipt was lost.
  const journalDir = process.env.SAC006_FACILITATOR_JOURNAL_DIR;
  const facilitatorJournal = journalDir ? new FileSubmissionJournal(journalDir, { create: false }) : undefined;
  const journal: JournalLookup | undefined = facilitatorJournal
    ? (hash) => facilitatorJournal.findByMessageHash(hash).map((e) => e.signature)
    : undefined;
  const report = await reconcileEntry(store, ledger, record.programId, fp, journal);
  console.log(JSON.stringify(report, replacer, 2));
}

if (process.argv[1]?.endsWith("reconcile.ts")) {
  main().catch((error) => {
    console.error(error instanceof Error ? (error.stack ?? error.message) : String(error));
    process.exitCode = 1;
  });
}
