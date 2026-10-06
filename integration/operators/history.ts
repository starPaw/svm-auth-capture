// Read-only attribution report for one evidence run: every payment PDA the run touched (taken from
// its events), with every finalized transaction that references it (signature, slot, error, block
// time). Written to `$SAC006_EVIDENCE_DIR/reports/history.json` by `run-all.sh`.
//   node --experimental-strip-types evidence/history.ts
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { type Address, createSolanaRpc } from "@solana/kit";
import { context, emit, env } from "./lib.ts";

const c = await context();
const dir = env("SAC006_EVIDENCE_DIR");
const payments = new Set<string>();
const collect = (v: unknown): void => {
  if (Array.isArray(v)) v.forEach(collect);
  else if (v && typeof v === "object") {
    for (const [k, x] of Object.entries(v)) {
      if (k === "payment" && typeof x === "string") payments.add(x);
      else if (k === "payment" && x && typeof x === "object" && typeof (x as { address?: unknown }).address === "string") payments.add((x as { address: string }).address);
      collect(x);
    }
  }
};
for (const line of readFileSync(join(dir, "events.jsonl"), "utf8").split("\n")) if (line) collect(JSON.parse(line));

const rpc = createSolanaRpc(c.rpcUrl);
const history: Record<string, { signature: string; slot: string; err: unknown; blockTime: string | null }[]> = {};
for (const payment of [...payments].sort()) {
  const entries = await rpc.getSignaturesForAddress(payment as Address, { commitment: "finalized", limit: 50 }).send({ abortSignal: AbortSignal.timeout(15_000) });
  history[payment] = entries
    .map((e) => ({ signature: e.signature, slot: e.slot.toString(), err: e.err, blockTime: e.blockTime === null ? null : e.blockTime.toString() }))
    .sort((a, b) => Number(BigInt(a.slot) - BigInt(b.slot)));
}
writeFileSync(join(dir, "reports", "history.json"), JSON.stringify(history, null, 2));
emit("history", { payments: payments.size, transactions: Object.values(history).reduce((n, h) => n + h.length, 0) });
