// Prints one finalized state snapshot (cluster Clock, payer/server token balances, and optionally a
// payment's (H,F) and deadlines) for `run-all.sh`.
//   node --experimental-strip-types evidence/snapshot.ts <label> [payment]
import type { Address } from "@solana/kit";
import { context, snapshot } from "./lib.ts";

const [label = "snapshot", payment] = process.argv.slice(2);
const c = await context();
await snapshot(c, label, payment as Address | undefined);
