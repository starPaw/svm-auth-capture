// Prints one finalized state snapshot (cluster Clock, payer/server token balances, and optionally a
// payment's (H,F) and deadlines) for `run-all.sh`.
//   node --experimental-strip-types evidence/snapshot.ts <label> [payment]
import type { Address } from "@solana/kit";
import { context, paymentHistorySlot, snapshot } from "./lib.ts";

const [label = "snapshot", payment] = process.argv.slice(2);
const c = await context();
const address = payment as Address | undefined;
await snapshot(c, label, address, address ? await paymentHistorySlot(c, address) : 0n);
