// Waits until the cluster Clock (not wall time) reaches a deadline, for `run-all.sh`.
//   node --experimental-strip-types evidence/wait-clock.ts <unix-seconds> <why>
import { context, waitForClock } from "./lib.ts";

const [atLeast, why = "deadline"] = process.argv.slice(2);
if (!atLeast || !/^[0-9]+$/.test(atLeast)) throw new Error("usage: wait-clock.ts <unix-seconds> <why>");
await waitForClock(await context(), BigInt(atLeast), why);
