// Prints the role public keys derived from the configured keypair files as shell assignments,
// so `run-all.sh` never needs to read or echo a secret key itself.
import { env, loadKeypair } from "./lib.ts";

const [sponsor, payer, server] = await Promise.all(
  ["SAC006_FACILITATOR_KEYPAIR_PATH", "SAC006_PAYER_KEYPAIR_PATH", "SAC006_SERVER_KEYPAIR_PATH"].map((n) => loadKeypair(env(n))),
);
console.log(`SPONSOR=${sponsor!.address}\nPAYER=${payer!.address}\nSERVER=${server!.address}`);
