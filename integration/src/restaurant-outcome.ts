// Explicit operator-only interface. Never registered at application startup or as an HTTP route.
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
export async function restaurantOutcomeMain(argv: readonly string[] = process.argv.slice(2)): Promise<void> {
  const [verb,id,action,signature,digest] = argv;
  if (argv.length !== 5 || verb !== "apply" || !/^[a-f0-9]{32}$/.test(id ?? "") || !["beer","salmon"].includes(action ?? "") ||
      !/^[1-9A-HJ-NP-Za-km-z]{64,88}$/.test(signature ?? "") || !/^[a-f0-9]{64}$/.test(digest ?? "")) {
    throw new Error("usage: restaurant-outcome.ts apply <order-id> <beer|salmon> <original-signature> <evidence-digest>");
  }
  // There is intentionally no env/flag/JSON/true bypass. A future live issuer needs separate
  // accepted host inventory/enrollment and authority; this release cannot repair live stores.
  throw new Error("Outcome application refused: no trusted live enrollment verifier is installed (one-UID profile only).");
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  restaurantOutcomeMain().catch(error => { console.error((error as Error).message); process.exitCode = 1; });
}
