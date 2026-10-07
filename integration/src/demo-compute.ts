// Restaurant-only fee policy. Compile all fee instructions before any economic/sponsor signature.
import type { Address, Instruction } from "@solana/kit";
import type { Ledger } from "./ledger.ts";
import { buildTransaction } from "./transactions.ts";
export const DEMO_COMPUTE = Object.freeze({ maxUnitLimit: 200_000, unitPriceMicroLamports: 100_000, maxPriorityFeeLamports: 20_000, marginPercent: 10, roundingUnits: 1_000, minUnitLimit: 10_000 });
export const COMPUTE_PROGRAM = "ComputeBudget111111111111111111111111111111" as Address;
/** Explicit per-transaction priority-fee exposure ceiling; excludes base fee and rent. */
export function demoPriorityFeeLamports(units: number, price = BigInt(DEMO_COMPUTE.unitPriceMicroLamports)): bigint {
  if (!Number.isSafeInteger(units) || units < 0 || price < 0n) throw new Error("invalid demo priority fee inputs");
  const fee = (BigInt(units) * price + 999_999n) / 1_000_000n;
  if (fee > BigInt(DEMO_COMPUTE.maxPriorityFeeLamports)) throw new Error("demo priority fee exceeds explicit exposure bound");
  return fee;
}
/** Same independent limit/price ceilings at the private Devnet facilitator; defaults elsewhere stay unchanged. */
export function demoSponsorComputeBounds() {
  demoPriorityFeeLamports(DEMO_COMPUTE.maxUnitLimit);
  return { maxComputeUnitLimit: DEMO_COMPUTE.maxUnitLimit, maxComputeUnitPriceMicroLamports: BigInt(DEMO_COMPUTE.unitPriceMicroLamports) };
}
export function demoComputeInstructions(units: number): Instruction[] {
  if (!Number.isSafeInteger(units) || units < DEMO_COMPUTE.minUnitLimit || units > DEMO_COMPUTE.maxUnitLimit) throw new Error("demo compute limit outside bound");
  demoPriorityFeeLamports(units);
  const limit = new Uint8Array(5); limit[0] = 2; new DataView(limit.buffer).setUint32(1,units,true);
  const price = new Uint8Array(9); price[0] = 3; new DataView(price.buffer).setBigUint64(1,BigInt(DEMO_COMPUTE.unitPriceMicroLamports),true);
  return [{ programAddress:COMPUTE_PROGRAM, data:limit }, { programAddress:COMPUTE_PROGRAM, data:price }];
}
export function demoComputeLimit(consumed: bigint): number {
  if (consumed <= 0n || consumed > BigInt(DEMO_COMPUTE.maxUnitLimit)) throw new Error("invalid simulation compute consumption");
  const rounded = Number(((consumed * 110n + 99n) / 100n + 999n) / 1_000n * 1_000n);
  const units = Math.max(DEMO_COMPUTE.minUnitLimit,rounded);
  if (units > DEMO_COMPUTE.maxUnitLimit) throw new Error("simulation plus safety margin exceeds demo compute bound");
  return units;
}
export async function buildDemoTransaction(a: Parameters<typeof buildTransaction>[0], ledger: Pick<Ledger,"simulate">) {
  if (a.instructions.some(ix => ix.programAddress === COMPUTE_PROGRAM)) throw new Error("compute budget is finalized by demo policy only");
  // No signer signs the measurement probe. It uses the intended blockhash and bounded budget.
  const probe = await buildTransaction({ ...a, signers:[], instructions:[...demoComputeInstructions(DEMO_COMPUTE.maxUnitLimit),...a.instructions] });
  const simulation = await ledger.simulate(probe);
  if (!simulation.ok || simulation.unitsConsumed === undefined) throw new Error("successful compute measurement required before signing");
  const instructions = [...demoComputeInstructions(demoComputeLimit(simulation.unitsConsumed)),...a.instructions];
  // buildTransaction compiles this complete message before applying a.signers; no post-sign mutation.
  return buildTransaction({ ...a, instructions });
}
