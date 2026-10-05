// Raw Compute Budget instructions (SetComputeUnitLimit=2:u32, SetComputeUnitPrice=3:u64).
import type { Instruction } from "@solana/kit";
import { COMPUTE_BUDGET_PROGRAM_ADDRESS } from "../src/facilitator.js";

export function getSetComputeUnitLimitInstruction(units: number): Instruction {
  const data = new Uint8Array(5);
  data[0] = 2;
  new DataView(data.buffer).setUint32(1, units, true);
  return { programAddress: COMPUTE_BUDGET_PROGRAM_ADDRESS, data };
}

export function getSetComputeUnitPriceInstruction(microLamports: bigint): Instruction {
  const data = new Uint8Array(9);
  data[0] = 3;
  new DataView(data.buffer).setBigUint64(1, microLamports, true);
  return { programAddress: COMPUTE_BUDGET_PROGRAM_ADDRESS, data };
}
