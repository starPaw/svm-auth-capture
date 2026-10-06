// Validates a SAC-007 deployment-identity v1 record (contract:
// docs/evidence/sac-007/README.md) before the SAC-006 runtime trusts its network/program
// identity. This module only checks shape, version, and the record's own internal
// consistency; it does not re-verify deployment evidence, and it does not substitute for the
// externally pinned Git revision + independent ACCEPT the contract requires. Callers must pin
// and pass the path to that exact accepted revision's file.
import { readFileSync } from "node:fs";
import type { Address } from "@solana/kit";

export type DeploymentRecord = {
  network: { cluster: string; genesisHash: string; caip2: string };
  programId: Address;
};

function fail(reason: string): never {
  throw new Error(`invalid deployment-identity record: ${reason}`);
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const BASE58 = /^[1-9A-HJ-NP-Za-km-z]+$/;

/**
 * Loads and validates a v1 deployment-identity JSON file from disk. Enforces the producer
 * contract's acceptance preconditions: schema version 1, `record_status: "verified"`, exact
 * CAIP-2 derivation from the full genesis hash, and `program.executable === true`. Rejects a
 * template, an unsupported version, or any missing/malformed required field.
 */
export function loadDeploymentRecord(path: string): DeploymentRecord {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    fail(`cannot read or parse ${path}: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!isObject(raw)) fail("record is not a JSON object");
  if (raw.schema_version !== 1) fail(`unsupported schema_version ${JSON.stringify(raw.schema_version)}`);
  if (raw.record_status !== "verified") fail(`record_status is ${JSON.stringify(raw.record_status)}, not "verified"`);

  const network = raw.network;
  if (!isObject(network)) fail("missing network");
  if (network.cluster !== "devnet") fail(`unsupported network.cluster ${JSON.stringify(network.cluster)}`);
  const genesisHash = network.genesis_hash;
  if (typeof genesisHash !== "string" || !BASE58.test(genesisHash)) fail("network.genesis_hash is not a base58 string");
  const caip2 = network.caip2;
  const expectedCaip2 = `solana:${genesisHash.slice(0, 32)}`;
  if (caip2 !== expectedCaip2) fail(`network.caip2 ${JSON.stringify(caip2)} does not equal ${JSON.stringify(expectedCaip2)}`);

  const program = raw.program;
  if (!isObject(program)) fail("missing program");
  const programId = program.program_id;
  if (typeof programId !== "string" || !BASE58.test(programId)) fail("program.program_id is not a base58 string");
  if (program.executable !== true) fail(`program.executable is ${JSON.stringify(program.executable)}, not boolean true`);

  return { network: { cluster: network.cluster, genesisHash, caip2 }, programId: programId as Address };
}
