// Validates a SAC-007 deployment-identity v1 record (contract: docs/evidence/sac-007/README.md)
// before the SAC-006 runtime trusts its network/program identity. Every v1 field is checked for
// presence, type, and format, together with the eligibility rules of a `verified` record. This
// module does not re-verify deployment evidence (that is SAC-007's verifier and its independent
// review); it only refuses a record that is incomplete, inconsistent, or not the accepted one.
//
// Linkage: the contract has SAC-006 pin the independently accepted record's exact Git revision
// and path externally. The JSON cannot name its own accepted commit, so the pin is the SHA-256 of
// the record file's bytes at that revision; a file whose bytes differ is rejected.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { type Address, isAddress, isSignature } from "@solana/kit";
import { isObject } from "./types.ts";

/** The independently accepted SAC-007 record this runtime is pinned to. */
export const ACCEPTED_DEPLOYMENT_RECORD = {
  revision: "333d87fbd777ceed89ce432a6fe2368639c9bbc2",
  path: "docs/evidence/sac-007/deployment-identity.v1.json",
  sha256: "f013c31e871c7b66812a8156b2f9bfef8b76dc14c1d77722512d952852d47b87",
  acceptance: "https://github.com/starPaw/capture402/pull/13#issuecomment-6020976687",
} as const;

export type DeploymentRecord = {
  network: { cluster: string; genesisHash: string; caip2: string };
  programId: Address;
  deployment: {
    loader: Address;
    programData: Address;
    upgradeAuthority: Address | null;
    slot: bigint;
    executableSha256: string;
    executableSize: number;
  };
  /** The pinned accepted record's SHA-256 this file matched (byte-exact, or after CRLF → LF). */
  sha256: string;
};

const UPGRADEABLE_LOADER = "BPFLoaderUpgradeab1e11111111111111111111111";
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const SHA256 = /^[0-9a-f]{64}$/;
const GIT_SHA = /^[0-9a-f]{40}$/;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
/** Template placeholders are deliberately invalid completed values (`<…>`). */
const PLACEHOLDER = /^<.*>$/s;

function fail(reason: string): never {
  throw new Error(`invalid deployment-identity record: ${reason}`);
}

function object(parent: Record<string, unknown>, key: string, at: string): Record<string, unknown> {
  const v = parent[key];
  if (!isObject(v)) fail(`${at}${key} is missing or not an object`);
  return v;
}

function text(parent: Record<string, unknown>, key: string, at: string, pattern?: RegExp): string {
  const v = parent[key];
  if (typeof v !== "string" || v.length === 0) fail(`${at}${key} is missing or not a non-empty string`);
  if (PLACEHOLDER.test(v)) fail(`${at}${key} is an unreplaced template placeholder`);
  if (pattern && !pattern.test(v)) fail(`${at}${key} is malformed: ${JSON.stringify(v)}`);
  return v;
}

function oneOf<T extends string>(parent: Record<string, unknown>, key: string, at: string, allowed: readonly T[]): T {
  const v = text(parent, key, at);
  if (!(allowed as readonly string[]).includes(v)) fail(`${at}${key} must be one of ${allowed.join("|")}, got ${JSON.stringify(v)}`);
  return v as T;
}

function address(parent: Record<string, unknown>, key: string, at: string): Address {
  const v = text(parent, key, at);
  if (!isAddress(v)) fail(`${at}${key} is not a complete base58 public key`);
  return v;
}

/** Slots, offsets, and sizes are unsigned decimal strings compared as integers (never `Number`). */
function decimal(parent: Record<string, unknown>, key: string, at: string): bigint {
  return BigInt(text(parent, key, at, DECIMAL));
}

function textArray(parent: Record<string, unknown>, key: string, at: string, { nonEmpty }: { nonEmpty: boolean }): string[] {
  const v = parent[key];
  if (!Array.isArray(v)) fail(`${at}${key} is missing or not an array`);
  if (nonEmpty && v.length === 0) fail(`${at}${key} must not be empty`);
  for (const [i, item] of v.entries()) {
    if (typeof item !== "string" || item.length === 0 || PLACEHOLDER.test(item)) fail(`${at}${key}[${i}] is not a completed non-empty string`);
  }
  return v as string[];
}

function publicHttpsUrl(value: string, at: string): void {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    fail(`${at} is not a URL`);
  }
  if (url.protocol !== "https:") fail(`${at} must be an HTTPS URL`);
  if (url.username || url.password || url.search || url.hash) fail(`${at} must not carry credentials, a query string, or a fragment`);
  // Providers also put keys in the path (`/v2/<key>`, `/<token>/`). A public identifier needs no
  // opaque path token, so a long token-like segment is treated as a credential.
  if (url.pathname.split("/").some((segment) => /^[A-Za-z0-9_-]{16,}$/.test(segment))) fail(`${at} has a token-like path segment; it may carry a credential`);
}

/**
 * Validates the complete v1 contract and the eligibility rules of a `verified` record, and
 * returns the identity the runtime consumes. Rejects a template, any placeholder, an unsupported
 * version, any missing/malformed field, an ineligible record, and inconsistent slots or hashes.
 */
export function parseDeploymentRecord(raw: unknown): Omit<DeploymentRecord, "sha256"> {
  if (!isObject(raw)) fail("record is not a JSON object");
  if (raw.schema_version !== 1) fail(`unsupported schema_version ${JSON.stringify(raw.schema_version)}`);
  if (raw.record_status !== "verified") fail(`record_status is ${JSON.stringify(raw.record_status)}, not "verified"`);

  const network = object(raw, "network", "");
  if (network.cluster !== "devnet") fail(`unsupported network.cluster ${JSON.stringify(network.cluster)}`);
  const genesisHash = text(network, "genesis_hash", "network.");
  if (!isAddress(genesisHash)) fail("network.genesis_hash is not a complete 32-byte base58 hash");
  const caip2 = text(network, "caip2", "network.");
  const expectedCaip2 = `solana:${genesisHash.slice(0, 32)}`;
  if (caip2 !== expectedCaip2) fail(`network.caip2 ${JSON.stringify(caip2)} does not equal ${JSON.stringify(expectedCaip2)}`);
  publicHttpsUrl(text(network, "public_rpc_identifier", "network."), "network.public_rpc_identifier");

  const program = object(raw, "program", "");
  const programId = address(program, "program_id", "program.");
  if (program.executable !== true) fail(`program.executable is ${JSON.stringify(program.executable)}, not boolean true`);
  const loader = address(program, "loader", "program.");
  if (program.program_data === null) {
    if (loader === UPGRADEABLE_LOADER) fail("program.program_data must be the ProgramData address for the upgradeable loader");
  } else {
    address(program, "program_data", "program.");
  }
  const authority = object(program, "upgrade_authority", "program.");
  const authorityStatus = oneOf(authority, "status", "program.upgrade_authority.", ["present", "absent", "unknown"] as const);
  if (authorityStatus === "unknown") fail("program.upgrade_authority.status is unknown; a verified record requires a known status");
  if (authorityStatus === "present") address(authority, "public_key", "program.upgrade_authority.");
  else if (authority.public_key !== null) fail("program.upgrade_authority.public_key must be null when the authority is absent");

  const build = object(raw, "build", "");
  text(build, "source_revision", "build.", GIT_SHA);
  text(build, "host", "build.");
  const versions = object(build, "pinned_versions", "build.");
  for (const key of ["solana_cli", "cargo_build_sbf", "platform_tools", "sbf_rustc"]) text(versions, key, "build.pinned_versions.");
  text(build, "sbf_architecture", "build.");
  textArray(build, "commands", "build.", { nonEmpty: true });
  const artifactSha256 = text(build, "artifact_sha256", "build.", SHA256);
  const artifactSize = decimal(build, "artifact_size_bytes", "build.");

  const deployment = object(raw, "deployment", "");
  const transactions = deployment.transactions;
  if (!Array.isArray(transactions) || transactions.length === 0) fail("deployment.transactions must be a non-empty array");
  let highestTransactionSlot = 0n;
  transactions.forEach((tx: unknown, i) => {
    const at = `deployment.transactions[${i}].`;
    if (!isObject(tx)) fail(`${at.slice(0, -1)} is not an object`);
    const signature = text(tx, "signature", at);
    if (!isSignature(signature)) fail(`${at}signature is not a complete base58 signature`);
    const commitment = oneOf(tx, "commitment", at, ["finalized", "confirmed", "processed", "unknown"] as const);
    const result = oneOf(tx, "result", at, ["success", "failure", "unknown"] as const);
    if (commitment !== "finalized" || result !== "success") fail(`${at.slice(0, -1)} is ${commitment}/${result}; a verified record requires finalized/success`);
    const slot = decimal(tx, "slot", at);
    if (slot > highestTransactionSlot) highestTransactionSlot = slot;
  });
  const deploymentSlot = decimal(deployment, "deployment_slot", "deployment.");

  const verification = object(raw, "verification", "");
  const observationSlot = decimal(verification, "observation_slot", "verification.");
  if (observationSlot < deploymentSlot || observationSlot < highestTransactionSlot) {
    fail("verification.observation_slot is earlier than the deployment slot or a listed transaction slot");
  }
  const observedAt = text(verification, "observed_at", "verification.", RFC3339_UTC);
  // Date.parse alone normalizes impossible days (for example February 30). Check the calendar
  // separately, then enforce RFC 3339's time ranges without accepting normalized dates.
  const [year, month, day, hour, minute, second] = observedAt.match(/\d+/g)!.slice(0, 6).map(Number) as [number, number, number, number, number, number];
  const calendar = new Date(`${observedAt.slice(0, 10)}T00:00:00Z`);
  if (!Number.isFinite(calendar.getTime()) || calendar.getUTCFullYear() !== year || calendar.getUTCMonth() + 1 !== month || calendar.getUTCDate() !== day || hour > 23 || minute > 59 || second > 60) {
    fail("verification.observed_at is not a valid RFC 3339 UTC calendar/time value");
  }
  const comparison = object(verification, "executable_comparison", "verification.");
  const cmpAt = "verification.executable_comparison.";
  text(comparison, "method", cmpAt);
  text(comparison, "loader_layout", cmpAt);
  decimal(comparison, "executable_offset_bytes", cmpAt);
  const comparedLength = decimal(comparison, "compared_length_bytes", cmpAt);
  decimal(comparison, "trailing_padding_bytes", cmpAt);
  text(comparison, "padding_handling", cmpAt);
  const deployedSha256 = text(comparison, "deployed_executable_sha256", cmpAt, SHA256);
  const comparisonResult = oneOf(comparison, "result", cmpAt, ["match", "mismatch", "unknown"] as const);
  if (comparisonResult !== "match") fail(`${cmpAt}result is ${comparisonResult}; a verified record requires match`);
  if (comparedLength !== artifactSize) fail(`${cmpAt}compared_length_bytes does not equal build.artifact_size_bytes`);
  if (deployedSha256 !== artifactSha256) fail(`${cmpAt}deployed_executable_sha256 does not equal build.artifact_sha256`);
  textArray(comparison, "limitations", cmpAt, { nonEmpty: false });
  for (const path of textArray(verification, "evidence_paths", "verification.", { nonEmpty: true })) {
    const outside = path.startsWith("/") || path.includes("\\") || /^[A-Za-z]:/.test(path) || path.split("/").includes("..");
    if (outside || /^[A-Za-z][A-Za-z0-9+.-]*:/.test(path) || path.split("/").some((part) => part.length === 0 || part === ".") || /[\x00-\x1f]/.test(path)) fail(`verification.evidence_paths entry ${JSON.stringify(path)} is not a relative path inside the evidence directory`);
  }

  if (loader !== UPGRADEABLE_LOADER || program.program_data === null) fail("runtime supports only the accepted upgradeable-loader layout");
  if (artifactSize <= 0n || artifactSize > 10_485_760n) fail("build.artifact_size_bytes is outside the supported executable size");
  return { network: { cluster: network.cluster, genesisHash, caip2 }, programId, deployment: {
    loader, programData: program.program_data as Address,
    upgradeAuthority: authorityStatus === "present" ? authority.public_key as Address : null,
    slot: deploymentSlot, executableSha256: artifactSha256, executableSize: Number(artifactSize),
  } };
}

/**
 * Loads the record at `path`, requires its bytes to hash to the pinned accepted record
 * (`ACCEPTED_DEPLOYMENT_RECORD.sha256`), and validates it. Callers cannot override acceptance.
 */
export function loadDeploymentRecord(path: string): DeploymentRecord {
  const expectedSha256 = ACCEPTED_DEPLOYMENT_RECORD.sha256;
  let bytes: Buffer;
  try {
    bytes = readFileSync(path);
  } catch (error) {
    fail(`cannot read ${path}: ${error instanceof Error ? error.message : String(error)}`);
  }
  // A checkout that converts line endings (core.autocrlf) changes bytes, not content: the pin also
  // matches the LF-normalized bytes, so CRLF is the only difference it tolerates.
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  const lfSha256 = createHash("sha256").update(bytes.toString("latin1").replace(/\r\n/g, "\n"), "latin1").digest("hex");
  if (sha256 !== expectedSha256 && lfSha256 !== expectedSha256) {
    fail(`${path} has SHA-256 ${sha256}, not the pinned accepted record ${expectedSha256} (${ACCEPTED_DEPLOYMENT_RECORD.path} at ${ACCEPTED_DEPLOYMENT_RECORD.revision})`);
  }
  let raw: unknown;
  try {
    raw = JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    fail(`cannot parse ${path}: ${error instanceof Error ? error.message : String(error)}`);
  }
  return { ...parseDeploymentRecord(raw), sha256: expectedSha256 };
}
