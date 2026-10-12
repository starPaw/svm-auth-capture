// Tests for SAC-007 deployment-identity v1 record validation (SAC-006 consumer side) — no network
// access. The accepted record in this repository must load under the default pin; every
// incomplete, malformed, placeholder, ineligible, or inconsistent variant of it must be rejected,
// and a record whose bytes differ from the pinned accepted record is rejected even if valid.
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { getAddressEncoder, type Rpc, type SolanaRpcApi } from "@solana/kit";
import { RpcLedger } from "../src/rpc-ledger.ts";
import { ACCEPTED_DEPLOYMENT_RECORD, loadDeploymentRecord, parseDeploymentRecord } from "../src/deployment-record.js";

const ACCEPTED_PATH = fileURLToPath(new URL(`../../${ACCEPTED_DEPLOYMENT_RECORD.path}`, import.meta.url));
const accepted = (): Record<string, any> => JSON.parse(readFileSync(ACCEPTED_PATH, "utf8"));

function writeRecord(record: unknown): { path: string } {
  const path = join(mkdtempSync(join(tmpdir(), "sac006-record-")), "deployment-identity.v1.json");
  const text = JSON.stringify(record, null, 2);
  writeFileSync(path, text);
  return { path };
}

/** Applies `mutate` to a copy of the accepted record and expects validation to reject it. */
function rejects(mutate: (r: Record<string, any>) => void, reason: RegExp): void {
  const r = accepted();
  mutate(r);
  expect(() => parseDeploymentRecord(r)).toThrow(reason);
}

describe("the accepted SAC-007 record", () => {
  test.each(["matching", "byte", "padding", "slot", "authority", "pointer", "loader", "executable", "stale"])("live deployment comparison: %s", async (mutation) => {
    const record = loadDeploymentRecord(ACCEPTED_PATH);
    const pin = record.deployment;
    const p = new Uint8Array(36);
    new DataView(p.buffer).setUint32(0, 2, true);
    p.set(getAddressEncoder().encode(pin.programData), 4);
    const binary = readFileSync(new URL("../../docs/evidence/sac-007/build-candidate/svm_auth_capture.so", import.meta.url));
    const d = new Uint8Array(45 + binary.length + 8);
    const view = new DataView(d.buffer);
    view.setUint32(0, 3, true); view.setBigUint64(4, pin.slot, true);
    d[12] = 1; d.set(getAddressEncoder().encode(pin.upgradeAuthority!), 13); d.set(binary, 45);
    if (mutation === "byte") d[45] = d[45]! ^ 1;
    if (mutation === "padding") d[d.length - 1] = 1;
    if (mutation === "slot") view.setBigUint64(4, pin.slot + 1n, true);
    if (mutation === "authority") d[13] = d[13]! ^ 1;
    if (mutation === "pointer") p[4] = p[4]! ^ 1;
    const account = (data: Uint8Array, executable: boolean) => ({ owner: pin.loader, executable, lamports: 1n, data: [Buffer.from(data).toString("base64"), "base64"] });
    const program = account(p, true);
    if (mutation === "loader") program.owner = record.programId;
    if (mutation === "executable") program.executable = false;
    const rpc = { getGenesisHash: () => ({ send: async () => record.network.genesisHash }), getMultipleAccounts: () => ({ send: async () => ({
      context: { slot: mutation === "stale" ? pin.slot - 1n : pin.slot }, value: [program, account(d, false)],
    }) }) } as unknown as Rpc<SolanaRpcApi>;
    const check = new RpcLedger({ deployment: record, network: record.network.caip2, genesisHash: record.network.genesisHash, rpcUrl: "http://unused.invalid", rpc }).verifyGenesis();
    if (mutation === "matching") await expect(check).resolves.toBeUndefined();
    else await expect(check).rejects.toThrow(/deployment/);
  });

  test("startup must reject a missing or upgraded live program even when genesis and record match", async () => {
    const record = loadDeploymentRecord(ACCEPTED_PATH);
    const config = { network: record.network.caip2, genesisHash: record.network.genesisHash, rpcUrl: "http://unused.invalid", deployment: record,
      rpc: { getGenesisHash: () => ({ send: async () => record.network.genesisHash }), getMultipleAccounts: () => ({ send: async () => ({ context: { slot: 600000000n }, value: [null, null] }) }) } as unknown as Rpc<SolanaRpcApi> };
    await expect(new RpcLedger(config).verifyGenesis()).rejects.toThrow(/deployment/);
  });
  test("loads under the default pin and yields the consumed identity", () => {
    const record = loadDeploymentRecord(ACCEPTED_PATH);
    expect(record).toMatchObject({
      network: { cluster: "devnet", genesisHash: "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG", caip2: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1" },
      programId: "992QmwmwCebawRJsTCgvc8qnzGivbFaD39ZQE7VhHp7o",
      sha256: ACCEPTED_DEPLOYMENT_RECORD.sha256,
    });
  });

  test("a valid record whose bytes differ from the pinned accepted record is rejected", () => {
    const { path } = writeRecord(accepted()); // same content, different serialization
    expect(() => loadDeploymentRecord(path)).toThrow(/not the pinned accepted record/);
  });

  test("a CRLF checkout of the accepted record still matches the pin", () => {
    const path = join(mkdtempSync(join(tmpdir(), "sac006-record-")), "deployment-identity.v1.json");
    writeFileSync(path, readFileSync(ACCEPTED_PATH, "utf8").replace(/\n/g, "\r\n"));
    expect(loadDeploymentRecord(path).sha256).toBe(ACCEPTED_DEPLOYMENT_RECORD.sha256);
  });

  test("callers cannot substitute another acceptance hash", () => {
    const { path } = writeRecord(accepted());
    // Untyped JavaScript callers passing the old options argument cannot bypass the pin.
    expect(() => Reflect.apply(loadDeploymentRecord, undefined, [path, { expectedSha256: "0".repeat(64) }])).toThrow(/pinned accepted record/);
  });

  test("an unreadable or malformed file is rejected", () => {
    expect(() => loadDeploymentRecord(join(tmpdir(), "sac006-no-such-record.json"))).toThrow(/cannot read/);
    const path = join(mkdtempSync(join(tmpdir(), "sac006-record-")), "bad.json");
    writeFileSync(path, "{not json");
    expect(() => loadDeploymentRecord(path)).toThrow(/pinned accepted record/);
    expect(() => parseDeploymentRecord(null)).toThrow(/not a JSON object/);
  });
});

describe("incomplete records are rejected", () => {
  test.each([
    ["build", (r: Record<string, any>) => delete r.build],
    ["deployment", (r: Record<string, any>) => delete r.deployment],
    ["verification", (r: Record<string, any>) => delete r.verification],
    ["program.upgrade_authority", (r: Record<string, any>) => delete r.program.upgrade_authority],
    ["program.loader", (r: Record<string, any>) => delete r.program.loader],
    ["network.public_rpc_identifier", (r: Record<string, any>) => delete r.network.public_rpc_identifier],
    ["build.pinned_versions.sbf_rustc", (r: Record<string, any>) => delete r.build.pinned_versions.sbf_rustc],
    ["build.commands", (r: Record<string, any>) => (r.build.commands = [])],
    ["deployment.transactions", (r: Record<string, any>) => (r.deployment.transactions = [])],
    ["verification.executable_comparison.limitations", (r: Record<string, any>) => delete r.verification.executable_comparison.limitations],
    ["verification.evidence_paths", (r: Record<string, any>) => (r.verification.evidence_paths = [])],
  ])("missing %s", (_field, mutate) => {
    expect(() => {
      const r = accepted();
      mutate(r);
      parseDeploymentRecord(r);
    }).toThrow(/invalid deployment-identity record/);
  });

  test("the unpopulated template", () => {
    const template = JSON.parse(readFileSync(ACCEPTED_PATH.replace(".v1.json", ".v1.template.json"), "utf8"));
    expect(() => parseDeploymentRecord(template)).toThrow(/record_status is "template"/);
    template.record_status = "verified";
    expect(() => parseDeploymentRecord(template)).toThrow(/placeholder|malformed|not boolean true/);
  });
});

describe("malformed fields are rejected", () => {
  test.each(["build", "deployment", "verification"])("corrupted %s object", (key) => rejects((r) => (r[key] = "corrupted"), /not an object/));
  test("corrupted authority object", () => rejects((r) => (r.program.upgrade_authority = []), /not an object/));
  test.each(["1".repeat(31), "z".repeat(44), "1".repeat(64)])("incomplete or oversized genesis %#", (value) => rejects((r) => (r.network.genesis_hash = value), /genesis_hash/));
  test.each(["2026-02-30T12:00:00Z", "2026-13-01T12:00:00Z", "2026-10-07T24:00:00Z", "2026-10-07T12:60:00Z"])("impossible timestamp %s", (value) => rejects((r) => (r.verification.observed_at = value), /observed_at/));
  test("unsupported version", () => rejects((r) => (r.schema_version = "1"), /schema_version/));
  test("non-devnet cluster", () => rejects((r) => (r.network.cluster = "mainnet-beta"), /cluster/));
  test("CAIP-2 mismatch", () => rejects((r) => (r.network.caip2 = "solana:wrong"), /does not equal/));
  test("credential-bearing RPC identifier", () => rejects((r) => (r.network.public_rpc_identifier = "https://rpc.example/?api-key=x"), /credentials/));
  test("non-HTTPS RPC identifier", () => rejects((r) => (r.network.public_rpc_identifier = "http://rpc.example"), /HTTPS/));
  test("RPC identifier with a key in its path", () => rejects((r) => (r.network.public_rpc_identifier = "https://solana-devnet.g.alchemy.com/v2/abc123secretKEY987"), /token-like path/));
  test("RPC identifier with a fragment", () => rejects((r) => (r.network.public_rpc_identifier = "https://rpc.example/#key"), /fragment/));
  test("abbreviated program id", () => rejects((r) => (r.program.program_id = "992Qmwmw"), /program_id/));
  test("placeholder value", () => rejects((r) => (r.build.host = "<BUILD_HOST_OS_AND_ARCHITECTURE>"), /placeholder/));
  test("short source revision", () => rejects((r) => (r.build.source_revision = "da3312b"), /source_revision/));
  test("uppercase SHA-256", () => rejects((r) => (r.build.artifact_sha256 = r.build.artifact_sha256.toUpperCase()), /artifact_sha256/));
  test("numeric slot instead of a decimal string", () => rejects((r) => (r.deployment.deployment_slot = 508146249), /deployment_slot/));
  test("abbreviated transaction signature", () => rejects((r) => (r.deployment.transactions[0].signature = "4S1sEL2c"), /signature/));
  test("non-UTC observation time", () => rejects((r) => (r.verification.observed_at = "2026-10-06 16:06:48"), /observed_at/));
  test.each(["../secrets.json", "/etc/passwd", "..\\secrets.json", "C:/test/key.json", "https://example.com/evidence", "./", "snapshots//account.json", "snapshots/\u0000account.json"])("evidence path %# escaping the directory", (bad) =>
    rejects((r) => r.verification.evidence_paths.push(bad), /evidence_paths/),
  );
});

describe("ineligible or inconsistent verified records are rejected", () => {
  test("executable not observed true", () => rejects((r) => (r.program.executable = "true"), /not boolean true/));
  test("unknown upgrade authority", () => rejects((r) => ((r.program.upgrade_authority = { status: "unknown", public_key: null })), /unknown/));
  test("absent authority with a key", () => rejects((r) => (r.program.upgrade_authority.status = "absent"), /must be null/));
  test("upgradeable loader without ProgramData", () => rejects((r) => (r.program.program_data = null), /ProgramData/));
  test("a deployment transaction below finalized", () => rejects((r) => (r.deployment.transactions[3].commitment = "confirmed"), /finalized\/success/));
  test("a failed deployment transaction", () => rejects((r) => (r.deployment.transactions[3].result = "failure"), /finalized\/success/));
  test("observation slot before the deployment slot", () => rejects((r) => (r.verification.observation_slot = "508146248"), /observation_slot/));
  test("executable comparison not match", () => rejects((r) => (r.verification.executable_comparison.result = "unknown"), /requires match/));
  test("compared length differs from the artifact size", () => rejects((r) => (r.verification.executable_comparison.compared_length_bytes = "116703"), /compared_length_bytes/));
  test("deployed hash differs from the artifact hash", () => rejects((r) => (r.verification.executable_comparison.deployed_executable_sha256 = "0".repeat(64)), /deployed_executable_sha256/));
});

// The accepted producer template is the required-field inventory, rather than a second schema.
const template = JSON.parse(readFileSync(ACCEPTED_PATH.replace(".v1.json", ".v1.template.json"), "utf8"));
function requiredPaths(value: unknown, prefix: string[] = []): string[][] {
  if (!value || typeof value !== "object") return [];
  const entries = Array.isArray(value) ? (value.length ? [["0", value[0]] as const] : []) : Object.entries(value);
  return entries.flatMap(([key, child]) => {
    const path = [...prefix, key];
    return [...(Array.isArray(value) ? [] : [path]), ...requiredPaths(child, path)];
  });
}
test.each(requiredPaths(template).map(path => [path.join("."), path] as const))("v1 required field %s cannot be omitted", (_label, path) => {
  rejects(r => {
    const parent = path.slice(0, -1).reduce((value, key) => value[key], r);
    delete parent[path.at(-1)!];
  }, /invalid deployment-identity record/);
});
