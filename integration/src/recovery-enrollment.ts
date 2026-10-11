// Admission is a capability issued by a trusted implementation, not caller metadata/true.
// No live issuer exists. The only issuer owns a NEW disposable synthetic namespace.
import { mkdirSync, mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Address } from "@solana/kit";
import { enrollRecoveryDomain, type CoordinationToken, type DomainPaths, type RecoveryDomain } from "./coordination.ts";
import { DOMAIN_ROLES } from "./coordination-schema.ts";
import { LOCAL_PROGRAM_ID } from "./program.ts";
export const FIXTURE_NETWORK = "solana:outcome-apply-fixture";
export const FIXTURE_GENESIS = "11111111111111111111111111111111";
export type RecoveryIdentity = { network: string; genesisHash: string; programId: Address };
export type RecoveryEnrollment = Readonly<{ profile: "isolated-one-uid-fixture" }>;
const grants = new WeakMap<RecoveryEnrollment, { domain: RecoveryDomain; uid: number; identity: RecoveryIdentity }>();
export function verifyRecoveryEnrollment(grant: RecoveryEnrollment | undefined, token: CoordinationToken, identity: RecoveryIdentity): void {
  const proof = grant && grants.get(grant);
  if (!proof || token.mode !== "exclusive" || proof.domain !== token.domain || proof.uid !== process.getuid!() ||
      JSON.stringify(proof.identity) !== JSON.stringify(identity)) throw new Error("outcome application refused: trusted enrollment verifier unavailable");
  token.assert();
}
/** Test/local validation ONLY. Creates its own empty namespace; cannot enroll an existing store,
 * accept a host manifest, supplied boolean, alternate UID, network or deployment. Within the
 * trusted single UID, the fixture owner admits only cooperative fixture writer children. This
 * proves no live/legacy activation inventory and must NEVER be used as a live host verifier. */
export function createIsolatedRecoveryFixture() {
  const root = mkdtempSync(join(realpathSync(tmpdir()), "outcome-apply-fixture-"));
  const paths = Object.fromEntries(DOMAIN_ROLES.map(role => { const path = join(root, role); mkdirSync(path, { mode: 0o700 }); return [role, path]; })) as DomainPaths;
  const domain = enrollRecoveryDomain(paths);
  const identity: RecoveryIdentity = Object.freeze({ network: FIXTURE_NETWORK, genesisHash: FIXTURE_GENESIS, programId: LOCAL_PROGRAM_ID });
  const enrollment: RecoveryEnrollment = Object.freeze({ profile: "isolated-one-uid-fixture" });
  grants.set(enrollment, { domain, uid: process.getuid!(), identity });
  return { root, paths, domain, identity, enrollment };
}
