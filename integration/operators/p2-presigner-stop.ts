// A specific owner-approved continuation, never a general UNKNOWN recovery route.
export const STOPPED_P2_SOURCE = 'b2062584b488adfa3e34e43918fddaafd7e0dc37';
export const STOPPED_P2_ENTRY = '2d4ac36d064410b834b7eecf13127c4c9818fcb19dcee4dc1a2716c5f13cf4f8';
export const STOPPED_P2_MANIFEST = 'dda6fa6162d0ddd4199b38e023ec602f178c364715196510650ea78de5c39301';
export function credentialDirectory(directory: unknown): string {
  if (typeof directory !== 'string' || !/^\/run\/credentials\/capture402-e2e-p2-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\.service$/.test(directory)) throw Error('scoped ephemeral signer credentials required');
  return directory;
}
export type PreSignerStop = {
  schema: 1; reason: 'B206_SYSTEMD_SERVICE_SUFFIX_REJECTED_BEFORE_SDK_SIGNER';
  stoppedSourceRevision: string; stoppedEntrypointSha256: string; stoppedManifestSha256: string;
  originalIntentSha256: string; originalPlanHash: string; observedCredentialDirectory: string;
};
export type PreSignerContinuation = { stop: PreSignerStop; attestationSha256: string; ownerApprovalReference: string };
export function validatePreSignerContinuation(value: PreSignerContinuation): void {
  const s = value.stop;
  if (!s || s.schema !== 1 || s.reason !== 'B206_SYSTEMD_SERVICE_SUFFIX_REJECTED_BEFORE_SDK_SIGNER' || s.stoppedSourceRevision !== STOPPED_P2_SOURCE || s.stoppedEntrypointSha256 !== STOPPED_P2_ENTRY || s.stoppedManifestSha256 !== STOPPED_P2_MANIFEST || ![s.originalIntentSha256, s.originalPlanHash, value.attestationSha256].every(x => typeof x === 'string' && /^[a-f0-9]{64}$/.test(x)) || typeof value.ownerApprovalReference !== 'string' || !value.ownerApprovalReference.trim()) throw Error('specific approved pre-signer stop required');
  credentialDirectory(s.observedCredentialDirectory);
  // The pinned old entry point rejects every such path before loadKeypair.
  // Root-operator attestation + explicit new approval are required; missing wires alone prove nothing.
}
