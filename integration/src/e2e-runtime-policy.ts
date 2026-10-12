// Owner-approved private endpoint binding; URL is never a public configuration field.
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { DeploymentRecord } from './deployment-record.ts';
export const E2E_SPONSOR = '5mkvwgKeWMYrFppGm8ugLzQC9Wff4vduqWphsGhQNigX';
export function trustedRuntimeFile(path: string): string {
  let current = path;
  for (;;) {
    const s = lstatSync(current);
    if (s.isSymbolicLink() || s.uid !== 0 || s.mode & 0o022 || current === path && (!s.isFile() || s.nlink !== 1)) throw Error('untrusted private runtime policy');
    if (dirname(current) === current) break;
    current = dirname(current);
  }
  return readFileSync(path,'utf8');
}
export function validateRuntimeRpc(policy: unknown, endpoint: string, record: DeploymentRecord): void {
  const p = policy as Record<string,unknown>;
  let url: URL;
  try { url = new URL(endpoint); } catch { throw Error('invalid private RPC configuration'); }
  if (!p || Object.keys(p).sort().join() !== 'deploymentSha256,endpointSha256,genesisHash,schema' || p.schema !== 1 ||
    url.protocol !== 'https:' || url.username || url.password || url.hash ||
    p.endpointSha256 !== createHash('sha256').update(endpoint).digest('hex') ||
    p.genesisHash !== record.network.genesisHash || p.deploymentSha256 !== record.sha256) throw Error('private RPC policy/runtime mismatch');
}
export function requireE2eRuntimeRpc(endpoint: string, record: DeploymentRecord): void {
  const path = process.env.SAC006_E2E_RPC_POLICY_PATH;
  if (!path) throw Error('approved E2E private RPC policy required');
  validateRuntimeRpc(JSON.parse(trustedRuntimeFile(path)),endpoint,record);
}
