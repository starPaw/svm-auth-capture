// Offline parser/RPC fixture. These bytes, signatures and slots are synthetic.
// They are never passed off as an accepted deployment or used for live signing.
import { createHash } from 'node:crypto';
import { getAddressDecoder } from '@solana/kit';
import { parseDeploymentRecord, type DeploymentRecord } from '../../src/deployment-record.ts';

const address = (byte: number) => getAddressDecoder().decode(new Uint8Array(32).fill(byte));
export const fixtureExecutable = Buffer.from('SYNTHETIC_OFFLINE_EXECUTABLE');
const executableHash = createHash('sha256').update(fixtureExecutable).digest('hex');
const genesis = 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG';

export function deploymentFixture(): Record<string, any> {
  return {
    schema_version: 1, record_status: 'verified',
    network: { cluster: 'devnet', genesis_hash: genesis, caip2: `solana:${genesis.slice(0, 32)}`, public_rpc_identifier: 'https://fixture.invalid' },
    program: { program_id: address(3), executable: true, loader: 'BPFLoaderUpgradeab1e11111111111111111111111',
      program_data: address(4), upgrade_authority: { status: 'present', public_key: address(5) } },
    build: { source_revision: 'a'.repeat(40), host: 'synthetic test fixture',
      pinned_versions: { solana_cli: 'fixture', cargo_build_sbf: 'fixture', platform_tools: 'fixture', sbf_rustc: 'fixture' },
      sbf_architecture: 'fixture', commands: ['offline fixture only'], artifact_sha256: executableHash,
      artifact_size_bytes: String(fixtureExecutable.length) },
    deployment: { transactions: [{ signature: '2'.repeat(88), commitment: 'finalized', result: 'success', slot: '10' }], deployment_slot: '10' },
    verification: { observation_slot: '11', observed_at: '2000-01-01T00:00:00Z',
      executable_comparison: { method: 'synthetic fixture', loader_layout: 'loader-v3 fixture', executable_offset_bytes: '45',
        compared_length_bytes: String(fixtureExecutable.length), trailing_padding_bytes: '0', padding_handling: 'fixture',
        deployed_executable_sha256: executableHash, result: 'match', limitations: [] }, evidence_paths: ['synthetic-fixture'] },
  };
}

export function parsedDeploymentFixture(): DeploymentRecord {
  const raw = deploymentFixture();
  return { ...parseDeploymentRecord(raw), sha256: createHash('sha256').update(JSON.stringify(raw)).digest('hex') };
}
