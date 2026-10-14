import {expect,test} from 'vitest';
import {createHash} from 'node:crypto';
import {validateRuntimeRpc} from '../src/e2e-runtime-policy.ts';
import {parsedDeploymentFixture,fixtureExecutable} from './fixtures/deployment-fixture.ts';
const record=parsedDeploymentFixture();
const endpoint='https://approved.invalid/private-fixture-token';
const policy={schema:1,endpointSha256:createHash('sha256').update(endpoint).digest('hex'),genesisHash:record.network.genesisHash,deploymentSha256:record.sha256};
test('private owner-selected endpoint is exact-bound to network and accepted program identity',()=>{
 expect(()=>validateRuntimeRpc(policy,endpoint,record)).not.toThrow();
 for(const patch of [{endpointSha256:'a'.repeat(64)},{genesisHash:'wrong'},{deploymentSha256:'b'.repeat(64)},{schema:2},{unexpected:true}]) expect(()=>validateRuntimeRpc({...policy,...patch},endpoint,record)).toThrow(/mismatch/);
 for(const url of ['https://another.invalid/private-fixture-token',endpoint+'?retry=1','http://approved.invalid/private-fixture-token']) {
  try{validateRuntimeRpc(policy,url,record);throw Error('unexpected acceptance');}catch(error){expect(String(error)).not.toContain('private-fixture-token');}
 }
});
