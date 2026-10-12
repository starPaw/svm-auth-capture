// Actual pinned SDK transport against a local observation-only RPC fixture.
import {expect,test} from 'vitest';
import {createServer} from 'node:http';
import {once} from 'node:events';
import {readFileSync} from 'node:fs';
import {getAddressEncoder} from '@solana/kit';
import {rpcBackend} from '../operators/e2e-provision.ts';
import {loadDeploymentRecord} from '../src/deployment-record.ts';
const record=loadDeploymentRecord('../docs/evidence/sac-007/deployment-identity.v1.json');
test.each(['accepted','wrong-genesis','wrong-program','stale-finalized-bank'])('same configured provider binds all quotes/finality/minContextSlot: %s',async fault=>{
  const calls:{method:string;params:any[]}[]=[];
  const pin=record.deployment,p=Buffer.alloc(36);p.writeUInt32LE(2);p.set(getAddressEncoder().encode(pin.programData),4);
  const binary=readFileSync('../docs/evidence/sac-007/build-candidate/svm_auth_capture.so'),d=Buffer.alloc(45+binary.length);
  d.writeUInt32LE(3);d.writeBigUInt64LE(pin.slot,4);d[12]=1;d.set(getAddressEncoder().encode(pin.upgradeAuthority!),13);d.set(binary,45);
  if(fault==='wrong-program')d[45]=d[45]!^1;
  const account=(bytes:Buffer,executable:boolean)=>({owner:pin.loader,executable,lamports:1,data:[bytes.toString('base64'),'base64'],rentEpoch:0,space:bytes.length});
  const server=createServer(async(req,res)=>{
    let body='';for await(const chunk of req)body+=chunk;const payload=JSON.parse(body);calls.push(payload);
    let result:any;
    if(payload.method==='getGenesisHash')result=fault==='wrong-genesis'?'wrong':record.network.genesisHash;
    else if(payload.method==='getMultipleAccounts')result={context:{slot:Number(fault==='stale-finalized-bank'?pin.slot-1n:pin.slot)},value:payload.params[0].length===2?[account(p,true),account(d,false)]:[null]};
    else if(payload.method==='getMinimumBalanceForRentExemption')result=2039280;
    else if(payload.method==='getFeeForMessage')result={context:{slot:Number(pin.slot)},value:5000};
    else if(payload.method==='getTransaction')result=null;
    else throw Error('unexpected read/send');
    res.setHeader('Content-Type','application/json');res.end(JSON.stringify({jsonrpc:'2.0',id:payload.id,result}));
  });
  server.listen(0,'127.0.0.1');await once(server,'listening');
  try {
    const backend=rpcBackend(record,`http://127.0.0.1:${(server.address() as any).port}/approved`);
    if(fault!=='accepted') {
      await expect(backend.rent(165)).rejects.toThrow();expect(calls.every(c=>['getGenesisHash','getMultipleAccounts'].includes(c.method))).toBe(true);
    } else {
      expect(await backend.rent(165)).toBe(2039280n);
      expect(await backend.fee({messageBytes:new Uint8Array([0])} as any)).toBe(5000n);
      expect(await backend.snapshot([record.programId],pin.slot)).toMatchObject({slot:pin.slot,accounts:[null]});
      expect(await backend.finalized('1'.repeat(64))).toBeNull();
      expect(calls.filter(c=>c.method==='getGenesisHash')).toHaveLength(1);
      const reads=calls.filter(c=>c.method!=='getGenesisHash');
      // Kit strips explicit finalized because it is the RPC server default; it must
      // never emit confirmed/processed for any of these observation/quote requests.
      expect(reads.every(c=>c.params.at(-1)?.commitment===undefined || c.params.at(-1).commitment==='finalized')).toBe(true);
      expect(calls.filter(c=>c.method==='getMultipleAccounts').every(c=>c.params[1].minContextSlot===Number(pin.slot))).toBe(true);
      expect(calls.some(c=>c.method==='sendTransaction')).toBe(false);
    }
  } finally {server.closeAllConnections();await new Promise<void>(r=>server.close(()=>r()));}
});
