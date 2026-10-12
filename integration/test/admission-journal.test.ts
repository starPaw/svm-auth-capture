import { afterEach, expect, test } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync, renameSync, rmSync, chmodSync, openSync, closeSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { createRequire } from 'node:module';
import { AdmissionJournal, type AdmissionPolicy } from '../src/admission-journal.ts';
import { SponsorshipGuard } from '../src/sponsorship.ts';
const dirs:string[]=[];
afterEach(()=>dirs.splice(0).forEach(d=>rmSync(d,{recursive:true,force:true})));
function fixture(kind:AdmissionPolicy['kind']='relay-attempts',maximum=45,carryForward=20) {
  const dir=mkdtempSync(join(tmpdir(),'b3-admission-'));dirs.push(dir);
  const policy:AdmissionPolicy={schema:1,kind,reference:'synthetic-b3',maximum,carryForward,historicalActual:kind==='relay-attempts'?null:carryForward,sourceSha256:'a'.repeat(64)};
  AdmissionJournal.initialize(dir,policy);
  return {dir,policy,restart:()=>new AdmissionJournal(dir,kind,maximum)};
}
test('UNKNOWN historical attempts carry forward 20; concurrent admissions reserve before balance await and restart cannot reset',async()=>{
  const f=fixture(),admission=f.restart();
  const guard=new SponsorshipGuard({admission,maxAttempts:45,minLamportsBalance:1n,feePayer:'11111111111111111111111111111111' as any,ledger:{getAccount:async()=>{await Promise.resolve();return {lamports:1n};}} as any});
  const results=await Promise.all(Array.from({length:40},()=>guard.check()));
  expect(results.filter(r=>r===undefined)).toHaveLength(25);
  expect(f.restart().summary()).toMatchObject({used:45,historicalActual:null,carryForward:20});
  expect(()=>f.restart().reserve()).toThrow(/cap/);
});
test('balance refusal/read failure does not return durable slots',async()=>{
  const f=fixture();
  for(const fail of [false,true]) {
    const guard=new SponsorshipGuard({admission:f.restart(),maxAttempts:45,minLamportsBalance:1n,feePayer:'11111111111111111111111111111111' as any,ledger:{getAccount:async()=>{if(fail)throw Error('private-provider-credential');return null;}} as any});
    expect(await guard.check()).toBeTruthy();
  }
  expect(f.restart().summary().used).toBe(22);
});
test('orders preserve five old slots and permit at most six new admissions',()=>{
  const f=fixture('orders',11,5);
  for(let i=0;i<6;i++)f.restart().reserve();
  expect(f.restart().summary()).toMatchObject({used:11,historicalActual:5});
  expect(()=>f.restart().reserve()).toThrow(/cap/);
});
test('SIGKILL after fsync preserves reservation and original lock inode',async()=>{
  const f=fixture(),lock=readFileSync(join(f.dir,'.lock'));const worker=join(f.dir,'worker.mjs');
  writeFileSync(worker,`import {AdmissionJournal} from ${JSON.stringify(new URL('../src/admission-journal.ts',import.meta.url).pathname)};new AdmissionJournal(${JSON.stringify(f.dir)},'relay-attempts',45).reserve();process.stdout.write('reserved\\n');setInterval(()=>{},1000);`);
  const child=spawn(process.execPath,['--experimental-strip-types',worker],{stdio:['ignore','pipe','pipe']});
  await once(child.stdout!,'data');child.kill('SIGKILL');await once(child,'exit');
  expect(f.restart().summary().used).toBe(21);expect(readFileSync(join(f.dir,'.lock'))).toEqual(lock);
});
test('cross-process native flock prevents double admission',async()=>{
  const f=fixture('orders',6,5),worker=join(f.dir,'worker.mjs');
  writeFileSync(worker,`import {AdmissionJournal} from ${JSON.stringify(new URL('../src/admission-journal.ts',import.meta.url).pathname)};try{new AdmissionJournal(${JSON.stringify(f.dir)},'orders',6).reserve();process.exit(0)}catch{process.exit(72)}`);
  const children=Array.from({length:8},()=>spawn(process.execPath,['--experimental-strip-types',worker],{stdio:'ignore'}));
  const results=await Promise.all(children.map(async c=>(await once(c,'exit'))[0]));
  expect(results.filter(c=>c===0)).toHaveLength(1);expect(f.restart().summary().used).toBe(6);
});
test.each(['missing','corrupt','mode','policy','lock'])('%s journal cannot reinitialize or admit',fault=>{
  const f=fixture(),live=f.restart(),state=join(f.dir,'state.json');
  if(fault==='missing')rmSync(state);if(fault==='corrupt')writeFileSync(state,'{');if(fault==='mode')chmodSync(state,0o644);
  if(fault==='policy')writeFileSync(join(f.dir,'policy.json'),'{}');
  if(fault==='lock'){renameSync(join(f.dir,'.lock'),join(f.dir,'.lock.saved'));writeFileSync(join(f.dir,'.lock'),'replacement',{mode:0o600});}
  expect(()=>live.reserve()).toThrow();expect(()=>AdmissionJournal.initialize(f.dir,f.policy)).toThrow();
});
test('runtime cap drift and externally held lock deny without changing state',()=>{
  const f=fixture(),before=createHash('sha256').update(readFileSync(join(f.dir,'state.json'))).digest('hex');
  expect(()=>new AdmissionJournal(f.dir,'relay-attempts',46)).toThrow(/mismatch/);
  const flock=createRequire(import.meta.url)('fs-ext').flockSync,fd=openSync(join(f.dir,'.lock'),'r+');
  try{flock(fd,'exnb');expect(()=>f.restart()).toThrow();}finally{flock(fd,'un');closeSync(fd);}
  expect(createHash('sha256').update(readFileSync(join(f.dir,'state.json'))).digest('hex')).toBe(before);
});
