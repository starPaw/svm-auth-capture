import { afterEach, expect, test, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync, renameSync, rmSync, chmodSync, openSync, closeSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { createRequire } from 'node:module';
import { AdmissionJournal, type AdmissionPolicy } from '../src/admission-journal.ts';
import * as durable from '../src/durable-file.ts';
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
test('durable guard cannot silently expand its explicit configured attempt cap',()=>{
  const f=fixture();
  expect(()=>new SponsorshipGuard({admission:f.restart(),maxAttempts:1,minLamportsBalance:0n,feePayer:'11111111111111111111111111111111' as any,ledger:{} as any})).toThrow(/cap mismatch/);
  expect(f.restart().summary().used).toBe(20);
});

test('selected A extension preserves six consumed orders, immutable archive and lock inode across restart',()=>{
  const f=fixture('orders',11,5);f.restart().reserve();
  const lock=statSync(join(f.dir,'.lock'));
  const oldPolicy=readFileSync(join(f.dir,'policy.json'),'utf8'),oldState=readFileSync(join(f.dir,'state.json'),'utf8');
  const live=f.restart();live.extendExpiredAOrderLimit();
  expect(()=>live.reserve()).toThrow(/drift/);
  const archive=readFileSync(join(f.dir,'expired-A-maximum-11-to-12.lock'),'utf8');
  expect(JSON.parse(archive)).toMatchObject({oldPolicy:JSON.parse(oldPolicy),oldState:JSON.parse(oldState),newState:{used:6}});
  const next=()=>new AdmissionJournal(f.dir,'orders',12);
  expect(next().summary()).toMatchObject({used:6,maximum:12,carryForward:5,historicalActual:5});
  for(let i=0;i<6;i++)next().reserve();
  expect(next().summary().used).toBe(12);expect(()=>next().reserve()).toThrow(/cap/);
  expect(readFileSync(join(f.dir,'expired-A-maximum-11-to-12.lock'),'utf8')).toBe(archive);
  expect(statSync(join(f.dir,'.lock')).ino).toBe(lock.ino);
});
test.each(['relay','five-used','seven-used'])('order extension refuses %s without replacing policy/state',fault=>{
  const f=fault==='relay'?fixture():fixture('orders',11,5);
  if(fault==='seven-used'){f.restart().reserve();f.restart().reserve();}
  const policy=readFileSync(join(f.dir,'policy.json')),state=readFileSync(join(f.dir,'state.json'));
  expect(()=>f.restart().extendExpiredAOrderLimit()).toThrow(/scope/);
  expect(readFileSync(join(f.dir,'policy.json'))).toEqual(policy);expect(readFileSync(join(f.dir,'state.json'))).toEqual(state);
});
test.each([1,2])('interrupted extension write %i blocks both caps and retains originals in immutable archive',at=>{
  const f=fixture('orders',11,5);f.restart().reserve();let calls=0;
  const real=durable.replaceDurableFile;
  const spy=vi.spyOn(durable,'replaceDurableFile').mockImplementation((path,data)=>{if(++calls===at)throw Error('crash injection');real(path,data);});
  expect(()=>f.restart().extendExpiredAOrderLimit()).toThrow(/crash/);spy.mockRestore();
  const archive=JSON.parse(readFileSync(join(f.dir,'expired-A-maximum-11-to-12.lock'),'utf8'));expect(archive.oldState.used).toBe(6);expect(archive.newState.used).toBe(6);
  expect(()=>new AdmissionJournal(f.dir,'orders',11)).toThrow();expect(()=>new AdmissionJournal(f.dir,'orders',12)).toThrow();
});
