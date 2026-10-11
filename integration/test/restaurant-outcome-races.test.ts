import { fork, type ChildProcess } from "node:child_process";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, expect, test } from "vitest";
import { outcomeFixture } from "./fixtures/outcome-fixture.ts";
const roots:string[]=[],children:ChildProcess[]=[];
afterEach(()=>{ for(const c of children.splice(0)) c.kill("SIGKILL");for(const p of roots.splice(0)) rmSync(p,{ recursive:true,force:true }); });
function worker(f:Awaited<ReturnType<typeof outcomeFixture>>,role:string) {
  const c=fork(resolve("test/fixtures/outcome-race-worker.ts"),[JSON.stringify(f.paths),role,f.id,f.signature],{ execArgv:["--experimental-strip-types"],stdio:["ignore","ignore","pipe","ipc"] });children.push(c);
  const messages:any[]=[],pending:{ name:string;done:()=>void }[]=[];let errors="";c.stderr?.on("data",d=>errors+=d);
  c.on("message",m=>{ messages.push(m);for(const p of pending) if(p.name === m) p.done(); });
  return { c,messages,receive(name:string) { if(messages.includes(name)) return Promise.resolve();return new Promise<void>((resolve,reject)=>{ const t=setTimeout(()=>reject(new Error("missing "+name+errors)),4000);pending.push({ name,done:()=>{ clearTimeout(t);resolve(); } }); }); } };
}
test.each(["order","facilitator","reclaim"])("real %s writer blocks recovery, one total timeout retains reservations",async role=>{
  const f=await outcomeFixture();roots.push(f.root);const w=worker(f,role);await w.receive("entered");const pre=readFileSync(f.path);
  f.options.timeoutMs=60;await expect(f.apply()).rejects.toThrow();expect(readFileSync(f.path)).toEqual(pre);expect(existsSync(f.busyPath)).toBe(true);
  w.c.send("release");await w.receive("released");
});
test("complete snapshot is revalidated after a real journal writer wins the race",async()=>{
  const f=await outcomeFixture();roots.push(f.root);const w=worker(f,"facilitator");await w.receive("entered");const pre=readFileSync(f.path);
  const result=f.apply();w.c.send("release");await w.receive("released");await expect(result).rejects.toThrow();expect(readFileSync(f.path)).toEqual(pre);expect(existsSync(f.busyPath)).toBe(true);
});
test("exclusive recovery blocks an actual competing restaurant writer through RPC/persistence",async()=>{
  const f=await outcomeFixture();roots.push(f.root);let entered!:()=>void,release!:()=>void;
  const inside=new Promise<void>(r=>entered=r),gate=new Promise<void>(r=>release=r),get=f.reader.getAccountAtLeast;
  f.reader.getAccountAtLeast=async(...args)=>{ entered();await gate;return get(...args); };
  const apply=f.apply();await inside;const w=worker(f,"order");await w.receive("ready");expect(w.messages).not.toContain("entered");
  release();expect((await apply).result).toBe("applied");await w.receive("entered");expect(w.messages).toContainEqual({ status:"active" });
  w.c.send("release");await w.receive("released");expect(w.messages).toContain("reservation-refused");expect(w.messages).not.toContain("unexpected-reservation");
});
