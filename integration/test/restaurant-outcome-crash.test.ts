import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { resolve, join } from "node:path";
import { expect, test } from "vitest";
import { RecoveryDomain } from "../src/coordination.ts";
import { applyRestaurantOutcome } from "../src/restaurant-outcome-apply.ts";
import { FIXTURE_GENESIS, FIXTURE_NETWORK } from "../src/recovery-enrollment.ts";
import { LOCAL_PROGRAM_ID } from "../src/program.ts";
const boundaries = ["stage-file-before","stage-directory-before","record-before-write","record-after-write","record-file-before","record-file-after","record-directory-before","record-directory-after","order-partial-write","order-file-before","order-file-after","order-rename-before","order-rename-after","order-directory-before","order-directory-after","persisted-order-file-before","busy-unlink-before","busy-unlink-after","unlock-directory-before","unlock-directory-after"];
const hash=(b:Uint8Array)=>createHash("sha256").update(b).digest("hex");
function run(kind:string,boundary:string,failure=false) {
  const child=spawnSync(process.execPath,["--experimental-strip-types",resolve("test/fixtures/outcome-fault-worker.ts"),kind,boundary,failure ? "failure" : "success"],{ timeout:8000,encoding:"utf8" });
  const lines=child.stdout.trim().split("\n").map(s=>JSON.parse(s));return { child,meta:lines[0],result:lines[1] };
}
test.each(boundaries)("SIGKILL %s: evidence survives, restart performs no application",async boundary => {
  const { child,meta }=run("kill",boundary);
  try {
    expect(child.signal,child.stderr).toBe("SIGKILL");
    for(const p of meta.original) expect(hash(readFileSync(p.path))).toBe(p.sha256);
    const path=join(meta.paths.orders,meta.id+".json"),busy=existsSync(path+".busy"),raw=readFileSync(path),order=JSON.parse(raw.toString());
    const replaced=["order-rename-after","order-directory-before","order-directory-after","persisted-order-file-before","busy-unlink-before","busy-unlink-after","unlock-directory-before","unlock-directory-after"].includes(boundary);
    expect(order.status).toBe(replaced ? "active" : "pending");if(!replaced) expect(hash(raw)).toBe(meta.preimageSha256);
    expect(busy).toBe(!["busy-unlink-after","unlock-directory-before","unlock-directory-after"].includes(boundary));
    if(replaced) {
      const record=readFileSync(join(meta.paths.orders,readdirSync(meta.paths.orders).find((n:string)=>n.endsWith(".record"))!));
      expect(order.events[1].applicationRecordSha256).toBe(hash(record));
    }
    const domain=new RecoveryDomain(meta.paths);await domain.run("exclusive",async()=>{}); // SIGKILL released process locks only.
    await expect(applyRestaurantOutcome({ domain,identity:{ network:FIXTURE_NETWORK,genesisHash:FIXTURE_GENESIS,programId:LOCAL_PROGRAM_ID },orderId:meta.id,action:"beer",signature:meta.signature,evidenceDigest:meta.evidenceDigest,reader:{} as never })).rejects.toThrow(/enrollment verifier/);
    expect(readFileSync(path)).toEqual(raw);expect(existsSync(path+".busy")).toBe(busy);
  } finally { rmSync(meta.root,{ recursive:true,force:true }); }
});
test.each(boundaries)("fs/write/unlink fault %s: explicit repeat completes only proven local work",boundary => {
  const { child,meta,result }=run("fault",boundary);
  try {
    expect(child.status,child.stderr).toBe(0);expect(result.fired).toBe(true);expect(result.beforeRetry.originals).toBe(true);expect(result.after.originals).toBe(true);
    const incomplete=["stage-file-before","stage-directory-before","record-before-write","record-after-write","order-partial-write"].includes(boundary);
    expect(result.repeat).toBe(incomplete ? "refused" : ["busy-unlink-after","unlock-directory-before","unlock-directory-after"].includes(boundary) ? "already-applied" : "completed");
    expect(result.after.busy).toBe(incomplete);expect(result.after.status).toBe(incomplete ? "pending" : "active");
    if(!["busy-unlink-after","unlock-directory-before","unlock-directory-after"].includes(boundary)) expect(result.beforeRetry.busy).toBe(true);
  } finally { rmSync(meta.root,{ recursive:true,force:true }); }
});
test("finalized failure also resumes after failed order directory fsync",()=>{
  const { child,meta,result }=run("fault","order-directory-before",true);
  try { expect(child.status,child.stderr).toBe(0);expect(result.repeat).toBe("completed");expect(result.after.busy).toBe(false);const order=JSON.parse(readFileSync(join(meta.paths.orders,meta.id+".json"),"utf8"));expect(order.events[1].status).toBe("rejected"); }
  finally { rmSync(meta.root,{ recursive:true,force:true }); }
});
