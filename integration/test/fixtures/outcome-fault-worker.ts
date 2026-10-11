// Actual process death / native fsync injection. Hooks exist ONLY in this test worker.
import { createRequire, syncBuiltinESMExports } from "node:module";
import { createHash } from "node:crypto";
const require = createRequire(import.meta.url), fs = require("node:fs") as typeof import("node:fs");
const [kind,boundary,failure] = process.argv.slice(2);
const { outcomeFixture } = await import("./outcome-fixture.ts");
const f = await outcomeFixture(failure === "failure");
const hash = (raw:Uint8Array) => createHash("sha256").update(raw).digest("hex");
const original = [f.paths.orders,f.paths.facilitator,f.paths.reclaim,f.paths.operations].flatMap(dir => fs.readdirSync(dir).filter(n=>n!==`${f.id}.json` && n!==`${f.id}.json.busy`).map(n=>({ path:dir+"/"+n,sha256:hash(fs.readFileSync(dir+"/"+n)) })));
fs.writeSync(1,JSON.stringify({ root:f.root,paths:f.paths,id:f.id,signature:f.signature,evidenceDigest:f.options.evidenceDigest,preimageSha256:hash(fs.readFileSync(f.path)),original })+"\n");
let active = true, fired = false, recordWritten = false, renamed = false, unlinked = false;
const fds = new Map<number,string>();
function hit(name:string) {
  if (!active || fired || name !== boundary) return;
  fired = true;
  if (kind === "kill") process.kill(process.pid,"SIGKILL");
  // Linux strace calibration identifies the next real fsync syscall. The injected
  // EIO comes from syscall tracing, not this JavaScript hook.
  if (kind === "native-fault") { fs.writeSync(2,"NATIVE_FAULT_TARGET:"+name+"\n");return; }
  throw new Error("injected fault: "+name);
}
const originalOpen = fs.openSync, originalClose = fs.closeSync, originalFsync = fs.fsyncSync, originalWrite = fs.writeFileSync, originalRename = fs.renameSync, originalUnlink = fs.unlinkSync;
(fs as any).openSync = (...args:any[]) => { const fd=(originalOpen as any)(...args);fds.set(fd,String(args[0]));return fd; };
fs.closeSync = fd => { fds.delete(fd);originalClose(fd); };
(fs as any).writeFileSync = (fd:any,...rest:any[]) => {
  const path=typeof fd === "number" ? fds.get(fd) : String(fd);
  if(path?.endsWith(".record")) { hit("record-before-write");(originalWrite as any)(fd,...rest);recordWritten=true;hit("record-after-write");return; }
  if(path?.endsWith(".order") && recordWritten && boundary === "order-partial-write") { (originalWrite as any)(fd,"{incomplete");hit("order-partial-write"); }
  (originalWrite as any)(fd,...rest);
};
fs.fsyncSync = fd => {
  const path=fds.get(fd) ?? "",directory=fs.fstatSync(fd).isDirectory();
  const name = directory ? unlinked ? "unlock-directory" : renamed ? "order-directory" : recordWritten ? "record-directory" : "stage-directory" :
    path.endsWith(".record") ? "record-file" : path.endsWith(".order") ? recordWritten ? "order-file" : "stage-file" : path===f.path ? "persisted-order-file" : "other";
  hit(name+"-before");originalFsync(fd);hit(name+"-after");
};
fs.renameSync = (a,b) => { hit("order-rename-before");originalRename(a,b);renamed=true;hit("order-rename-after"); };
fs.unlinkSync = path => { hit("busy-unlink-before");originalUnlink(path);unlinked=true;hit("busy-unlink-after"); };
syncBuiltinESMExports();
try { await f.apply(); fs.writeSync(1,JSON.stringify({ unexpectedSuccess:true })+"\n"); }
catch (error) {
  active=false;syncBuiltinESMExports();
  const beforeRetry = { pending:JSON.parse(fs.readFileSync(f.path,"utf8")).status === "pending",busy:fs.existsSync(f.busyPath),originals:original.every(p=>hash(fs.readFileSync(p.path))===p.sha256) };
  let repeat:string;
  try { repeat=(await f.apply()).result; } catch { repeat="refused"; }
  fs.writeSync(1,JSON.stringify({ fired,errorCode:(error as NodeJS.ErrnoException).code,beforeRetry,repeat,after:{ status:JSON.parse(fs.readFileSync(f.path,"utf8")).status,busy:fs.existsSync(f.busyPath),originals:original.every(p=>hash(fs.readFileSync(p.path))===p.sha256) } })+"\n");
}
