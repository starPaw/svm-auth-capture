// A preallocated replacement inode is bound in the immutable record BEFORE order rename.
// This lets an explicit repeat reject even a same-byte substituted post-state inode.
import { constants, closeSync, fstatSync, fsyncSync, ftruncateSync, lstatSync, openSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
function refused(): never { throw new Error("outcome application refused: replacement identity changed"); }
export function inode(path: string): string { const s = lstatSync(path,{ bigint:true }); return `${s.dev}:${s.ino}`; }
export function verifyStagedOrder(path: string, expectedIdentity: string, postimage: string): void {
  const fd = openSync(path,constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const s = fstatSync(fd,{ bigint:true });
    if (!s.isFile() || s.nlink !== 1n || s.mode !== 0o100600n || s.uid !== BigInt(process.getuid!()) || `${s.dev}:${s.ino}` !== expectedIdentity || inode(path) !== expectedIdentity || s.size > 1048576n) refused();
    const raw = readFileSync(fd).toString("utf8"); if (raw !== "" && raw !== postimage) refused();
  } finally { closeSync(fd); }
}
export function replaceRecoveryOrder(stage: string, path: string, expectedIdentity: string, postimage: string): void {
  verifyStagedOrder(stage,expectedIdentity,postimage);
  const fd = openSync(stage,constants.O_WRONLY | constants.O_NOFOLLOW);
  try {
    if (`${fstatSync(fd,{ bigint:true }).dev}:${fstatSync(fd,{ bigint:true }).ino}` !== expectedIdentity || inode(stage) !== expectedIdentity) refused();
    ftruncateSync(fd,0); writeFileSync(fd,postimage); fsyncSync(fd);
  } finally { closeSync(fd); }
  verifyStagedOrder(stage,expectedIdentity,postimage);
  renameSync(stage,path);
  const directory = openSync(dirname(path),constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { fsyncSync(directory); } finally { closeSync(directory); }
}
