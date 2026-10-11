// Complete bounded private domain inventory, including unknown names (which refuse).
import { createHash } from "node:crypto";
import { constants, closeSync, fstatSync, lstatSync, openSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import type { RecoveryDomain } from "./coordination.ts";
export const recoveryHash = (raw: string | Uint8Array) => createHash("sha256").update(raw).digest("hex");
export type FilePin = { role: string; name: string; identity: string; sha256: string };
export type RecoverySnapshot = { pins: FilePin[]; bytes: Map<string, Buffer> };
const refuse = (): never => { throw new Error("outcome application refused: unsafe or changed evidence"); };
function identity(s: import("node:fs").BigIntStats) {
  return [s.dev,s.ino,s.mode,s.uid,s.gid,s.nlink,s.size,s.mtimeNs,s.ctimeNs].join(":");
}
export function recoverySnapshot(domain: RecoveryDomain, ownRecord: string): RecoverySnapshot {
  domain.verify();
  const pins: FilePin[] = [], bytes = new Map<string, Buffer>(); let total = 0;
  for (const member of domain.metadata.members) {
    const names = readdirSync(member.path).sort(); if (names.length > 2000) refuse();
    for (const name of names) {
      if (name === ".coordination.lock" || member.role === "orders" && (name === ownRecord || name === ownRecord.replace(/\.record$/, ".order"))) continue;
      const valid = member.role === "orders" ? /^[a-f0-9]{32}\.json(?:\.busy|\.(authorize|beer|salmon|finish|void|refund|reclaim)\.lock)?$/.test(name) || /^[a-f0-9]{32}\.outcome-[a-f0-9]{64}\.record$/.test(name) :
        member.role === "operations" ? /^[a-f0-9]{64}\.json$/.test(name) :
        /^[1-9A-HJ-NP-Za-km-z]{64,88}\.json$/.test(name) || /^reclaim-[1-9A-HJ-NP-Za-km-z]{32,44}(?:-after-[1-9A-HJ-NP-Za-km-z]{64,88})?\.lock$/.test(name);
      if (!valid) refuse();
      const path = join(member.path, name), fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      try {
        const s = fstatSync(fd, { bigint: true }), pathname = lstatSync(path, { bigint: true });
        if (!s.isFile() || s.nlink !== 1n || s.uid !== BigInt(process.getuid!()) || s.mode !== (name.endsWith(".record") ? 0o100400n : 0o100600n) || s.size > 1048576n || identity(s) !== identity(pathname)) refuse();
        const raw = readFileSync(fd); total += raw.length; if (total > 32 * 1048576 || raw.length !== Number(s.size)) refuse();
        if (identity(fstatSync(fd,{ bigint:true })) !== identity(s) || identity(lstatSync(path,{ bigint:true })) !== identity(s)) refuse();
        pins.push({ role: member.role, name, identity: identity(s), sha256: recoveryHash(raw) }); bytes.set(`${member.role}/${name}`,raw);
      } finally { closeSync(fd); }
    }
    if (JSON.stringify(readdirSync(member.path).sort()) !== JSON.stringify(names)) refuse();
  }
  return { pins, bytes };
}
export function sameRecoveryPins(a: FilePin[], b: FilePin[]) { if (JSON.stringify(a) !== JSON.stringify(b)) refuse(); }
export function readRecoveryRecord(path: string): string {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const s = fstatSync(fd,{ bigint:true });
    if (!s.isFile() || s.uid !== BigInt(process.getuid!()) || s.mode !== 0o100400n || s.nlink !== 1n || s.size > 8n * 1048576n || identity(s) !== identity(lstatSync(path,{ bigint:true }))) refuse();
    const raw = readFileSync(fd);
    if (raw.length !== Number(s.size) || identity(fstatSync(fd,{ bigint:true })) !== identity(s) || identity(lstatSync(path,{ bigint:true })) !== identity(s)) refuse();
    const text = new TextDecoder("utf-8",{ fatal:true, ignoreBOM:true }).decode(raw);
    if (JSON.parse(text).recordIdentity !== `${s.dev}:${s.ino}`) refuse();
    return text;
  } finally { closeSync(fd); }
}
