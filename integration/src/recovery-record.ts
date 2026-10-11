// Private immutable application evidence; not a broadcast queue. No replacement primitive.
import { constants, closeSync, fchmodSync, fstatSync, fsyncSync, openSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
export function createRecoveryRecord<T extends object>(path: string, body: T): string {
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  let raw: string;
  try {
    const s = fstatSync(fd,{ bigint:true });
    raw = JSON.stringify({ ...body, recordIdentity:`${s.dev}:${s.ino}` });
    writeFileSync(fd,raw); fchmodSync(fd,0o400); fsyncSync(fd);
  } finally { closeSync(fd); }
  const directory = openSync(dirname(path),constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { fsyncSync(directory); } finally { closeSync(directory); }
  return raw;
}
