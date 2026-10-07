// Local journals must survive a host crash before the caller broadcasts or starts a handler.
// Atomic rename alone only protects readers; flush both contents and directory entries.
import { randomUUID } from "node:crypto";
import { closeSync, fsyncSync, mkdirSync, openSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

function syncDirectory(path: string): void {
  const fd = openSync(path, "r");
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/** Flush ancestors too: an existing directory may have been created by the run driver. */
export function ensureDurableDirectory(path: string): void {
  mkdirSync(path, { recursive: true });
  let current = resolve(path);
  for (;;) {
    syncDirectory(current);
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
}

/** Exclusive creation: a failed flush leaves the reservation blocking reuse, never usable. */
export function createDurableFile(path: string, data: string): void {
  const fd = openSync(path, "wx", 0o600);
  try {
    writeFileSync(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  syncDirectory(dirname(path));
}

/** A throw at any stage prevents subsequent broadcast/handler execution. */
export function replaceDurableFile(path: string, data: string): void {
  const tmp = `${path}.tmp-${randomUUID()}`;
  try {
    createDurableFile(tmp, data);
    renameSync(tmp, path);
    syncDirectory(dirname(path));
  } finally {
    try {
      unlinkSync(tmp);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
}
