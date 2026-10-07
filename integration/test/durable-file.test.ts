import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test, vi } from "vitest";
import { createDurableFile, replaceDurableFile } from "../src/durable-file.ts";
import { OperationStore } from "../src/operation-store.ts";

const fault = vi.hoisted(() => ({ fail: "" as "" | "file" | "directory", flushes: [] as string[] }));
vi.mock("node:fs", async (original) => {
  const fs = await original<typeof import("node:fs")>();
  return { ...fs, fsyncSync: (fd: number) => {
    const kind = fs.fstatSync(fd).isDirectory() ? "directory" : "file";
    fault.flushes.push(kind);
    if (fault.fail === kind) throw new Error(`injected ${kind} flush failure`);
    fs.fsyncSync(fd);
  } };
});
afterEach(() => { fault.fail = ""; fault.flushes = []; });

test("exclusive reservations are acknowledged only after file and directory flushes", () => {
  const dir = mkdtempSync(join(tmpdir(), "sac006-durable-"));
  const store = new OperationStore(dir);
  fault.flushes = [];
  store.reserve("fp", "payer", "/resource");
  expect(fault.flushes).toEqual(["file", "directory"]);
});

test("a directory flush failure denies reservation and leaves reuse blocked", () => {
  const store = new OperationStore(mkdtempSync(join(tmpdir(), "sac006-durable-")));
  fault.fail = "directory";
  expect(() => store.reserve("fp", "payer", "/resource")).toThrow(/flush failure/);
  fault.fail = "";
  expect(() => store.reserve("fp", "payer", "/resource")).toThrow(/already reserved/);
});

test("a failed content flush cannot replace the last durable state", () => {
  const dir = mkdtempSync(join(tmpdir(), "sac006-durable-"));
  const path = join(dir, "record.json");
  createDurableFile(path, "before");
  fault.fail = "file";
  expect(() => replaceDurableFile(path, "after")).toThrow(/flush failure/);
  expect(readFileSync(path, "utf8")).toBe("before");
  expect(readdirSync(dir)).toEqual(["record.json"]);
});
