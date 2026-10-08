import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test, expect } from "vitest";
import { prepareKeys, reserveOperation } from "../operators/dev-environment.ts";

test("dev identities are distinct, private and never overwritten on a second preparation", () => {
  const directory = mkdtempSync(join(tmpdir(), "capture402-dev-keys-"));
  const identities = prepareKeys(directory);
  expect(new Set(Object.values(identities)).size).toBe(4);
  const before = readFileSync(join(directory, "keys/sponsor.json"), "utf8");
  expect(JSON.parse(before)).toHaveLength(64);
  expect(statSync(join(directory, "keys/sponsor.json")).mode & 0o777).toBe(0o600);
  expect(() => prepareKeys(directory)).toThrow(/never overwrite/);
  expect(readFileSync(join(directory, "keys/sponsor.json"), "utf8")).toBe(before);
});

test.each(["funding", "asset-preparation"])("an unresolved %s reservation blocks replacement bytes", operation => {
  const directory = mkdtempSync(join(tmpdir(), "capture402-dev-operation-"));
  reserveOperation(directory, operation, { transactionBase64: "original-wire", signature: "original-signature" });
  const before = readFileSync(join(directory, `${operation}.json`), "utf8");
  expect(() => reserveOperation(directory, operation, { transactionBase64: "replacement-wire" })).toThrow();
  expect(readFileSync(join(directory, `${operation}.json`), "utf8")).toBe(before);
  expect(statSync(join(directory, `${operation}.json`)).mode & 0o777).toBe(0o600);
});

test("dev preparation refuses arbitrary journal operation names", () => {
  expect(() => reserveOperation(tmpdir(), "../../live", {})).toThrow(/unknown/);
});
