import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test, expect } from "vitest";
import { prepareKeys, reserveOperation, preparationArguments } from "../operators/dev-environment.ts";
import { validateSmokeView } from "../operators/dev-smoke.ts";
import type { Address } from "@solana/kit";

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

test("dev smoke requires both original finalized signatures and exact released budget", () => {
  const view = { status: "closed", payment: "unused-public-address" as Address, authorized: 100, captured: 0, refunded: 0, released: 100, remaining: 0,
    events: ["authorize", "void"].map(action => ({ action, status: "finalized", signature: `original-${action}`, chainStatus: { commitment: "finalized", err: null } })) };
  expect(() => validateSmokeView(view)).not.toThrow();
  expect(() => validateSmokeView({ ...view, remaining: 1 })).toThrow();
  expect(() => validateSmokeView({ ...view, events: view.events.slice(0, 1) })).toThrow();
  for (const commitment of ["confirmed", "unknown", undefined]) {
    expect(() => validateSmokeView({ ...view, events: [{ ...view.events[0]!, chainStatus: { commitment, err: null } }, view.events[1]!] })).toThrow();
  }
  expect(() => validateSmokeView({ ...view, events: [{ ...view.events[0]!, chainStatus: { commitment: "finalized", err: "failed" } }, view.events[1]!] })).toThrow();
});


test("E2E operator helper has fixed disjoint paths and rejects ambiguous arguments before work", () => {
  for (const action of ["keys", "fund", "asset", "observe"]) {
    expect(preparationArguments([action, "--profile", "e2e"])).toEqual({ action,
      private: "/etc/capture402-e2e", setup: "/var/lib/capture402-e2e/setup",
      record: "/opt/capture402-e2e/current/docs/evidence/sac-007/deployment-identity.v1.json" });
    expect(preparationArguments([action]).private).toBe("/etc/capture402-dev");
  }
  for (const args of [[], ["fund", "e2e"], ["fund", "--profile", "other"], ["fund", "--profile", "e2e", "extra"], ["reset", "--profile", "e2e"]]) {
    expect(() => preparationArguments(args)).toThrow(/expected/);
  }
});
