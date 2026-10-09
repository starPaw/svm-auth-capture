import { mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, expect, test, vi } from "vitest";
import { FileSubmissionJournal } from "../src/submission-journal.ts";
import { Facilitator } from "../src/facilitator.ts";
import { authorizePayload } from "../src/transactions.ts";
import { attestObservation, transactionObservation } from "../src/lifetime-provenance.ts";
import { createHarness } from "./fixture.ts";
const fault = vi.hoisted(() => ({ kind: "" }));
vi.mock("node:fs", async original => {
  const fs = await original<typeof import("node:fs")>();
  return { ...fs, fsyncSync: (fd: number) => {
    const kind = fs.fstatSync(fd).isDirectory() ? "directory" : "file";
    if (fault.kind === kind) throw new Error("synthetic flush failure");
    fs.fsyncSync(fd);
  }, openSync: (...args: Parameters<typeof fs.openSync>) => {
    if (fault.kind === "create" && args[1] === "wx") throw new Error("synthetic create failure");
    return fs.openSync(...args);
  } };
});
afterEach(() => { fault.kind = ""; });
test.each(["create", "file", "directory"])("%s failure blocks submit with metadata and retains failed reservation", async kind => {
  const h = await createHarness();
  try {
    const journal = new FileSubmissionJournal(mkdtempSync(join(tmpdir(), "relay-fsync-")));
    const f = () => new Facilitator({ network: h.ledger.network, programId: h.facilitator.programId,
      feePayer: h.facilitatorKey, ledger: h.ledger, journal, observationKey: "synthetic-key" });
    const tx = await h.signedAuthorize({ salt: h.newSalt() });
    const body = { ...h.body(authorizePayload(tx)), lifetimeObservation: attestObservation(transactionObservation(tx)!, "synthetic-key") };
    const submit = vi.spyOn(h.ledger, "submit"); fault.kind = kind;
    const result = await f().settle(body); fault.kind = "";
    expect(result.errorReason).toBe("settlement_not_submitted"); expect(submit).not.toHaveBeenCalled();
    if (kind !== "create") {
      expect(journal.list()).toHaveLength(1);
      expect((await f().settle(body)).errorReason).toBe("settlement_pending"); expect(submit).not.toHaveBeenCalled();
    }
  } finally { fault.kind = ""; await h.close(); }
});
