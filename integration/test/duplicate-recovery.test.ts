import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, expect, test } from "vitest";
import { Facilitator } from "../src/facilitator.ts";
import { FileSubmissionJournal } from "../src/submission-journal.ts";
import { authorizePayload } from "../src/transactions.ts";
import { Reason } from "../src/types.ts";
import { createHarness, DC, NOW, type Harness } from "./fixture.ts";

let h: Harness;
beforeAll(async () => { h = await createHarness(); });
afterAll(async () => { await h.close(); });

test.each(["authorize", "capture"] as const)("a concurrent %s after landing retains the unresolved original signature", async (operation) => {
  const journal = new FileSubmissionJournal(mkdtempSync(join(tmpdir(), "sac006-duplicate-recovery-")));
  const facilitator = new Facilitator({ network: h.ledger.network, programId: h.facilitator.programId, feePayer: h.facilitatorKey, ledger: h.ledger, journal });
  const body = operation === "authorize"
    ? h.body(authorizePayload(await h.signedAuthorize({ salt: h.newSalt() })))
    : h.body(await h.capture(await h.authorized(), 30n, false, 100n, 0n));
  const submit = h.ledger.submit;
  let entered!: () => void;
  const landed = new Promise<void>(resolve => { entered = resolve; });
  let release!: () => void;
  const blocked = new Promise<void>(resolve => { release = resolve; });
  const submissions = h.ledger.submissions.length;
  h.ledger.submit = async (transaction) => {
    const result = await submit.call(h.ledger, transaction);
    expect(result).toMatchObject({ kind: "submitted", outcome: { status: "succeeded" } });
    entered();
    await blocked;
    return { kind: "submitted" };
  };
  try {
    const firstP = facilitator.settle(body);
    await landed;
    h.setTime(DC); // Both changed state and an expired capture window must not change attribution.
    const duplicateP = facilitator.settle(body);
    release();
    const [first, duplicate] = await Promise.all([firstP, duplicateP]);
    expect(first).toMatchObject({ success: false, errorReason: Reason.settlementPending });
    expect(first.transaction).not.toBe("");
    expect(duplicate).toEqual(first);
    expect(h.ledger.submissions.length).toBe(submissions + 1);
    expect(journal.list()).toHaveLength(1);
  } finally {
    release();
    h.ledger.submit = submit;
    h.setTime(NOW);
  }
});
