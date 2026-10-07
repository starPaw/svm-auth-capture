import { generateKeyPairSigner, type Address } from "@solana/kit";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { transferSetupTokens } from "../operators/chains.ts";
import { FileSubmissionJournal } from "../src/submission-journal.ts";
import { AccountState, getTokenEncoder } from "@solana-program/token";
import { expect, test } from "vitest";
import { type Context, type Snapshot, finalizedSlot, snapshot, unchanged } from "../operators/lib.ts";
import { ata, LOCAL_PROGRAM_ID, TOKEN_PROGRAM_ADDRESS } from "../src/program.ts";
import type { SlotAccount } from "../src/reconciliation.ts";

const payer = "11111111111111111111111111111112" as Address;
const server = "11111111111111111111111111111113" as Address;
const mint = "11111111111111111111111111111114" as Address;

test.each([undefined, { status: "succeeded", commitment: "confirmed" }])("setup transfers retain original bytes and never retry an unresolved result: %j", async (outcome) => {
  const [sponsor, payer, server] = await Promise.all([generateKeyPairSigner(), generateKeyPairSigner(), generateKeyPairSigner()]);
  const journal = new FileSubmissionJournal(mkdtempSync(join(tmpdir(), "sac006-setup-")));
  let sends = 0;
  const c = { sponsor, payer, server, mint, ledger: {
    latestBlockhash: async () => ({ blockhash: "11111111111111111111111111111111", lastValidBlockHeight: 1n }),
    submit: async () => { sends += 1; expect(journal.list()).toHaveLength(1); return { kind: "submitted", outcome }; },
  } } as unknown as Context;
  await expect(transferSetupTokens(c, journal, payer, server.address, 1n)).rejects.toThrow(/stop for original-signature reconciliation/);
  expect(sends).toBe(1);
  expect(journal.list()[0]?.transactionBase64).toBeTruthy();
});

async function fixture(read?: (a: Address, slot: bigint) => Promise<SlotAccount>) {
  const payerAta = await ata(payer, mint);
  const reads: bigint[] = [];
  const c = {
    record: { programId: LOCAL_PROGRAM_ID }, payer: { address: payer }, server: { address: server }, mint,
    ledger: {
      now: async () => 1000n,
      getAccountAtLeast: async (a: Address, slot: bigint): Promise<SlotAccount> => {
        reads.push(slot);
        if (read) return read(a, slot);
        return { kind: "ok", slot, account: { owner: TOKEN_PROGRAM_ADDRESS, data: new Uint8Array(getTokenEncoder().encode({ mint, owner: a === payerAta ? payer : server, amount: 10n, delegate: null, state: AccountState.Initialized, isNative: null, delegatedAmount: 0n, closeAuthority: null })), lamports: 1n, executable: false } };
      },
    },
  } as unknown as Context;
  return { c, reads };
}

test("post-transaction balance reads share the exact required slot", async () => {
  const { c, reads } = await fixture();
  const state = await snapshot(c, "after finalized transfer", undefined, 123n);
  expect(reads).toEqual([123n, 123n]);
  expect(state).toMatchObject({ balanceSlot: "123", payerAta: "10", serverAta: "10" });
});

test("provider outages cannot become absent balances or preservation evidence", async () => {
  const { c } = await fixture(async () => ({ kind: "unavailable", detail: "429" }));
  await expect(snapshot(c, "provider outage")).rejects.toThrow(/balance snapshot unavailable/);
  const historical = { payerAta: "absent", serverAta: "absent", balanceSlot: "0" } as Snapshot;
  expect(unchanged(historical, historical)).toBe(false);
});

test("even a misbehaving reader cannot provide stale balance evidence", async () => {
  const { c } = await fixture(async () => ({ kind: "ok", slot: 1n, account: null }));
  await expect(snapshot(c, "stale", undefined, 123n)).rejects.toThrow(/predates/);
});

test("success evidence rejects a signature whose finality is unavailable", async () => {
  const { c } = await fixture();
  c.ledger.getSignatureStatus = async () => ({ kind: "unavailable", detail: "malformed" });
  await expect(finalizedSlot(c, "signature")).rejects.toThrow(/evidence remains unknown/);
});
