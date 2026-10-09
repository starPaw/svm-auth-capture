import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { getBase64EncodedWireTransaction, partiallySignTransaction, type Transaction } from "@solana/kit";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { attestObservation, relayProvenance, retainObservation, transactionObservation,
  type LifetimeObservation, type OriginReader } from "../src/lifetime-provenance.ts";
import { Facilitator } from "../src/facilitator.ts";
import { FileSubmissionJournal, messageHash } from "../src/submission-journal.ts";
import { authorizePayload, capturePayload, refundPayload, voidPayload, buildTransaction, reclaimInstruction, authorizeInstruction } from "../src/transactions.ts";
import { createHarness, type Harness } from "./fixture.ts";
import { getSetComputeUnitLimitInstruction as limit, getSetComputeUnitPriceInstruction as price } from "./compute-budget.ts";

const GENESIS = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
const NETWORK = `solana:${GENESIS.slice(0, 32)}`;
const KEY = "synthetic-existing-bearer-test-key";
let h: Harness, journal: FileSubmissionJournal, dir: string;
beforeEach(async () => { h = await createHarness(); dir = mkdtempSync(join(tmpdir(), "relay-provenance-")); journal = new FileSubmissionJournal(dir); });
afterEach(async () => { await h.close(); });
const observation = (tx: Transaction): LifetimeObservation => ({ version: 1, messageHash: messageHash(tx.messageBytes),
  blockhash: h.lifetime().blockhash, lastValidBlockHeight: "18446744073709551615", contextSlot: "9007199254740993",
  commitment: "finalized", network: NETWORK, genesisHash: GENESIS });
const reader: OriginReader = { verifyBlockhashOrigin: async (blockhash, slot, genesisHash, network) =>
  ({ state: "verified", blockhash, slot: slot.toString(), genesisHash, network, commitment: "finalized" }) };
function facilitator(originReader: OriginReader = reader) {
  return new Facilitator({ network: NETWORK, programId: h.facilitator.programId, feePayer: h.facilitatorKey, journal, observationKey: KEY,
    ledger: { network: NETWORK, now: () => h.ledger.now(), getAccount: a => h.ledger.getAccount(a), simulate: t => h.ledger.simulate(t),
      submit: t => h.ledger.submit(t), ...originReader } });
}
function body(payload: Record<string, unknown>, transport?: unknown) {
  const req = { ...h.requirements(), network: NETWORK };
  return { x402Version: 2, paymentPayload: { x402Version: 2, accepted: req, payload }, paymentRequirements: req, lifetimeObservation: transport };
}

// Every operation executes the accepted SBF; provenance never changes its economic consent.
test.each(["authorize", "capture", "capture+void", "void", "refund"])("%s retains original wire, economic signature and provenance before submit", async op => {
  let tx: Transaction, payload: Record<string, unknown>;
  if (op === "authorize") { tx = await h.signedAuthorize({ salt: h.newSalt() }); payload = authorizePayload(tx); }
  else {
    const p = await h.authorized();
    if (op === "refund") { expect((await h.post("/settle", h.body(await h.capture(p, 20n, false, 100n, 0n)))).json.success).toBe(true);
      tx = await h.signedRefund(p, 10n, 80n, 20n); payload = refundPayload(p, tx, 10n, 80n, 20n); }
    else if (op === "void") { tx = await h.signedVoid(p, 100n, 0n); payload = voidPayload(p, tx, 100n, 0n); }
    else { tx = await h.signedCapture(p, 20n, op === "capture+void", 100n, 0n); payload = capturePayload(p, tx, 20n, op === "capture+void", 100n, 0n); }
  }
  const wire = getBase64EncodedWireTransaction(await partiallySignTransaction([h.facilitatorKey.keyPair], tx));
  const value = observation(tx);
  h.ledger.beforeSubmit = () => {
    const prepared = journal.list()[0]!;
    expect(prepared.transactionBase64).toBe(wire);
    expect(prepared.attempts[0]!.outcome).toBeUndefined();
    expect(prepared.lifetimeProvenance).toEqual({ version: 1, messageHash: value.messageHash, blockhash: value.blockhash,
      observation: { state: "recorded", source: "first-party", value }, origin: { state: "verified", blockhash: value.blockhash,
        slot: value.contextSlot, commitment: "finalized", network: NETWORK, genesisHash: GENESIS } });
    expect(prepared.blockhashSlot).toBeUndefined(); // No claim under the old reclaim semantics.
    expect(prepared.lastValidBlockHeight).toBeUndefined();
  };
  const result = await facilitator().settle(body(payload, attestObservation(value, KEY)));
  expect(result.success).toBe(true);
  expect(journal.read(result.transaction)!.transactionBase64).toBe(wire);
});

test.each([{ extra: [] }, { extra: [limit(200000)] },
  { extra: [limit(200000), price(1000n)] }])(
  "complete message binding includes compute-budget variant %j", async ({ extra }) => {
    const tx = await h.signedAuthorize({ salt: h.newSalt(), extra });
    const value = observation(tx), before = getBase64EncodedWireTransaction(tx);
    const result = await facilitator().settle(body(authorizePayload(tx), attestObservation(value, KEY)));
    expect(result.success).toBe(true); expect(getBase64EncodedWireTransaction(tx)).toBe(before);
    expect(journal.read(result.transaction)!.messageHash).toBe(value.messageHash);
  });

const corruptions: [string, (o: any) => void][] = [
  ["unsafe height number", o => { o.lastValidBlockHeight = 9007199254740993; }],
  ["unsafe slot number", o => { o.contextSlot = 9007199254740993; }],
  ["height overflow", o => { o.lastValidBlockHeight = "18446744073709551616"; }],
  ["slot overflow", o => { o.contextSlot = "18446744073709551616"; }],
  ["negative height", o => { o.lastValidBlockHeight = "-1"; }],
  ["negative slot", o => { o.contextSlot = "-1"; }],
  ["fraction", o => { o.lastValidBlockHeight = "1.5"; }],
  ["exponent", o => { o.contextSlot = "1e5"; }],
  ["leading zero", o => { o.contextSlot = "01"; }],
  ["oversized decimal", o => { o.contextSlot = "9".repeat(10000); }],
  ["missing genesis", o => { delete o.genesisHash; }],
  ["invented commitment", o => { o.commitment = "canonical"; }],
  ["untrusted authority", o => { o.source = "first-party"; }],
];
test.each(corruptions)("%s is explicit unavailable evidence and does not refuse payment", async (_label, corrupt) => {
  const tx = await h.signedAuthorize({ salt: h.newSalt() }); const value = observation(tx); corrupt(value);
  const check = vi.fn(reader.verifyBlockhashOrigin);
  const result = await facilitator({ verifyBlockhashOrigin: check }).settle(body(authorizePayload(tx), { observation: value }));
  expect(result.success).toBe(true); expect(check).not.toHaveBeenCalled();
  expect(journal.read(result.transaction)!.lifetimeProvenance!.observation).toEqual({ state: "unavailable", reason: "invalid" });
});

test.each(["message", "blockhash", "borrowed-order", "borrowed-payer", "borrowed-reclaim"])("%s substitution never qualifies or changes signed bytes", async field => {
  const tx = await h.signedAuthorize({ salt: h.newSalt() });
  let other = await h.signedAuthorize({ salt: h.newSalt() });
  if (field === "borrowed-reclaim") other = await buildTransaction({ feePayer: h.payer.address, signers: [h.payer], lifetime: h.lifetime(),
    instructions: [await reclaimInstruction({ programId: h.facilitator.programId, payment: await h.paymentFor(h.newSalt()),
      payer: h.payer.address, server: h.server.address, mint: h.mint })] });
  if (field === "borrowed-payer") other = await buildTransaction({ feePayer: h.facilitatorKey.address, signers: [h.outsider], lifetime: h.lifetime(),
    instructions: [await authorizeInstruction({ programId: h.facilitator.programId, payer: h.outsider.address, server: h.server.address,
      mint: h.mint, funder: h.facilitatorKey.address, salt: h.newSalt(), maximum: 100n, captureDeadline: 1100n, refundDeadline: 1200n })] });
  const value = observation(field.startsWith("borrowed") ? other : tx);
  if (field === "message") value.messageHash = "a".repeat(64);
  if (field === "blockhash") value.blockhash = GENESIS;
  const check = vi.fn(reader.verifyBlockhashOrigin);
  const result = await facilitator({ verifyBlockhashOrigin: check }).settle(body(authorizePayload(tx), attestObservation(value, KEY)));
  expect(result.success).toBe(true); expect(check).not.toHaveBeenCalled();
  expect(journal.read(result.transaction)!.lifetimeProvenance!.origin).toMatchObject({ state: "unverified", reason: "binding-mismatch" });
});

test.each(["height", "slot", "genesis", "key"])("forged %s cannot overwrite first-party recording", async field => {
  const tx = await h.signedAuthorize({ salt: h.newSalt() });
  const transport = attestObservation(observation(tx), KEY);
  if (field === "height") transport.observation.lastValidBlockHeight = "123";
  if (field === "slot") transport.observation.contextSlot = "123";
  if (field === "genesis") transport.observation.genesisHash = h.lifetime().blockhash;
  if (field === "key") transport.attestation = "0".repeat(64);
  const proof = await relayProvenance(tx, transport, NETWORK, reader, KEY);
  expect(proof.observation).toMatchObject({ state: "recorded", source: "request" });
  if (field === "genesis") expect(proof.origin).toMatchObject({ state: "unverified", reason: "network-mismatch" });
  // A matching block may independently qualify origin even for a request observation.
  // It never authenticates request lastValidBlockHeight or supplies receipt/recovery authority.
});

test("missing metadata stays explicit; no fresh lifetime is fetched", async () => {
  const tx = await h.signedAuthorize({ salt: h.newSalt() }); const check = vi.fn(reader.verifyBlockhashOrigin);
  const result = await facilitator({ verifyBlockhashOrigin: check }).settle(body(authorizePayload(tx)));
  expect(result.success).toBe(true); expect(check).not.toHaveBeenCalled();
  expect(journal.read(result.transaction)!.lifetimeProvenance!.observation).toEqual({ state: "unavailable", reason: "missing" });
});

test("recording copies scalars and does not infer context from legacy blockhashSlot", async () => {
  const tx = await h.signedAuthorize({ salt: h.newSalt() }); const lifetime = { ...h.lifetime(), blockhashSlot: 10n };
  retainObservation(tx, lifetime); lifetime.lastValidBlockHeight = 12n;
  expect(transactionObservation(tx)!.lastValidBlockHeight).toBe("1000000");
  expect(transactionObservation(tx)!.contextSlot).toBeNull();
});

test("an unavailable verifier permits one submit; lost result/restart never rebroadcasts", async () => {
  const tx = await h.signedAuthorize({ salt: h.newSalt() }); const value = observation(tx);
  h.ledger.failSubmit = "after-landing";
  const submittedBefore = h.ledger.submissions.length;
  const request = body(authorizePayload(tx), attestObservation(value, KEY));
  const f = facilitator({ verifyBlockhashOrigin: async () => { throw new Error("pruned"); } });
  const first = await f.settle(request); expect(first.errorReason).toBe("settlement_pending");
  const bytes = readFileSync(join(dir, `${first.transaction}.json`));
  const second = await facilitator().settle({ ...request, lifetimeObservation: { observation: observation(tx) } });
  expect(second.transaction).toBe(first.transaction); expect(h.ledger.submissions.length - submittedBefore).toBe(1);
  expect(readFileSync(join(dir, `${first.transaction}.json`))).toEqual(bytes);
  expect(journal.read(first.transaction)!.lifetimeProvenance!.origin).toMatchObject({ state: "unverified", reason: "lookup-unavailable" });
});

test("concurrent different metadata joins original and preserves its trusted evidence", async () => {
  const tx = await h.signedAuthorize({ salt: h.newSalt() }); const value = observation(tx);
  let release!: () => void; const blocked = new Promise<void>(r => { release = r; });
  let entered!: () => void; const ready = new Promise<void>(r => { entered = r; });
  const f = facilitator({ verifyBlockhashOrigin: async (...args) => { entered(); await blocked; return reader.verifyBlockhashOrigin(...args); } });
  const first = f.settle(body(authorizePayload(tx), attestObservation(value, KEY)));
  await ready;
  const second = f.settle(body(authorizePayload(tx), { observation: { ...value, lastValidBlockHeight: "1" } }));
  release(); const results = await Promise.all([first, second]);
  expect(results.filter(r => r.success)).toHaveLength(1); expect(journal.list()).toHaveLength(1);
  expect(journal.list()[0]!.lifetimeProvenance!.observation).toEqual({ state: "recorded", source: "first-party", value });
});

test.each(["before-prepare", "after-prepare", "after-submit"])("SIGKILL %s retains exact bytes and reservations across process restart", async boundary => {
  const tx = await h.signedAuthorize({ salt: h.newSalt() }); const signed = await partiallySignTransaction([h.facilitatorKey.keyPair], tx);
  const wire = getBase64EncodedWireTransaction(signed);
  const { getSignatureFromTransaction } = await import("@solana/kit");
  const signature = getSignatureFromTransaction(signed);
  const provenance = await relayProvenance(signed, attestObservation(observation(tx), KEY), NETWORK, reader, KEY);
  const entry = { signature, messageHash: messageHash(tx.messageBytes), transactionBase64: wire, blockhash: h.lifetime().blockhash,
    operation: "authorize", payment: "synthetic", payer: h.payer.address, expectedHeld: "0", expectedRefundable: "0", lifetimeProvenance: provenance };
  const input = join(dir, "input.txt"); writeFileSync(input, JSON.stringify(entry));
  const code = `import {readFileSync,writeFileSync} from 'node:fs';
    import {FileSubmissionJournal} from ${JSON.stringify(resolve("src/submission-journal.ts"))};
    const j=new FileSubmissionJournal(${JSON.stringify(dir)});
    const kill=()=>process.kill(process.pid,'SIGKILL');
    if(${JSON.stringify(boundary)}==='before-prepare')kill();
    j.prepare(JSON.parse(readFileSync(${JSON.stringify(input)},'utf8')));
    if(${JSON.stringify(boundary)}==='after-submit')writeFileSync(${JSON.stringify(join(dir, "synthetic-submit.txt"))},'one');
    kill();`;
  const child = spawnSync(process.execPath, ["--experimental-strip-types", "--input-type=module", "-e", code], { timeout: 10000 });
  expect(child.signal, child.stderr?.toString()).toBe("SIGKILL");
  const previous = journal.read(signature);
  if (boundary === "before-prepare") { expect(previous).toBeUndefined(); return; }
  expect(previous!.transactionBase64).toBe(wire); expect(previous!.lifetimeProvenance).toEqual(provenance);
  const submit = vi.spyOn(h.ledger, "submit");
  const result = await facilitator().settle(body(authorizePayload(tx)));
  expect(result).toMatchObject({ errorReason: "settlement_pending", transaction: signature }); expect(submit).not.toHaveBeenCalled();
  expect(journal.read(signature)!.attempts[0]!.outcome).toBeUndefined();
});

test("legacy read keeps exact bytes and absent metadata; restart leaves unknown unknown", async () => {
  const tx = await h.signedAuthorize({ salt: h.newSalt() });
  const value = { signature: "legacy", messageHash: messageHash(tx.messageBytes), transactionBase64: "synthetic-original", blockhash: h.lifetime().blockhash,
    operation: "authorize", payment: "p", payer: h.payer.address, expectedHeld: "0", expectedRefundable: "0", attempts: [{ preparedAt: "original" }] };
  const path = join(dir, "legacy.json"); const bytes = JSON.stringify(value) + "\n"; writeFileSync(path, bytes);
  expect(journal.read("legacy")!.lifetimeProvenance).toBeUndefined(); expect(journal.findByMessageHash(value.messageHash)).toHaveLength(1);
  expect((await facilitator().settle(body(authorizePayload(tx)))).transaction).toBe("legacy");
  expect(readFileSync(path, "utf8")).toBe(bytes);
});

test.each(["blockhash", "slot", "genesisHash", "network", "commitment"])("unrelated reader %s cannot qualify", async field => {
  const tx = await h.signedAuthorize({ salt: h.newSalt() }); const value = observation(tx);
  const proof = await relayProvenance(tx, { observation: value }, NETWORK, { verifyBlockhashOrigin: async (...args) => {
    const origin = await reader.verifyBlockhashOrigin(...args);
    return { ...origin, [field]: "wrong" } as never;
  } });
  expect(proof.origin).toMatchObject({ state: "unverified", reason: "binding-mismatch" });
});
