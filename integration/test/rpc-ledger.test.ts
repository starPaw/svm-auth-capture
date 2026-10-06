// Unit tests for `RpcLedger` (SAC-006) against an injected fake RPC client — no network access.
// Exercises genesis verification, Clock decoding, account mapping, simulation mapping, and the
// three-way `submit` classification (not-submitted / ambiguous submitted / finalized succeeded
// or failed), including the bounded-timeout and signature-mismatch edge cases.
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type Address,
  generateKeyPairSigner,
  getSignatureFromTransaction,
  lamports,
  type Rpc,
  SolanaError,
  SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE,
  type SolanaRpcApi,
  type Transaction,
} from "@solana/kit";
import { getTransferSolInstruction } from "@solana-program/system";
import { describe, expect, test } from "vitest";
import { loadDeploymentRecord } from "../src/deployment-record.js";
import { RpcLedger } from "../src/rpc-ledger.js";
import { buildTransaction } from "../src/transactions.js";

const GENESIS = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
const NETWORK = `solana:${GENESIS.slice(0, 32)}`;
const PROGRAM_ID = "992QmwmwCebawRJsTCgvc8qnzGivbFaD39ZQE7VhHp7o" as Address;

/** Wraps a plain value as the `{ send: () => Promise<T> }` shape every `@solana/kit` RPC builder returns. */
const sendable = <T>(value: T) => ({ send: () => Promise.resolve(value) });

/** A fake RPC exposing only the methods `RpcLedger` calls, each matching the real `.send()` shape. */
function fakeRpc(overrides: Partial<Record<keyof SolanaRpcApi, unknown>>): Rpc<SolanaRpcApi> {
  return overrides as unknown as Rpc<SolanaRpcApi>;
}

async function sampleTransaction(): Promise<Transaction> {
  const [feePayer, destination] = await Promise.all([generateKeyPairSigner(), generateKeyPairSigner()]);
  return buildTransaction({
    feePayer: feePayer.address,
    instructions: [
      getTransferSolInstruction({ source: feePayer, destination: destination.address, amount: lamports(1n) }),
    ],
    signers: [feePayer],
    lifetime: { blockhash: "11111111111111111111111111111111111111111111" as never, lastValidBlockHeight: 1n },
  });
}

/** Builds a Clock sysvar account's base64 `data` for a given `unix_timestamp`. */
function clockBase64(unixTimestamp: bigint): string {
  const bytes = new Uint8Array(40);
  new DataView(bytes.buffer).setBigInt64(32, unixTimestamp, true);
  return Buffer.from(bytes).toString("base64");
}

describe("RpcLedger.verifyGenesis", () => {
  test("accepts a matching genesis", async () => {
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      rpc: fakeRpc({ getGenesisHash: () => sendable(GENESIS) }),
    });
    await expect(ledger.verifyGenesis()).resolves.toBeUndefined();
  });

  test("rejects a mismatched genesis", async () => {
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      rpc: fakeRpc({ getGenesisHash: () => sendable("Wrong1111111111111111111111111111111111111") }),
    });
    await expect(ledger.verifyGenesis()).rejects.toThrow(/genesis mismatch/);
  });
});

describe("RpcLedger.now", () => {
  test("decodes the Clock sysvar's unix_timestamp", async () => {
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      rpc: fakeRpc({
        getAccountInfo: () =>
          sendable({
            value: {
              data: [clockBase64(1_791_308_511n)],
              owner: "Sysvar1111111111111111111111111111111111111" as Address,
              lamports: lamports(1n),
              executable: false,
            },
          }),
      }),
    });
    await expect(ledger.now()).resolves.toBe(1_791_308_511n);
  });

  test("throws when the Clock sysvar account is missing", async () => {
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      rpc: fakeRpc({ getAccountInfo: () => sendable({ value: null }) }),
    });
    await expect(ledger.now()).rejects.toThrow(/Clock sysvar account not found/);
  });
});

describe("RpcLedger.getAccount", () => {
  test("maps a populated account", async () => {
    const owner = "11111111111111111111111111111111111111111" as Address;
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      rpc: fakeRpc({
        getAccountInfo: () =>
          sendable({
            value: { data: [Buffer.from([1, 2, 3]).toString("base64")], owner, lamports: lamports(5n), executable: true },
          }),
      }),
    });
    const account = await ledger.getAccount(PROGRAM_ID);
    expect(account).toEqual({ owner, data: new Uint8Array([1, 2, 3]), lamports: 5n, executable: true });
  });

  test("returns null for a missing account", async () => {
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      rpc: fakeRpc({ getAccountInfo: () => sendable({ value: null }) }),
    });
    await expect(ledger.getAccount(PROGRAM_ID)).resolves.toBeNull();
  });
});

describe("RpcLedger.simulate", () => {
  test("maps a clean simulation to ok", async () => {
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      rpc: fakeRpc({ simulateTransaction: () => sendable({ value: { err: null, logs: [] } }) }),
    });
    await expect(ledger.simulate(await sampleTransaction())).resolves.toEqual({ ok: true });
  });

  test("maps a failed simulation to its error and logs", async () => {
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      rpc: fakeRpc({
        simulateTransaction: () => sendable({ value: { err: { InstructionError: [0, "Custom"] }, logs: ["log a", "log b"] } }),
      }),
    });
    const outcome = await ledger.simulate(await sampleTransaction());
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.logs).toEqual(["log a", "log b"]);
      expect(outcome.error).toContain("InstructionError");
    }
  });
});

describe("RpcLedger.submit", () => {
  test("classifies a preflight rejection as not-submitted", async () => {
    const preflightError = new SolanaError(SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE, {
      accounts: null,
      fee: null,
      innerInstructions: null,
      loadedAccountsDataSize: null,
      loadedAddresses: null,
      logs: ["simulation failed"],
      postBalances: null,
      postTokenBalances: null,
      preBalances: null,
      preTokenBalances: null,
      replacementBlockhash: null,
      returnData: null,
      unitsConsumed: null,
    });
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      rpc: fakeRpc({
        sendTransaction: () => ({
          send: () => Promise.reject(preflightError),
        }),
      }),
    });
    const result = await ledger.submit(await sampleTransaction());
    expect(result.kind).toBe("not-submitted");
  });

  test("classifies a generic send failure as ambiguous submitted", async () => {
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      rpc: fakeRpc({ sendTransaction: () => ({ send: () => Promise.reject(new Error("transport timeout")) }) }),
    });
    const result = await ledger.submit(await sampleTransaction());
    expect(result).toEqual({ kind: "submitted" });
  });

  test("classifies a signature mismatch as ambiguous submitted", async () => {
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      rpc: fakeRpc({ sendTransaction: () => sendable("UnrelatedSignature1111111111111111111111111111111111111111111111111111111111111111") }),
    });
    const result = await ledger.submit(await sampleTransaction());
    expect(result).toEqual({ kind: "submitted" });
  });

  test("reports a finalized success for the matched signature", async () => {
    const transaction = await sampleTransaction();
    const signature = getSignatureFromTransaction(transaction);
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      pollIntervalMs: 1,
      rpc: fakeRpc({
        sendTransaction: () => sendable(signature),
        getSignatureStatuses: () => sendable({ value: [{ confirmationStatus: "finalized", err: null }] }),
      }),
    });
    const result = await ledger.submit(transaction);
    expect(result).toEqual({ kind: "submitted", outcome: { status: "succeeded", commitment: "finalized" } });
  });

  test("reports a finalized failure with fetched logs for the matched signature", async () => {
    const transaction = await sampleTransaction();
    const signature = getSignatureFromTransaction(transaction);
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      pollIntervalMs: 1,
      rpc: fakeRpc({
        sendTransaction: () => sendable(signature),
        getSignatureStatuses: () =>
          sendable({ value: [{ confirmationStatus: "finalized", err: { InstructionError: [0, "Custom"] } }] }),
        getTransaction: () => sendable({ meta: { logMessages: ["failure log"] } }),
      }),
    });
    const result = await ledger.submit(transaction);
    expect(result.kind).toBe("submitted");
    if (result.kind === "submitted" && result.outcome?.status === "failed") {
      expect(result.outcome.logs).toEqual(["failure log"]);
    } else {
      throw new Error(`expected a finalized failure, got ${JSON.stringify(result)}`);
    }
  });

  test("stays ambiguous (undefined outcome) when the bounded wait is exhausted", async () => {
    const transaction = await sampleTransaction();
    const signature = getSignatureFromTransaction(transaction);
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      confirmTimeoutMs: 5,
      pollIntervalMs: 1,
      rpc: fakeRpc({
        sendTransaction: () => sendable(signature),
        getSignatureStatuses: () => sendable({ value: [null] }),
      }),
    });
    const result = await ledger.submit(transaction);
    expect(result).toEqual({ kind: "submitted", outcome: undefined });
  });
});

describe("loadDeploymentRecord", () => {
  test("accepts a verified v1 record", () => {
    const dir = mkdtempSync(join(tmpdir(), "sac006-record-"));
    const path = join(dir, "deployment-identity.v1.json");
    writeFileSync(
      path,
      JSON.stringify({
        schema_version: 1,
        record_status: "verified",
        network: { cluster: "devnet", genesis_hash: GENESIS, caip2: NETWORK },
        program: { program_id: PROGRAM_ID, executable: true },
      }),
    );
    const record = loadDeploymentRecord(path);
    expect(record).toEqual({ network: { cluster: "devnet", genesisHash: GENESIS, caip2: NETWORK }, programId: PROGRAM_ID });
  });

  test("rejects an unpopulated template", () => {
    const dir = mkdtempSync(join(tmpdir(), "sac006-record-"));
    const path = join(dir, "deployment-identity.v1.json");
    writeFileSync(path, JSON.stringify({ schema_version: 1, record_status: "template" }));
    expect(() => loadDeploymentRecord(path)).toThrow(/record_status is "template"/);
  });

  test("rejects a CAIP-2 mismatch", () => {
    const dir = mkdtempSync(join(tmpdir(), "sac006-record-"));
    const path = join(dir, "deployment-identity.v1.json");
    writeFileSync(
      path,
      JSON.stringify({
        schema_version: 1,
        record_status: "verified",
        network: { cluster: "devnet", genesis_hash: GENESIS, caip2: "solana:wrong" },
        program: { program_id: PROGRAM_ID, executable: true },
      }),
    );
    expect(() => loadDeploymentRecord(path)).toThrow(/does not equal/);
  });
});
