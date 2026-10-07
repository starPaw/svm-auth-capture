// Unit tests for `RpcLedger` (SAC-006) against an injected fake RPC client — no network access.
// Exercises genesis verification, Clock decoding, account mapping, simulation mapping, the
// three-way `submit` classification (not-submitted / ambiguous submitted / finalized succeeded
// or failed), including the bounded-timeout, signature-mismatch, and already-processed edge
// cases (the latter through the installed SDK's own JSON-RPC error conversion), and the
// read-only `ChainReader` evidence used by reconciliation.
import {
  type Address,
  generateKeyPairSigner,
  getBase64EncodedWireTransaction,
  getCompiledTransactionMessageDecoder,
  getSignatureFromTransaction,
  getSolanaErrorFromJsonRpcError,
  lamports,
  type Rpc,
  SolanaError,
  SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE,
  type SolanaRpcApi,
  type Transaction,
} from "@solana/kit";
import { getTransferSolInstruction } from "@solana-program/system";
import { describe, expect, test } from "vitest";
import { cachedClusterClock, redactRpcUrl, RpcDeadlineExceeded, RpcLedger } from "../src/rpc-ledger.js";
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

  test("never puts RPC credentials in the mismatch error", async () => {
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "https://devnet.example-rpc.com/?api-key=secret-key-value",
      rpc: fakeRpc({ getGenesisHash: () => sendable("Wrong1111111111111111111111111111111111111") }),
    });
    const error = await ledger.verifyGenesis().catch((e: Error) => e);
    expect(String(error)).toMatch(/https:\/\/devnet\.example-rpc\.com \(credentials redacted\)/);
    expect(String(error)).not.toContain("secret-key-value");
    expect(redactRpcUrl("https://user:pw@rpc.example/v1?x=1")).toBe("https://rpc.example (credentials redacted)");
    expect(redactRpcUrl("https://api.devnet.solana.com")).toBe("https://api.devnet.solana.com");
    expect(redactRpcUrl("https://rpc.example/v2/SYNTHETIC_PATH_KEY#secret")).toBe("https://rpc.example (credentials redacted)");
    expect(redactRpcUrl("https://user:pw@rpc.example/token/?key=secret")).not.toMatch(/user|pw|token|secret/);
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
        simulateTransaction: () => sendable({ value: { err: { InstructionError: [0, { Custom: 6 }] }, logs: ["log a", "log b"] } }),
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

/** The exact error `@solana/kit` produces for a JSON-RPC sendTransaction preflight failure carrying `err`. */
function preflightFailure(err: unknown): unknown {
  return getSolanaErrorFromJsonRpcError({
    code: -32002,
    message: "Transaction simulation failed",
    data: { err, logs: [], accounts: null, unitsConsumed: 0, returnData: null },
  });
}

describe("RpcLedger.submit", () => {
  test.each(["ProviderInventedError", {}, { InstructionError: [0, { Custom: -1 }] }])("malformed preflight cause remains unresolved: %j", async (err) => {
    const ledger = new RpcLedger({ network: NETWORK, genesisHash: GENESIS, rpcUrl: "http://unused.invalid", confirmTimeoutMs: 10, pollIntervalMs: 1,
      rpc: fakeRpc({ sendTransaction: () => ({ send: () => Promise.reject(preflightFailure(err)) }) }) });
    expect((await ledger.submit(await sampleTransaction())).kind).toBe("submitted");
  });

  test.each([{}, { value: undefined }, { value: false }, { value: 0 }])("a malformed account response cannot establish absence: %j", async (response) => {
    const ledger = new RpcLedger({ network: NETWORK, genesisHash: GENESIS, rpcUrl: "http://unused.invalid", confirmTimeoutMs: 5, pollIntervalMs: 1,
      rpc: fakeRpc({ getAccountInfo: () => sendable({ context: { slot: 100n }, ...response }) }) });
    await expect(ledger.getAccount(PROGRAM_ID)).rejects.toThrow();
    expect((await ledger.getAccountAtLeast(PROGRAM_ID, 1n)).kind).toBe("unavailable");
  });

  test.each([undefined, null, 0, "false"])("malformed blockhash validity stays unavailable: %j", async (value) => {
    const ledger = new RpcLedger({ network: NETWORK, genesisHash: GENESIS, rpcUrl: "http://unused.invalid",
      rpc: fakeRpc({ isBlockhashValid: () => sendable({ context: { slot: 100n }, value }) }) });
    expect((await ledger.isBlockhashValid("bh")).kind).toBe("unavailable");
  });

  test("a preflight execution error without original status stays unresolved", async () => {
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      confirmTimeoutMs: 10, pollIntervalMs: 1,
      rpc: fakeRpc({ sendTransaction: () => ({ send: () => Promise.reject(preflightFailure({ InstructionError: [0, { Custom: 6 }] })) }) }),
    });
    const result = await ledger.submit(await sampleTransaction());
    expect(result.kind).toBe("submitted");
  });

  test("keeps an AlreadyProcessed preflight refusal submitted and resolves the original signature", async () => {
    const transaction = await sampleTransaction();
    const signature = getSignatureFromTransaction(transaction);
    const looked: string[] = [];
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      pollIntervalMs: 1,
      rpc: fakeRpc({
        sendTransaction: () => ({ send: () => Promise.reject(preflightFailure("AlreadyProcessed")) }),
        getSignatureStatuses: (sigs: string[]) => {
          looked.push(...sigs);
          return sendable({ value: [{ confirmationStatus: "finalized", err: null, slot: 7n }] });
        },
      }),
    });
    const result = await ledger.submit(transaction);
    expect(result).toEqual({ kind: "submitted", outcome: { status: "succeeded", commitment: "finalized" } });
    expect(looked).toEqual([signature]);
  });

  test("keeps an AlreadyProcessed refusal unresolved while the original signature is not finalized", async () => {
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      confirmTimeoutMs: 5,
      pollIntervalMs: 1,
      rpc: fakeRpc({
        sendTransaction: () => ({ send: () => Promise.reject(preflightFailure("AlreadyProcessed")) }),
        getSignatureStatuses: () => sendable({ value: [null] }),
      }),
    });
    expect(await ledger.submit(await sampleTransaction())).toEqual({ kind: "submitted", outcome: undefined });
  });

  test("keeps a BlockhashNotFound preflight refusal submitted: an earlier broadcast of these bytes may have landed", async () => {
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      confirmTimeoutMs: 5,
      pollIntervalMs: 1,
      rpc: fakeRpc({
        sendTransaction: () => ({ send: () => Promise.reject(preflightFailure("BlockhashNotFound")) }),
        getSignatureStatuses: () => sendable({ value: [null] }),
      }),
    });
    expect(await ledger.submit(await sampleTransaction())).toEqual({ kind: "submitted", outcome: undefined });
  });

  test("never classifies a preflight refusal without a transaction error as not-submitted", async () => {
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
      confirmTimeoutMs: 10, pollIntervalMs: 1,
      rpc: fakeRpc({
        sendTransaction: () => ({
          send: () => Promise.reject(preflightError),
        }),
      }),
    });
    const result = await ledger.submit(await sampleTransaction());
    expect(result).toEqual({ kind: "submitted", outcome: undefined });
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
        getSignatureStatuses: () => sendable({ value: [{ confirmationStatus: "finalized", err: null, slot: 7n }] }),
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
          sendable({ value: [{ confirmationStatus: "finalized", err: { InstructionError: [0, { Custom: 6 }] }, slot: 7n }] }),
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

describe("RpcLedger network awaits are bounded", () => {
  /** An RPC request that never answers, recording the abort signal it was given. */
  function stalled(signals: AbortSignal[]) {
    return {
      send: (config?: { abortSignal?: AbortSignal }) => {
        if (config?.abortSignal) signals.push(config.abortSignal);
        return new Promise<never>(() => {});
      },
    };
  }
  const elapsed = async <T>(run: () => Promise<T>): Promise<[T, number]> => {
    const start = Date.now();
    const value = await run();
    return [value, Date.now() - start];
  };

  test("a stalled sendTransaction ends at the settlement deadline as unresolved, sent once", async () => {
    const signals: AbortSignal[] = [];
    let sends = 0;
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      confirmTimeoutMs: 30,
      pollIntervalMs: 1,
      rpc: fakeRpc({
        sendTransaction: () => {
          sends += 1;
          return stalled(signals);
        },
      }),
    });
    const transaction = await sampleTransaction();
    const [result, ms] = await elapsed(() => ledger.submit(transaction));
    expect(result).toEqual({ kind: "submitted" });
    expect(ms).toBeLessThan(500);
    expect(sends).toBe(1);
    expect(signals[0]?.aborted).toBe(true);
  });

  test("stalled status requests end at the same deadline, never resending", async () => {
    const transaction = await sampleTransaction();
    const signals: AbortSignal[] = [];
    let sends = 0;
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      confirmTimeoutMs: 30,
      pollIntervalMs: 1,
      rpc: fakeRpc({
        sendTransaction: () => {
          sends += 1;
          return sendable(getSignatureFromTransaction(transaction));
        },
        getSignatureStatuses: () => stalled(signals),
      }),
    });
    const [result, ms] = await elapsed(() => ledger.submit(transaction));
    expect(result).toEqual({ kind: "submitted", outcome: undefined });
    expect(ms).toBeLessThan(500);
    expect(sends).toBe(1);
    expect(signals.every((s) => s.aborted)).toBe(true);
  });

  test("a stalled log fetch keeps the established finalized failure, with empty logs, within its own bound", async () => {
    const transaction = await sampleTransaction();
    const signals: AbortSignal[] = [];
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      confirmTimeoutMs: 30,
      requestTimeoutMs: 20,
      pollIntervalMs: 1,
      rpc: fakeRpc({
        sendTransaction: () => sendable(getSignatureFromTransaction(transaction)),
        getSignatureStatuses: () => sendable({ value: [{ confirmationStatus: "finalized", err: { InstructionError: [0, { Custom: 6 }] }, slot: 1n }] }),
        getTransaction: () => stalled(signals),
      }),
    });
    const [result, ms] = await elapsed(() => ledger.submit(transaction));
    expect(result).toMatchObject({ kind: "submitted", outcome: { status: "failed", commitment: "finalized", logs: [] } });
    expect(ms).toBeLessThan(500);
    expect(signals[0]?.aborted).toBe(true);
  });

  test("an AlreadyProcessed poll shares the deadline that started before the send", async () => {
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      confirmTimeoutMs: 30,
      pollIntervalMs: 1,
      rpc: fakeRpc({
        sendTransaction: () => ({ send: () => new Promise((_, reject) => setTimeout(() => reject(preflightFailure("AlreadyProcessed")), 20)) }),
        getSignatureStatuses: () => stalled([]),
      }),
    });
    const [result, ms] = await elapsed(async () => ledger.submit(await sampleTransaction()));
    expect(result).toEqual({ kind: "submitted", outcome: undefined });
    expect(ms).toBeLessThan(500);
  });

  test("stalled reads, simulation, and genesis checks fail with RpcDeadlineExceeded", async () => {
    const signals: AbortSignal[] = [];
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      requestTimeoutMs: 20,
      rpc: fakeRpc({
        getGenesisHash: () => stalled(signals),
        getAccountInfo: () => stalled(signals),
        getLatestBlockhash: () => stalled(signals),
        simulateTransaction: () => stalled(signals),
      }),
    });
    await expect(ledger.verifyGenesis()).rejects.toBeInstanceOf(RpcDeadlineExceeded);
    await expect(ledger.now()).rejects.toBeInstanceOf(RpcDeadlineExceeded);
    await expect(ledger.getAccount(PROGRAM_ID)).rejects.toBeInstanceOf(RpcDeadlineExceeded);
    await expect(ledger.latestBlockhash()).rejects.toBeInstanceOf(RpcDeadlineExceeded);
    await expect(ledger.simulate(await sampleTransaction())).rejects.toBeInstanceOf(RpcDeadlineExceeded);
    expect(signals).toHaveLength(5);
    expect(signals.every((s) => s.aborted)).toBe(true);
  });

  test("a transport that rejects as soon as it is aborted still yields RpcDeadlineExceeded", async () => {
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      requestTimeoutMs: 20,
      rpc: fakeRpc({
        getGenesisHash: () => ({
          send: ({ abortSignal }: { abortSignal: AbortSignal }) =>
            new Promise((_, reject) => abortSignal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")))),
        }),
      }),
    });
    await expect(ledger.verifyGenesis()).rejects.toBeInstanceOf(RpcDeadlineExceeded);
  });

  test("non-positive timeouts are refused at construction", () => {
    expect(() => new RpcLedger({ network: NETWORK, genesisHash: GENESIS, rpcUrl: "http://unused.invalid", confirmTimeoutMs: 0, rpc: fakeRpc({}) })).toThrow(/positive/);
  });

  test("a slow send is cut at requestTimeoutMs, leaving the rest of the settlement window for polling", async () => {
    const transaction = await sampleTransaction();
    let statusCalls = 0;
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      confirmTimeoutMs: 200,
      requestTimeoutMs: 20,
      pollIntervalMs: 1,
      rpc: fakeRpc({
        sendTransaction: () => stalled([]),
        getSignatureStatuses: () => {
          statusCalls += 1;
          return sendable({ value: [null] });
        },
      }),
    });
    const [result, ms] = await elapsed(() => ledger.submit(transaction));
    expect(result).toEqual({ kind: "submitted" });
    expect(ms).toBeLessThan(150);
    expect(statusCalls).toBe(0); // an unconfirmed send never polls a signature it cannot trust
  });

  test("a finalized failure seen at the end of the window still gets its own log fetch", async () => {
    const transaction = await sampleTransaction();
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      confirmTimeoutMs: 30,
      pollIntervalMs: 1,
      rpc: fakeRpc({
        sendTransaction: () => sendable(getSignatureFromTransaction(transaction)),
        getSignatureStatuses: () => ({
          send: () => new Promise((r) => setTimeout(() => r({ value: [{ confirmationStatus: "finalized", err: { InstructionError: [0, { Custom: 6 }] }, slot: 1n }] }), 25)),
        }),
        getTransaction: () => ({ send: () => new Promise((r) => setTimeout(() => r({ meta: { logMessages: ["late log"] } }), 15)) }),
      }),
    });
    const result = await ledger.submit(transaction);
    expect(result).toMatchObject({ outcome: { status: "failed", logs: ["late log"] } });
  });

  test("the history search shares one deadline across all its requests", async () => {
    let fetched = 0;
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      confirmTimeoutMs: 50,
      requestTimeoutMs: 40,
      rpc: fakeRpc({
        getSignaturesForAddress: () => sendable(Array.from({ length: 50 }, (_, i) => ({ signature: `s${i}` }))),
        getTransaction: () => {
          fetched += 1;
          return { send: () => new Promise((r) => setTimeout(() => r({ transaction: [Buffer.from([1]).toString("base64"), "base64"] }), 15)) };
        },
      }),
    });
    const [result, ms] = await elapsed(() => ledger.findSignaturesByMessage(PROGRAM_ID, new Uint8Array([9])));
    expect(result.kind).toBe("unavailable");
    expect(ms).toBeLessThan(300);
    expect(fetched).toBeLessThan(10);
  });

  test("stalled reconciliation reads report unavailable, never absence", async () => {
    const ledger = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      requestTimeoutMs: 20,
      confirmTimeoutMs: 30,
      pollIntervalMs: 1,
      rpc: fakeRpc({
        getSignatureStatuses: () => stalled([]),
        getSignaturesForAddress: () => stalled([]),
        isBlockhashValid: () => stalled([]),
        getAccountInfo: () => stalled([]),
      }),
    });
    const sig = getSignatureFromTransaction(await sampleTransaction());
    expect((await ledger.getSignatureStatus(sig)).kind).toBe("unavailable");
    expect((await ledger.findSignaturesByMessage(PROGRAM_ID, new Uint8Array([1]))).kind).toBe("unavailable");
    expect((await ledger.isBlockhashValid("bh")).kind).toBe("unavailable");
    expect((await ledger.getAccountAtLeast(PROGRAM_ID, 1n)).kind).toBe("unavailable");
  });
});

describe("RpcLedger ChainReader", () => {
  const ledgerWith = (rpc: Partial<Record<keyof SolanaRpcApi, unknown>>) =>
    new RpcLedger({ network: NETWORK, genesisHash: GENESIS, rpcUrl: "http://unused.invalid", rpc: fakeRpc(rpc) });

  test.each([
    {},
    { value: [] },
    { value: [undefined] },
    { value: [{ slot: 1n, confirmationStatus: "finalized" }] },
    { value: [{ slot: -1n, confirmationStatus: "finalized", err: null }] },
    { value: [{ slot: 1n, confirmationStatus: "finalized", err: false }] },
    { value: [{ slot: 1n, confirmationStatus: "finalized", err: {} }] },
    { value: [{ slot: 1n, confirmationStatus: "finalized", err: "UnknownFutureVariant" }] },
    { value: [{ slot: 1n, confirmationStatus: "finalized", err: { InstructionError: [0, { Custom: -1 }] } }] },
  ])("malformed status case %# stays unavailable, never definitive", async (response) => {
    const sig = getSignatureFromTransaction(await sampleTransaction());
    expect((await ledgerWith({ getSignatureStatuses: () => sendable(response) }).getSignatureStatus(sig)).kind).toBe("unavailable");
  });

  test("malformed finalized error remains pending without resending", async () => {
    const tx = await sampleTransaction();
    let broadcasts = 0;
    const ledger = new RpcLedger({ network: NETWORK, genesisHash: GENESIS, rpcUrl: "http://unused.invalid", confirmTimeoutMs: 20, pollIntervalMs: 1, rpc: fakeRpc({
      sendTransaction: () => { broadcasts += 1; return sendable(getSignatureFromTransaction(tx)); },
      getSignatureStatuses: () => sendable({ value: [{ slot: 1n, confirmationStatus: "finalized" }] }),
    }) });
    expect(await ledger.submit(tx)).toEqual({ kind: "submitted", outcome: undefined });
    expect(broadcasts).toBe(1);
  });

  test("ignores an account response older than its requested evidence slot", async () => {
    let reads = 0;
    const ledger = ledgerWith({ getAccountInfo: () => sendable({ context: { slot: ++reads === 1 ? 89n : 91n }, value: null }) });
    expect(await ledger.getAccountAtLeast(PROGRAM_ID, 90n)).toEqual({ kind: "ok", slot: 91n, account: null });
    expect(reads).toBe(2);
  });

  test("reports a signature's slot, commitment, and error", async () => {
    const ledger = ledgerWith({
      getSignatureStatuses: () => sendable({ value: [{ confirmationStatus: "confirmed", err: { InstructionError: [0, { Custom: 6 }] }, slot: 42n }] }),
    });
    const sig = getSignatureFromTransaction(await sampleTransaction());
    expect(await ledger.getSignatureStatus(sig)).toEqual({ kind: "found", slot: 42n, commitment: "confirmed", err: '{"InstructionError":[0,{"Custom":6}]}' });
  });

  test("reports missing history as not-found and an RPC failure as unavailable, never as absence", async () => {
    const sig = getSignatureFromTransaction(await sampleTransaction());
    expect(await ledgerWith({ getSignatureStatuses: () => sendable({ value: [null] }) }).getSignatureStatus(sig)).toEqual({ kind: "not-found" });
    const failing = ledgerWith({ getSignatureStatuses: () => ({ send: () => Promise.reject(new Error("429")) }) });
    expect((await failing.getSignatureStatus(sig)).kind).toBe("unavailable");
  });

  test("finds the original signature by its exact message bytes", async () => {
    const original = await sampleTransaction();
    const other = await sampleTransaction();
    const originalSignature = getSignatureFromTransaction(original);
    const otherSignature = getSignatureFromTransaction(other);
    const byWire: Record<string, string> = {
      [originalSignature]: getBase64EncodedWireTransaction(original),
      [otherSignature]: getBase64EncodedWireTransaction(other),
    };
    const ledger = ledgerWith({
      getSignaturesForAddress: () => sendable([{ signature: otherSignature }, { signature: originalSignature }]),
      getTransaction: (sig: string) => sendable({ transaction: [byWire[sig], "base64"] }),
    });
    const search = await ledger.findSignaturesByMessage(PROGRAM_ID, new Uint8Array(original.messageBytes));
    expect(search).toEqual({ kind: "ok", signatures: [originalSignature], truncated: false });
  });

  test("inconsistent history cannot attribute matching bytes to another signature", async () => {
    const original = await sampleTransaction();
    const unrelated = getSignatureFromTransaction(await sampleTransaction());
    const ledger = ledgerWith({
      getSignaturesForAddress: () => sendable([{ signature: unrelated }]),
      getTransaction: () => sendable({ transaction: [getBase64EncodedWireTransaction(original), "base64"] }),
    });
    expect(await ledger.findSignaturesByMessage(PROGRAM_ID, new Uint8Array(original.messageBytes))).toMatchObject({ kind: "unavailable" });
  });

  test("a grafted wire signature cannot bind an unrelated finalized transaction to the original message", async () => {
    const original = await sampleTransaction();
    const unrelated = await sampleTransaction();
    const unrelatedSignature = getSignatureFromTransaction(unrelated);
    const payer = getCompiledTransactionMessageDecoder().decode(original.messageBytes).staticAccounts[0]!;
    const forged = { ...original, signatures: { ...original.signatures, [payer]: Object.values(unrelated.signatures)[0]! } };
    const ledger = ledgerWith({
      getSignaturesForAddress: () => sendable([{ signature: unrelatedSignature }]),
      getTransaction: () => sendable({ transaction: [getBase64EncodedWireTransaction(forged), "base64"] }),
    });
    expect(await ledger.findSignaturesByMessage(PROGRAM_ID, new Uint8Array(original.messageBytes))).toMatchObject({ kind: "unavailable" });
  });

  test("reports listed-but-unretrievable history as unavailable", async () => {
    const ledger = ledgerWith({
      getSignaturesForAddress: () => sendable([{ signature: "orig" }]),
      getTransaction: () => sendable(null),
    });
    expect((await ledger.findSignaturesByMessage(PROGRAM_ID, new Uint8Array([1]))).kind).toBe("unavailable");
  });

  test("checks blockhash validity at the latest bank and reads accounts no older than a slot", async () => {
    const seen: unknown[] = [];
    const ledger = ledgerWith({
      isBlockhashValid: (_b: string, config: unknown) => {
        seen.push(config);
        return sendable({ context: { slot: 90n }, value: false });
      },
      getAccountInfo: (_a: string, config: unknown) => {
        seen.push(config);
        return sendable({ context: { slot: 95n }, value: null });
      },
    });
    expect(await ledger.isBlockhashValid("bh")).toEqual({ kind: "ok", valid: false, slot: 90n });
    expect(await ledger.getAccountAtLeast(PROGRAM_ID, 90n)).toEqual({ kind: "ok", slot: 95n, account: null });
    expect(seen).toEqual([{ commitment: "processed" }, { encoding: "base64", commitment: "finalized", minContextSlot: 90n }]);
  });

  test("waits for the finalized bank to reach the minimum slot, then reports unavailable when it never does", async () => {
    let calls = 0;
    const catchingUp = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      pollIntervalMs: 1,
      rpc: fakeRpc({
        getAccountInfo: () => {
          calls += 1;
          return calls < 3 ? { send: () => Promise.reject(new Error("Minimum context slot has not been reached")) } : sendable({ context: { slot: 91n }, value: null });
        },
      }),
    });
    expect(await catchingUp.getAccountAtLeast(PROGRAM_ID, 90n)).toEqual({ kind: "ok", slot: 91n, account: null });
    const stuck = new RpcLedger({
      network: NETWORK,
      genesisHash: GENESIS,
      rpcUrl: "http://unused.invalid",
      confirmTimeoutMs: 5,
      pollIntervalMs: 1,
      rpc: fakeRpc({ getAccountInfo: () => ({ send: () => Promise.reject(new Error("Minimum context slot has not been reached")) }) }),
    });
    expect(await stuck.getAccountAtLeast(PROGRAM_ID, 90n)).toEqual({ kind: "unavailable", detail: "Minimum context slot has not been reached" });
  });
});

describe("cachedClusterClock", () => {
  test("reads the cluster clock once per window, even under concurrent calls, and never steps back", async () => {
    let reads = 0;
    const values = [1_000n, 990n];
    const clock = cachedClusterClock(async () => values[reads++]!, 0);
    const first = await Promise.all([clock(), clock(), clock()]);
    expect(first).toEqual([1_000n, 1_000n, 1_000n]);
    expect(reads).toBe(1);
    await new Promise((r) => setTimeout(r, 2));
    expect(await clock()).toBe(1_000n); // the refreshed read (990) is behind: no backward step
    expect(reads).toBe(2);
  });

  test("serves cached time without another read inside the window", async () => {
    let reads = 0;
    const clock = cachedClusterClock(async () => {
      reads += 1;
      return 5_000n;
    }, 60_000);
    await clock();
    await clock();
    expect(reads).toBe(1);
  });
});
