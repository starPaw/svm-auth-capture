import { beforeEach, expect, test, vi } from "vitest";
const mocks = vi.hoisted(() => ({
  verify: vi.fn(async () => {}), reconcile: vi.fn(async (_options: unknown) => ({ version: 1, readOnly: true, conclusion: "unknown" })),
  load: vi.fn((_path: string) => ({ network: { caip2: "solana:fixture", genesisHash: "fixture-genesis" }, programId: "fixture-program", sha256: "fixture-record-hash" })),
  ledger: vi.fn(function (this: any, options: unknown) { this.options = options; this.verifyGenesis = mocks.verify; }),
}));
vi.mock("../src/deployment-record.ts", () => ({ loadDeploymentRecord: mocks.load }));
vi.mock("../src/rpc-ledger.ts", () => ({ RpcLedger: mocks.ledger }));
vi.mock("../src/restaurant-reconciliation.ts", () => ({ reconcileRestaurantOrder: mocks.reconcile }));
import { restaurantReconcileMain } from "../src/restaurant-reconcile.ts";
const id = "1234567890abcdef1234567890abcdef";
const env = { SAC006_STORE_DIR: "/synthetic/store", SAC006_DEPLOYMENT_RECORD_PATH: "/synthetic/deployment.json",
  SOLANA_RPC_URL: "https://provider.invalid/private-provider-key", SAC006_FACILITATOR_JOURNAL_DIR: "/synthetic/facilitator",
  SAC006_SERVER_KEYPAIR_PATH: "/never-read-private-keypair", SAC006_BEARER_TOKEN: "never-read-private-token" };
beforeEach(() => { vi.clearAllMocks(); mocks.verify.mockResolvedValue(undefined); });
test("CLI uses restaurant store paths and sanitized deployment attribution", async () => {
  const output = vi.fn(); await restaurantReconcileMain([id], env, output);
  expect(mocks.verify).toHaveBeenCalledOnce();
  expect(mocks.reconcile).toHaveBeenCalledWith(expect.objectContaining({
    ordersDir: "/synthetic/store-restaurant", orderId: id, programId: "fixture-program", network: "solana:fixture",
    journalDirs: ["/synthetic/facilitator", "/synthetic/store-restaurant-reclaim"],
  }));
  const report = JSON.parse(output.mock.calls[0]![0]);
  expect(report).toMatchObject({ readOnly: true, conclusion: "unknown", network: "solana:fixture", genesisHash: "fixture-genesis", deploymentRecordSha256: "fixture-record-hash" });
  expect(output.mock.calls[0]![0]).not.toContain("private"); expect(output.mock.calls[0]![0]).not.toContain("/synthetic");
});
test("CLI accepts explicit orders and reclaim directories without loading private keys", async () => {
  await restaurantReconcileMain([id], { ...env, SAC006_RESTAURANT_ORDERS_DIR: "/synthetic/orders", SAC006_RECLAIM_JOURNAL_DIR: "/synthetic/reclaim" }, vi.fn());
  expect(mocks.reconcile).toHaveBeenCalledWith(expect.objectContaining({ ordersDir: "/synthetic/orders", journalDirs: ["/synthetic/facilitator", "/synthetic/reclaim"] }));
});
test("genesis failure prevents any order/chain association", async () => {
  mocks.verify.mockRejectedValue(new Error("private-provider-key")); const output = vi.fn();
  await expect(restaurantReconcileMain([id], env, output)).rejects.toThrow(); expect(mocks.reconcile).not.toHaveBeenCalled(); expect(output).not.toHaveBeenCalled();
});
test.each([{ argv: [] }, { argv: ["../private-path"] }, { argv: [id, "extra"] }])("invalid CLI arguments are refused before file or RPC reads ($argv)", async ({ argv }) => {
  await expect(restaurantReconcileMain(argv, env, vi.fn())).rejects.toThrow("usage:");
  expect(mocks.load).not.toHaveBeenCalled(); expect(mocks.ledger).not.toHaveBeenCalled();
});
test("missing configuration is generic", async () => {
  await expect(restaurantReconcileMain([id], {}, vi.fn())).rejects.toThrow("reconciliation configuration incomplete");
});
