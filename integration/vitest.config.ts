import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    // LiteSVM is synchronous native code; one fork keeps the binary load and logs deterministic.
    pool: "forks",
    fileParallelism: false,
    testTimeout: 30_000,
  },
});
