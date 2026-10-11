// Disposable Linux-only syscall failure qualification; no live store or RPC access.
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { expect, test } from "vitest";

const strace = process.env.SAC006_TEST_STRACE;
const boundaries = ["record-file-before", "order-file-before", "order-directory-before", "unlock-directory-before"];
test.skipIf(process.platform !== "linux" || !strace).each(boundaries)("Linux fsync EIO at %s retains originals and permits only proven completion", boundary => {
  const traces = mkdtempSync(join(realpathSync(tmpdir()), "outcome-native-fault-"));
  const roots: string[] = [];
  function run(injection?: number) {
    const tracePath = join(traces, injection ? "injected.trace" : "calibration.trace");
    const args = ["-o", tracePath, "-e", "trace=fsync,write", "-s", "128"];
    if (injection) args.push("-e", `inject=fsync:error=EIO:when=${injection}`);
    args.push(process.execPath, "--experimental-strip-types", resolve("test/fixtures/outcome-fault-worker.ts"), "native-fault", boundary, "success");
    const child = spawnSync(strace!, args, { timeout: 8000, encoding: "utf8" });
    const lines = child.stdout.trim().split("\n").filter(Boolean).map(line => JSON.parse(line));
    if (lines[0]?.root) roots.push(lines[0].root);
    expect(child.status, child.stderr).toBe(0);
    expect(lines).toHaveLength(2);
    return { result: lines[1], trace: readFileSync(tracePath, "utf8") };
  }
  try {
    const calibration = run();
    expect(calibration.result.unexpectedSuccess).toBe(true);
    const marker = calibration.trace.indexOf("NATIVE_FAULT_TARGET:" + boundary);
    expect(marker).toBeGreaterThan(0);
    const occurrence = (calibration.trace.slice(0, marker).match(/^fsync\(/gm) ?? []).length + 1;
    const injected = run(occurrence);
    expect(injected.trace).toContain("(INJECTED)");
    const errors = injected.trace.split("\n").filter(line => line.startsWith("fsync(") && line.includes("EIO") && line.includes("(INJECTED)"));
    expect(errors).toHaveLength(1);
    expect(injected.result).toMatchObject({ fired: true, errorCode: "EIO", beforeRetry: { originals: true }, after: { originals: true, busy: false, status: "active" } });
    expect(injected.result.repeat).toBe(boundary === "unlock-directory-before" ? "already-applied" : "completed");
    expect(injected.result.beforeRetry.busy).toBe(boundary !== "unlock-directory-before");
    console.log(JSON.stringify({ boundary, occurrence, syscall: errors[0], result: injected.result }));
  } finally {
    for (const root of roots) rmSync(root, { recursive: true, force: true });
    rmSync(traces, { recursive: true, force: true });
  }
});
