// Unit tests for `requireBearerToken` (SAC-006 gap #3) against a minimal Hono app — no network.
import { Hono } from "hono";
import { describe, expect, test } from "vitest";
import { callerIdentity, requireBearerToken } from "../src/auth.js";

function appWith(token: string): Hono {
  const app = new Hono();
  app.use("/protected", requireBearerToken(token));
  app.get("/protected", (c) => c.json({ ok: true }));
  return app;
}

describe("requireBearerToken", () => {
  test("rejects a request with no authorization header", async () => {
    const res = await appWith("secret").request("/protected");
    expect(res.status).toBe(401);
  });

  test("rejects a non-Bearer authorization header", async () => {
    const res = await appWith("secret").request("/protected", { headers: { authorization: "Basic foo" } });
    expect(res.status).toBe(401);
  });

  test("rejects a wrong bearer token", async () => {
    const res = await appWith("secret").request("/protected", { headers: { authorization: "Bearer wrong" } });
    expect(res.status).toBe(401);
  });

  test("rejects a token that is a prefix or superset of the expected one", async () => {
    const app = appWith("secret");
    expect((await app.request("/protected", { headers: { authorization: "Bearer secre" } })).status).toBe(401);
    expect((await app.request("/protected", { headers: { authorization: "Bearer secretx" } })).status).toBe(401);
  });

  test("allows a request with the exact bearer token", async () => {
    const res = await appWith("secret").request("/protected", { headers: { authorization: "Bearer secret" } });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });
});

describe("callerIdentity", () => {
  test("derives a stable identity string from the token", () => {
    expect(callerIdentity("secret")).toBe("bearer:secret");
  });
});
