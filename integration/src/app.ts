// HTTP binding: x402 v2 facilitator `POST /verify` and `POST /settle` only. No lifecycle
// endpoint exists; capture, void, and refund are `/settle` payloads, and reclaim is payer-direct.
import { Hono } from "hono";
import type { Facilitator } from "./facilitator.js";
import { Reason } from "./types.js";

export function createApp(facilitator: Facilitator): Hono {
  const app = new Hono();

  app.post("/verify", async (c) => {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return c.json({ isValid: false, invalidReason: Reason.invalidPayload }, 400);
    }
    return c.json(await facilitator.verify(body));
  });

  app.post("/settle", async (c) => {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return c.json(
        { success: false, errorReason: Reason.invalidPayload, transaction: "", network: facilitator.network },
        400,
      );
    }
    return c.json(await facilitator.settle(body));
  });

  return app;
}
