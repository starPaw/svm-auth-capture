// Bearer-token authentication for the facilitator's routes (SAC-006 gap #3). The facilitator
// has no caller identity of its own (integration/README.md, "Trusted caller only"): this
// middleware is what makes "trusted caller" an enforced precondition rather than an operational
// assumption. Mount it on a parent app *before* `createApp`'s routes (see `gateway.ts`) — a
// middleware registered on the app `createApp` returns does not run before routes `createApp`
// already registered on that same app.
import { timingSafeEqual } from "node:crypto";
import type { MiddlewareHandler } from "hono";

/**
 * Rejects any request without `Authorization: Bearer <token>` matching exactly, using a
 * constant-time comparison so the facilitator cannot leak the token's length or prefix through
 * response-time differences. Every unauthenticated request is rejected before its body is ever
 * read, so it can never reach sponsor signing or submission.
 */
export function requireBearerToken(token: string): MiddlewareHandler {
  const expected = Buffer.from(token, "utf8");
  return async (c, next) => {
    const header = c.req.header("authorization") ?? "";
    const prefix = "Bearer ";
    if (!header.startsWith(prefix)) return c.json({ error: "missing bearer token" }, 401);
    const presented = Buffer.from(header.slice(prefix.length), "utf8");
    const match = presented.length === expected.length && timingSafeEqual(presented, expected);
    if (!match) return c.json({ error: "invalid bearer token" }, 401);
    await next();
  };
}

/** Identifies the authenticated caller for resource-fingerprint binding (`operation-store.ts`). */
export function callerIdentity(token: string): string {
  return `bearer:${token}`;
}
