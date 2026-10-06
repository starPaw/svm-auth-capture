// Parent app for the facilitator (SAC-006 gap #3). `createApp` registers its own routes, so
// middleware added to the app it returns never runs before them (integration/README.md,
// "Trusted caller only"): this module is the one place that actually makes the facilitator
// "private to the trusted resource server" rather than merely documenting the expectation.
// Composes, in order, in front of every facilitator route: bearer authentication, a demo
// merchant/mint allowlist, and (on `/settle` only) the sponsorship attempt/balance cap. An
// unauthenticated, non-allowlisted, or over-budget request is rejected by this app and never
// reaches `Facilitator.verify`/`Facilitator.settle`, so it never reaches sponsor signing or
// submission.
import type { Address } from "@solana/kit";
import { Hono, type MiddlewareHandler } from "hono";
import { createApp } from "./app.js";
import { requireBearerToken } from "./auth.js";
import type { Facilitator } from "./facilitator.js";
import { requireSponsorshipBudget, SponsorshipGuard } from "./sponsorship.js";

export type GatewayConfig = {
  bearerToken: string;
  sponsorship: SponsorshipGuard;
  /** The demo's one allowed merchant wallet (`payTo`) and asset mint; anything else is rejected. */
  allowlist: { merchant: Address; mint: Address };
};

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

/** Rejects a `paymentRequirements.payTo`/`asset` outside the demo's fixed allowlist. */
function requireAllowlisted(allowlist: GatewayConfig["allowlist"]): MiddlewareHandler {
  return async (c, next) => {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return next(); // malformed JSON: let the facilitator's own parsing produce the standard rejection.
    }
    const requirements = isObject(body) ? body.paymentRequirements : undefined;
    const payTo = isObject(requirements) ? requirements.payTo : undefined;
    const asset = isObject(requirements) ? requirements.asset : undefined;
    if (payTo !== undefined && payTo !== allowlist.merchant) return c.json({ error: "merchant not allowlisted" }, 403);
    if (asset !== undefined && asset !== allowlist.mint) return c.json({ error: "asset not allowlisted" }, 403);
    await next();
  };
}

export function createGatewayApp(facilitator: Facilitator, config: GatewayConfig): Hono {
  const gateway = new Hono();
  gateway.use("/verify", requireBearerToken(config.bearerToken));
  gateway.use("/settle", requireBearerToken(config.bearerToken));
  gateway.use("/verify", requireAllowlisted(config.allowlist));
  gateway.use("/settle", requireAllowlisted(config.allowlist));
  gateway.use("/settle", requireSponsorshipBudget(config.sponsorship));
  gateway.route("/", createApp(facilitator));
  return gateway;
}
