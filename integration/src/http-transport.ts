// x402 v2 HTTP transport (pinned spec: specs/transports-v2/http.md at the UPSTREAM x402 pin).
// Three headers carry all protocol data, each a base64-encoded JSON object:
//   PAYMENT-REQUIRED  server -> client, with HTTP 402: a `PaymentRequired` object
//   PAYMENT-SIGNATURE client -> server: a `PaymentPayload` object
//   PAYMENT-RESPONSE  server -> client: a `SettleResponse` object
// Response bodies are a server implementation concern; no protocol data is read from them.
import { isObject, type PaymentPayload, type PaymentRequirements } from "./types.ts";

export const PAYMENT_REQUIRED_HEADER = "PAYMENT-REQUIRED";
export const PAYMENT_SIGNATURE_HEADER = "PAYMENT-SIGNATURE";
export const PAYMENT_RESPONSE_HEADER = "PAYMENT-RESPONSE";

export type ResourceInfo = { url: string; description?: string; mimeType?: string };

export type PaymentRequired = {
  x402Version: 2;
  error?: string;
  resource: ResourceInfo;
  accepts: PaymentRequirements[];
  extensions?: Record<string, unknown>;
};

export function encodeHeader(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64");
}

/** Decodes a base64 JSON header value; throws on anything that is not valid base64 JSON. */
export function decodeHeader(header: string): unknown {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(header) || header.length % 4 !== 0) throw new Error("header is not base64");
  return JSON.parse(Buffer.from(header, "base64").toString("utf8"));
}

/** Shape check for a decoded `PAYMENT-SIGNATURE`; scheme-specific checks happen later. */
export function parsePaymentPayload(value: unknown): PaymentPayload {
  if (!isObject(value)) throw new Error("PaymentPayload must be a JSON object");
  if (value.x402Version !== 2) throw new Error("PaymentPayload.x402Version must be 2");
  if (!isObject(value.accepted)) throw new Error("PaymentPayload.accepted is required");
  if (!isObject(value.payload)) throw new Error("PaymentPayload.payload is required");
  if (value.resource !== undefined && !isObject(value.resource)) throw new Error("PaymentPayload.resource must be an object");
  return value as unknown as PaymentPayload;
}

/** Shape check for a decoded `PAYMENT-REQUIRED`. */
export function parsePaymentRequired(value: unknown): PaymentRequired {
  if (!isObject(value)) throw new Error("PaymentRequired must be a JSON object");
  if (value.x402Version !== 2) throw new Error("PaymentRequired.x402Version must be 2");
  if (!isObject(value.resource) || typeof value.resource.url !== "string") throw new Error("PaymentRequired.resource.url is required");
  if (!Array.isArray(value.accepts) || !value.accepts.every(isObject)) throw new Error("PaymentRequired.accepts must be an array of objects");
  return value as unknown as PaymentRequired;
}
