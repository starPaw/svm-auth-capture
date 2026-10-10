// Capability-free serving contract. No economic, Solana, store or RPC imports.
import { createHash, timingSafeEqual } from "node:crypto";

export const MODE = "READ_ONLY_QUARANTINE";
export const ACTIONS = ["beer", "salmon", "finish", "void", "refund"] as const;
export const capabilities = Object.freeze(Object.fromEntries(
  ["purchase", "authorize", "sign", "submit", "capture", "void", "refund", "reclaim", "fulfill", "reconcile", ...ACTIONS].map(k => [k, false])));
export type RetainedEvent = { action: string; amount: string; at: string; status: string; signature: string };
export type RetainedOrder = { id: string; capabilityHash: string; payer: string; payment: string; createdAt: number; status: string; events: RetainedEvent[] };
export type Projection = {
  version: 1; mode: typeof MODE; snapshotAt: string; viewerSha: string; inventorySha256: string;
  network: string; programId: string; tupleSha256: string;
  original: { signature: string; messageHash: string; wireSha256: string; journalSha256: string; operation: string; payment: string; payer: string; status: "UNKNOWN"; association: string | null; attribution: "retained-facilitator-original" };
  orders: RetainedOrder[];
};
export const hash = (s: string | ArrayLike<number>) => createHash("sha256").update(typeof s === "string" ? s : Uint8Array.from(s)).digest("hex");
export function check(ok: unknown): asserts ok { if (!ok) throw new Error("quarantine data refused"); }
// JSON.parse silently overwrites duplicate keys. Validate the token stream first,
// including escaped aliases, then parse only a complete finite JSON value.
export function strictJson(raw: string): unknown {
  let pos = 0;
  const space = () => { while (/[\x20\t\r\n]/.test(raw[pos] ?? "x")) pos++; };
  const string = () => {
    const start = pos; check(raw[pos++] === '"');
    while (pos < raw.length) { const c = raw[pos++]; if (c === "\\") pos++; else if (c === '"') return JSON.parse(raw.slice(start, pos)) as string; }
    check(false);
  };
  const value = (depth: number): void => {
    check(depth <= 64); space(); const c = raw[pos];
    if (c === '"') { string(); return; }
    if (c === "{" || c === "[") {
      pos++; space(); const close = c === "{" ? "}" : "]", keys = new Set<string>();
      if (raw[pos] === close) { pos++; return; }
      for (;;) {
        if (c === "{") { const key = string(); check(!keys.has(key)); keys.add(key); space(); check(raw[pos++] === ":"); }
        value(depth + 1); space(); if (raw[pos] === close) { pos++; return; }
        check(raw[pos++] === ","); space();
      }
    }
    const token = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(raw.slice(pos));
    check(token); check(!/^[-0-9]/.test(token[0]) || Number.isFinite(Number(token[0]))); pos += token[0].length;
  };
  value(0); space(); check(pos === raw.length); return JSON.parse(raw);
}
export function object(v: unknown, required: string[], optional: string[] = []): asserts v is Record<string, any> {
  check(v && typeof v === "object" && !Array.isArray(v));
  check(required.every(k => Object.hasOwn(v, k)) && Object.keys(v).every(k => [...required, ...optional].includes(k)));
}
export function text(v: unknown, limit = 256): asserts v is string { check(typeof v === "string" && v.length > 0 && v.length <= limit && !/[\x00-\x1f]/.test(v)); }
export function hex(v: unknown, size = 64): asserts v is string { check(typeof v === "string" && new RegExp(`^[a-f0-9]{${size}}$`).test(v)); }
export function decimal(v: unknown): asserts v is string { check(typeof v === "string" && /^(0|[1-9][0-9]{0,19})$/.test(v) && BigInt(v) <= (1n << 64n) - 1n); }
export function timestamp(v: unknown): asserts v is string { check(typeof v === "string" && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(v) && new Date(v).toISOString() === v); }
export function base58(v: unknown, signature = false): asserts v is string { check(typeof v === "string" && new RegExp(`^[1-9A-HJ-NP-Za-km-z]{${signature ? "80,90" : "32,44"}}$`).test(v)); }
export function freeze<T>(v: T): T {
  if (v && typeof v === "object") { Object.values(v).forEach(freeze); Object.freeze(v); }
  return v;
}
export function projection(value: unknown): Readonly<Projection> {
  object(value, ["version", "mode", "snapshotAt", "viewerSha", "inventorySha256", "network", "programId", "tupleSha256", "original", "orders"]);
  check(value.version === 1 && value.mode === MODE); timestamp(value.snapshotAt); hex(value.viewerSha, 40);
  hex(value.inventorySha256); hex(value.tupleSha256); text(value.network); check(/^solana:[a-zA-Z0-9-]+$/.test(value.network)); base58(value.programId);
  const o = value.original;
  object(o, ["signature", "messageHash", "wireSha256", "journalSha256", "operation", "payment", "payer", "status", "association", "attribution"]);
  base58(o.signature, true); [o.messageHash, o.wireSha256, o.journalSha256].forEach(v => hex(v));
  check(["authorize", "capture", "void", "refund"].includes(o.operation)); base58(o.payment); base58(o.payer);
  check(o.status === "UNKNOWN" && o.attribution === "retained-facilitator-original"); if (o.association !== null) hex(o.association, 32);
  check(Array.isArray(value.orders) && value.orders.length <= 4096);
  const seen = new Set();
  for (const r of value.orders) {
    object(r, ["id", "capabilityHash", "payer", "payment", "createdAt", "status", "events"]);
    hex(r.id, 32); hex(r.capabilityHash); check(!seen.has(r.id)); seen.add(r.id); base58(r.payer); base58(r.payment);
    check(Number.isSafeInteger(r.createdAt) && r.createdAt >= 0 && ["draft", "active", "closed", "pending", "rejected"].includes(r.status));
    check(Array.isArray(r.events) && r.events.length <= 64);
    for (const e of r.events) {
      object(e, ["action", "amount", "at", "status", "signature"]);
      check(["authorize", ...ACTIONS, "reclaim"].includes(e.action)); decimal(e.amount); timestamp(e.at);
      check(["prepared", "pending", "finalized", "rejected"].includes(e.status)); if (e.signature !== "") base58(e.signature, true);
    }
  }
  check(o.association === null || value.orders.some((r: RetainedOrder) => r.id === o.association && r.payment === o.payment && r.payer === o.payer));
  // Clone: a caller retaining the input cannot later change authorization or the snapshot.
  return freeze(JSON.parse(JSON.stringify(value)) as Projection);
}
export type ViewAuth = { merchantHash: string; operatorHash: string };
export const ASSETS = ["/assets/quarantine.css", "/assets/quarantine.js"] as const;
export function createQuarantineView(input: unknown, auth: ViewAuth, assets: Record<typeof ASSETS[number], string>) {
  const p = projection(input);
  object(auth, ["merchantHash", "operatorHash"]); hex(auth.merchantHash); hex(auth.operatorHash);
  check(auth.merchantHash !== auth.operatorHash);
  const authCopy = { ...auth }; const staticAssets = { ...assets };
  const equal = (actual: string | undefined, expected: string) => !!actual && actual.length <= 256 && timingSafeEqual(Buffer.from(hash(actual), "hex"), Buffer.from(expected, "hex"));
  const bearer = (r: Request) => { const a = r.headers.get("authorization"); return a?.startsWith("Bearer ") ? a.slice(7) : undefined; };
  const page = `<!doctype html><html lang="en"><meta charset="utf-8"><title>Retained order history</title><link rel="stylesheet" href="/assets/quarantine.css"><h1>Retained order history</h1><p>READ_ONLY_QUARANTINE · economic outage. Historical UNKNOWN is unresolved.</p><p id="scope"></p><label>Known order ID <input id="order" maxlength="32" autocomplete="off"></label><label id="merchant-label" hidden>Merchant application token <input id="merchant" type="password" autocomplete="off"></label><button id="view">View retained timeline</button><pre id="result"></pre><script src="/assets/quarantine.js"></script></html>`;
  return async (req: Request): Promise<Response> => {
    const headers = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'" };
    const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status, headers: { ...headers, "Content-Type": "application/json" } });
    const deny = () => json({ error: "quarantine request denied" }, 403);
    const u = new URL(req.url); const path = u.pathname;
    // No implicit HEAD/OPTIONS and no wildcard GET. Query variants are denied too.
    if (req.method !== "GET" || u.search || req.headers.has("payment-signature")) return deny();
    if (["/", "/customer", "/merchant"].includes(path)) return new Response(page, { headers: { ...headers, "Content-Type": "text/html; charset=utf-8" } });
    if ((ASSETS as readonly string[]).includes(path)) return new Response(staticAssets[path as typeof ASSETS[number]], { headers: { ...headers, "Content-Type": path.endsWith(".js") ? "text/javascript" : "text/css" } });
    if (path === "/api/config") return json({ mode: MODE, snapshotAt: p.snapshotAt, viewerSha: p.viewerSha, network: p.network, programId: p.programId, scope: "persisted history only; no current balances or finality", capabilities });
    if (path === "/api/quarantine/status") {
      if (!equal(bearer(req), authCopy.operatorHash)) return deny();
      return json({ mode: MODE, viewerSha: p.viewerSha, snapshotAt: p.snapshotAt, inventorySha256: p.inventorySha256, tupleSha256: p.tupleSha256, original: p.original, capabilities });
    }
    const match = /^\/api\/orders\/([a-f0-9]{32})(?:\/actions\/(beer|salmon|finish|void|refund))?$/.exec(path);
    if (!match) return deny();
    const r = p.orders.find(o => o.id === match[1]);
    if (match[2]) { if (!equal(bearer(req), authCopy.merchantHash)) return deny(); }
    else {
      const cookies = (req.headers.get("cookie") ?? "").split(";").map(s => s.trim()).filter(s => s.startsWith("capture402-order="));
      const cookie = cookies.length === 1 ? cookies[0]!.slice("capture402-order=".length) : undefined;
      if (!equal(cookie, r?.capabilityHash ?? "0".repeat(64))) return deny();
    }
    if (!r) return deny(); // Same response as auth failure; no session issuance.
    const { capabilityHash: _capability, ...publicOrder } = r;
    return json({ ...publicOrder, mode: MODE, snapshotAt: p.snapshotAt, scope: "retained timeline", capabilities });
  };
}
