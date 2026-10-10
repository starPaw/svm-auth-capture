// Separate explicit restaurant-unit profile, never the economic entrypoint.
import { readFileSync, lstatSync, chmodSync } from "node:fs";
import { createServer } from "node:http";
import { createQuarantineView, hash, ASSETS, strictJson, object, check } from "./quarantine-view.ts";

async function main() {
  // All paths fixed inside the sealed root; no environment, TCP port or arbitrary path option.
  if (Object.keys(process.env).some(k => !["LANG", "PATH", "TZ"].includes(k))) throw new Error("unexpected viewer environment");
  const regular = (p: string) => { const s = lstatSync(p); if (!s.isFile() || s.nlink !== 1 || s.mode & 0o222) throw new Error("unsealed viewer input"); return readFileSync(p, "utf8"); };
  const manifest = strictJson(regular("/app/manifest.json"));
  object(manifest, ["version", "projectionSha256", "authSha256", "assets"]); check(manifest.version === 1);
  object(manifest.assets, [...ASSETS]);
  const raw = regular("/app/projection.json");
  if (hash(raw) !== manifest.projectionSha256) throw new Error("projection binding failed");
  const assets = Object.fromEntries(ASSETS.map(p => {
    const raw = regular(`/app/${p.split('/').at(-1)}`);
    if (hash(raw) !== manifest.assets[p]) throw new Error("asset binding failed");
    return [p, raw];
  })) as Record<typeof ASSETS[number], string>;
  const authRaw = regular("/app/auth.json");
  if (hash(authRaw) !== manifest.authSha256) throw new Error("auth binding failed");
  const auth = strictJson(authRaw); object(auth, ["merchantHash", "operatorHash"]);
  const view = createQuarantineView(strictJson(raw), { merchantHash: auth.merchantHash, operatorHash: auth.operatorHash }, assets);
  createServer(async (req, res) => {
    try {
      // Check raw HTTP spelling before URL normalizes dot segments or escapes.
      if (!req.url?.startsWith("/") || /[%\\?]|\/\.{1,2}(?:\/|$)|\/\//.test(req.url)) throw new Error("noncanonical path");
      for (const name of ["authorization", "cookie"]) if (req.rawHeaders.filter((v, i) => i % 2 === 0 && v.toLowerCase() === name).length > 1) throw new Error("ambiguous authentication");
      const r = await view(new Request(`http://viewer${req.url}`, { method: req.method, headers: req.headers as Record<string, string> }));
      res.writeHead(r.status, Object.fromEntries(r.headers)); res.end(Buffer.from(await r.arrayBuffer()));
    } catch { res.writeHead(403, { "Cache-Control": "no-store" }); res.end(); }
  }).listen("/run/ingress/view.sock", () => chmodSync("/run/ingress/view.sock", 0o660));
}
if (process.argv[1]?.endsWith("quarantine-server.ts")) main().catch(() => { console.error("VIEW_START_REFUSED"); process.exitCode = 1; });
