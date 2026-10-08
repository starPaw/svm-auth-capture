import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { appendFileSync, existsSync, readFileSync, readdirSync } from 'node:fs';
import { solflareReceiverPatch } from './solflare-sdk-patch.mjs';
const root = dirname(fileURLToPath(new URL('../package.json', import.meta.url)));
const result = await build({ entryPoints:[join(root,'browser/solflare.js')], plugins:[solflareReceiverPatch()], bundle:true, format:'esm', platform:'browser', target:'es2023', minify:true, legalComments:'linked', metafile:true, outfile:join(root,'web/solflare.js') });
// Retain complete distributed dependency licenses alongside esbuild's linked notices.
const packages = new Map();
for (const input of Object.keys(result.metafile.inputs)) {
  if (!input.includes('node_modules') || !existsSync(resolve(input))) continue;
  for (let dir=dirname(resolve(input)); dir!==dirname(dir); dir=dirname(dir)) {
    const manifest=join(dir,'package.json');
    if (!existsSync(manifest)) continue;
    const info=JSON.parse(readFileSync(manifest,'utf8'));
    if (!info.name) continue;
    packages.set(dir,info); break;
  }
}
for (const [dir,info] of [...packages].sort((a,b)=>a[1].name.localeCompare(b[1].name))) {
  const files=readdirSync(dir).filter(name=>/^(license|copying|notice)/i.test(name)).sort();
  const samePackage=[...packages].find(([other,entry])=>entry.name===info.name && readdirSync(other).some(name=>/^(license|copying|notice)/i.test(name)));
  const licenseDir=files.length ? dir : samePackage?.[0];
  const licenseFiles=licenseDir ? readdirSync(licenseDir).filter(name=>/^(license|copying|notice)/i.test(name)).sort() : [];
  const notices=info.name==='@solflare-wallet/sdk' ? readFileSync(join(root,'browser/SOLFLARE-LICENSE.txt'),'utf8') : licenseFiles.map(name=>readFileSync(join(licenseDir,name),'utf8')).join('\n');
  if (!notices) throw new Error(`Missing bundled license: ${info.name}`);
  appendFileSync(join(root,'web/solflare.js.LEGAL.txt'),`\n${info.name} ${info.version} (${info.license ?? 'see license'})\n${notices}\n`);
}
