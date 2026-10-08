// Auditable build-time patch of @solflare-wallet/sdk 1.4.2. Never mutate node_modules.
// The lockfile pins the package archive; these hashes pin both distributed receivers.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

const originalHashes = {
  esm: '9525d79af38a6f3b68607ce1b421baa1b74822d5bd2aecd56fbecb5ad62f89a7',
  cjs: 'f78461491aad6c61184f85d9b454339b383b93a7a7d17211a48b372f12046616',
};
export function patchSolflareReceiver(source, format) {
  if (!originalHashes[format] || createHash('sha256').update(source).digest('hex') !== originalHashes[format]) {
    throw new Error('Solflare SDK receiver differs from pinned 1.4.2; review the security patch before building');
  }
  const receiver = '        _this._handleMessage = function (event) {\n';
  const removal = '        _this._removeElement = function () {\n';
  for (const needle of [receiver, removal]) {
    if (source.split(needle).length !== 2) throw new Error('Solflare SDK patch location is not unique');
  }
  return source.replace(receiver, receiver +
    "            // Authenticate the live iframe before inspecting any event, response or resize.\n" +
    "            if (event.origin !== 'https://connect.solflare.com' || !_this._element ||\n" +
    "                !_this._iframe || !_this._iframe.isConnected || !_this._iframe.contentWindow ||\n" +
    "                event.source !== _this._iframe.contentWindow) {\n" +
    "                return;\n" +
    "            }\n")
    .replace(removal, removal +
      '            // Removed/replaced frames must never remain trusted message senders.\n' +
      '            _this._iframe = null;\n');
}

export function solflareReceiverPatch() {
  let patched = 0;
  return {
    name: 'solflare-1.4.2-authenticated-receiver',
    setup(build) {
      build.onLoad({ filter: /[/\\]@solflare-wallet[/\\]sdk[/\\]lib[/\\](esm|cjs)[/\\]index\.js$/ }, ({ path }) => {
        const format = path.match(/[/\\]lib[/\\](esm|cjs)[/\\]index\.js$/)[1];
        const manifest = JSON.parse(readFileSync(join(dirname(path), '../../package.json'), 'utf8'));
        if (manifest.name !== '@solflare-wallet/sdk' || manifest.version !== '1.4.2') throw new Error('Unexpected Solflare SDK package');
        const contents = patchSolflareReceiver(readFileSync(path, 'utf8'), format);
        patched++;
        return { contents, loader: 'js' };
      });
      build.onEnd(result => {
        if (!result.errors.length && patched !== 1) throw new Error('Wallet bundle must contain exactly one patched Solflare receiver');
      });
    },
  };
}
