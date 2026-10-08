// Wallet Standard event discovery and raw-byte transaction signing.
// API references: wallet-standard/core/app and anza-xyz/wallet-standard signTransaction.
// No wallet is created, no keys are read, and no signAndSend call is made by this adapter.
export const DEVNET_POLICY = Object.freeze({ walletChain:'solana:devnet', cluster:'devnet', network:'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1' });
export function assertDevnetPolicy(policy) {
  if (policy?.walletChain !== DEVNET_POLICY.walletChain || policy?.cluster !== DEVNET_POLICY.cluster || policy?.network !== DEVNET_POLICY.network) throw new Error('Capture402 signing is restricted to the accepted Solana Devnet network.');
}
// Browser guard repeats the server fee ceiling; it never selects or rewrites fee instructions.
export function assertDemoCompute(before) {
  const indices = before.instructions.flatMap((ix,i) => base58(before.keys[ix.program]) === 'ComputeBudget111111111111111111111111111111' ? [i] : []);
  if (indices.length !== 2 || indices[0] !== 0 || indices[1] !== 1) throw new Error('The complete demo compute budget must precede wallet signing.');
  const [limit,price] = indices.map(i=>before.instructions[i]);
  if (limit.accounts.length || price.accounts.length || limit.data.length !== 5 || limit.data[0] !== 2 || price.data.length !== 9 || price.data[0] !== 3) throw new Error('Malformed demo compute budget.');
  const units = new DataView(Uint8Array.from(limit.data).buffer).getUint32(1,true);
  const microLamports = new DataView(Uint8Array.from(price.data).buffer).getBigUint64(1,true);
  if (units < 10_000 || units > 200_000 || microLamports !== 100_000n) throw new Error('Demo compute limit or price outside fixed sponsor policy.');
}
const registry = new Set();
const listeners = new Set();
const notify = () => listeners.forEach(fn => fn());
const api = Object.freeze({ register: (...wallets) => {
  wallets.forEach(wallet => registry.add(wallet)); notify();
  return () => { wallets.forEach(wallet => registry.delete(wallet)); notify(); };
} });
window.addEventListener('wallet-standard:register-wallet', event => {
  if (typeof event.detail === 'function') event.detail(api);
});
window.dispatchEvent(new CustomEvent('wallet-standard:app-ready', { detail: api }));
export const wallets = () => [...registry].filter(w => w.features?.['standard:connect'] && w.features?.['solana:signTransaction']?.supportedTransactionVersions?.includes('legacy'));
export const onWallets = fn => { listeners.add(fn); return () => listeners.delete(fn); };
export const fromBase64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
export const toBase64 = bytes => btoa(Array.from(bytes, b => String.fromCharCode(b)).join(''));
export const encodeEnvelope = value => toBase64(new TextEncoder().encode(JSON.stringify(value)));
export const decodeEnvelope = value => JSON.parse(new TextDecoder().decode(fromBase64(value)));
// Read canonical wire boundaries; never compare the 64-byte signature slots as message data.
function transaction(bytes) {
  let offset = 0;
  const read = n => { if (offset + n > bytes.length) throw new Error('Truncated wallet transaction'); const result = bytes.slice(offset, offset+n); offset += n; return result; };
  const short = () => {
    let n = 0, shift = 0, b;
    do { b = read(1)[0]; if (shift >= 21) throw new Error('Malformed transaction length'); n |= (b & 127) << shift; shift += 7; } while (b & 128);
    if (n > 65535 || shift > 7 && b === 0) throw new Error('Noncanonical transaction length');
    return n;
  };
  const count = short(); const signatures = Array.from({length:count},()=>read(64));
  const start = offset; const first = read(1)[0];
  const version = first & 128 ? first & 127 : 'legacy';
  if (version !== 'legacy' && version !== 0) throw new Error('Unsupported wallet transaction version');
  const required = version === 'legacy' ? first : read(1)[0];
  const header = [required,read(1)[0],read(1)[0]];
  const keys = Array.from({length:short()},()=>read(32)); const blockhash = read(32);
  const instructions = Array.from({length:short()},()=>({ program:read(1)[0],accounts:Array.from(read(short())),data:Array.from(read(short())) }));
  const lookups = version === 0 ? Array.from({length:short()},()=>({ account:Array.from(read(32)),writable:Array.from(read(short())),readonly:Array.from(read(short())) })) : [];
  if (offset !== bytes.length || count !== required || required > keys.length) throw new Error('Malformed wallet transaction boundary');
  return { version,header,keys,blockhash,instructions,lookups,signatures,message:bytes.slice(start) };
}
const equal = (a,b) => a.length === b.length && a.every((v,i)=>v===b[i]);
const jsonEqual = (a,b) => JSON.stringify(a)===JSON.stringify(b);
const present = signature => signature.some(b=>b!==0);
const hex = bytes => Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
function base58(bytes) {
  const alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let n=0n; for(const b of bytes) n=n*256n+BigInt(b);
  let result=''; while(n){result=alphabet[Number(n%58n)]+result;n/=58n;}
  for(const b of bytes){if(b!==0)break;result='1'+result;}
  return result;
}
let lastReport;
export const signingReport = () => lastReport;
async function compare(before,after) {
  const hash = async bytes => hex(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)));
  const fields = {
    version: before.version === after.version,
    header: jsonEqual(before.header,after.header),
    recentBlockhash: equal(before.blockhash,after.blockhash),
    feePayer: equal(before.keys[0],after.keys[0]),
    accountOrdering: jsonEqual(before.keys.map(base58),after.keys.map(base58)),
    instructions: jsonEqual(before.instructions,after.instructions),
    addressTableData: jsonEqual(before.lookups,after.lookups),
  };
  return { messageEqual:equal(before.message,after.message), changedFields:Object.keys(fields).filter(k=>!fields[k]),
    before:{version:before.version,messageBytes:before.message.length,messageSha256:await hash(before.message),header:before.header,feePayer:base58(before.keys[0]),recentBlockhash:base58(before.blockhash),accounts:before.keys.map(base58),instructions:before.instructions,addressTableData:before.lookups},
    after:{version:after.version,messageBytes:after.message.length,messageSha256:await hash(after.message),header:after.header,feePayer:base58(after.keys[0]),recentBlockhash:base58(after.blockhash),accounts:after.keys.map(base58),instructions:after.instructions,addressTableData:after.lookups},
    changedSignatureSlots:after.signatures.flatMap((s,i)=>equal(s,before.signatures[i]??[]) ? [] : [{index:i,signer:after.keys[i]?base58(after.keys[i]):'invalid',before:present(before.signatures[i]??[]) ? 'present':'absent',after:present(s)?'present':'absent'}]),
  };
}
export async function connect(wallet, changed, policy = DEVNET_POLICY) {
  assertDevnetPolicy(policy);
  if (wallet.name === 'Solflare') {
    // Its injected Standard wrapper validates chain then drops it in signTransactionV2.
    // Use the official SDK connection with explicit network=devnet instead.
    const { connectSolflareDevnet } = await import('./solflare.js');
    return { wallet, ...await connectSolflareDevnet(changed) };
  }
  const result = await wallet.features['standard:connect'].connect();
  const account = result.accounts.find(a => a.chains.includes('solana:devnet') && a.features.includes('solana:signTransaction'));
  if (!account) throw new Error('This wallet account cannot sign on Solana Devnet. Select a compatible Devnet account.');
  const off = wallet.features['standard:events']?.on('change', event => { if (event.accounts) changed(event.accounts.find(a => a.chains.includes('solana:devnet')) ?? null); });
  return { wallet, account, off };
}
export async function walletSign(connection, unsigned, policy = DEVNET_POLICY) {
  assertDevnetPolicy(policy);
  if (!connection?.account) throw new Error('Connect the payer wallet first.');
  lastReport = undefined;
  const wire = fromBase64(unsigned);
  // Snapshot before crossing the extension boundary: a wallet can mutate its input buffer.
  const before = transaction(new Uint8Array(wire));
  if (before.version !== 'legacy') throw new Error('This demo offers legacy transactions only.');
  const payerSlot = before.keys.slice(0,before.header[0]).findIndex(k=>base58(k)===connection.account.address);
  if (payerSlot < 0) throw new Error('Connected payer is not a required signer.');
  if (present(before.signatures[payerSlot])) throw new Error('Payer signature must be absent before wallet signing.');
  assertDemoCompute(before);
  const [signed] = await (connection.signTransaction ?? connection.wallet.features['solana:signTransaction'].signTransaction)({ account: connection.account, transaction: wire, chain: DEVNET_POLICY.walletChain });
  if (!(signed?.signedTransaction instanceof Uint8Array)) throw new Error('Wallet did not return a signed transaction.');
  const after = transaction(new Uint8Array(signed.signedTransaction));
  lastReport = await compare(before,after);
  if (!lastReport.messageEqual) throw new Error(`Wallet changed the offered transaction (${lastReport.changedFields.join(', ') || 'serialization'}). Nothing was submitted.`);
  if (!present(after.signatures[payerSlot]) || after.signatures.some((s,i)=>i!==payerSlot&&!equal(s,before.signatures[i]))) throw new Error('Wallet may add only the payer signature. Nothing was submitted.');
  return toBase64(signed.signedTransaction);
}
