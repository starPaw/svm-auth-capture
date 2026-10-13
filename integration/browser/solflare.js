// Official Solflare SDK transport, pinned by package-lock; serialized transactions stay exact.
import Solflare from '@solflare-wallet/sdk';
import { VersionedTransaction } from '@solana/web3.js';
export const DEVNET = 'solana:devnet';
export function createSolflareDevnet() {
  // The SDK otherwise defaults to mainnet-beta. Never derive this from wallet UI or Explorer URLs.
  return new Solflare({ network: 'devnet' });
}
export async function connectSolflareDevnet(changed) {
  const sdk = createSolflareDevnet();
  await sdk.connect();
  if (!sdk.publicKey) throw new Error('Solflare did not return a payer public key.');
  const account = () => sdk.publicKey ? { address: sdk.publicKey.toBase58(), chains: [DEVNET], features: ['solana:signTransaction'] } : null;
  const update = () => changed(account());
  sdk.on('accountChanged',update); sdk.on('disconnect',update);
  return {
    account: account(),
    off: () => { sdk.off('accountChanged',update); sdk.off('disconnect',update); },
    async signTransaction({ account: selected, transaction, chain }) {
      if (chain !== DEVNET || selected.address !== sdk.publicKey?.toBase58()) throw new Error('Solflare signing requires the original payer on Solana Devnet.');
      // VersionedTransaction also accepts legacy wire messages and retains compiled bytes.
      // No Connection, RPC request, recompilation, blockhash replacement or signAndSend call.
      const signed = await sdk.signTransaction(VersionedTransaction.deserialize(transaction));
      return [{ signedTransaction: new Uint8Array(signed.serialize()) }];
    },
    async signMessage({ account: selected, message }) {
      if(selected.address!==sdk.publicKey?.toBase58())throw new Error('Solflare message signing requires the connected recipient.');
      return [{signedMessage:new Uint8Array(message),signature:new Uint8Array(await sdk.signMessage(message,'utf8'))}];
    },
  };
}
