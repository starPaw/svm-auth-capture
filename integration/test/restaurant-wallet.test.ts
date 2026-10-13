// Browser signing adapter tests: real local transaction bytes/signatures, no payment relay.
import { getBase64Encoder, getTransactionDecoder, partiallySignTransaction } from "@solana/kit";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { createHarness, type Harness } from "./fixture.js";
import { encodeTransaction } from "../src/transactions.js";
import { demoComputeInstructions } from "../src/demo-compute.js";
let h: Harness, adapter: any;
beforeAll(async () => {
  h = await createHarness();
  // Wallet Standard event surface only; no mock ledger or production wallet injected.
  Object.assign(globalThis, { window: new EventTarget() });
  const modulePath = "../web/wallet.js";
  adapter = await import(modulePath);
});
afterAll(async () => { await h.close(); Reflect.deleteProperty(globalThis,"window"); });
const account = () => ({ address:h.payer.address,chains:["solana:devnet"],features:["solana:signTransaction"] });
describe("Wallet Standard adapter", () => {
  test('test-token message signing preserves recipient, amount, origin and exact bytes without a transaction',async()=>{
    Object.assign(window,{location:{origin:'https://demo.test'}});
    const expiresAt=Math.floor(Date.now()/1000)+600,id='a'.repeat(64);
    const challenge={recipient:h.payer.address,amount:1000,mint:h.mint,id,expiresAt,
      message:`Capture402 Devnet test-token request\nOrigin: https://demo.test\nRecipient: ${h.payer.address}\nMint: ${h.mint}\nAmount: 1000 test tokens\nNetwork: Solana Devnet\nRequest: ${id}\nExpires: ${expiresAt}\nNo funds or transaction authority are granted by this message.`};
    const {signBytes}=await import('@solana/kit');
    const connection={account:account(),signMessage:async({message}:any)=>[{signedMessage:new Uint8Array(message),signature:new Uint8Array(await signBytes(h.payer.keyPair.privateKey,message))}]};
    const result=await adapter.walletSignFaucetRequest(connection,challenge,{...adapter.DEVNET_POLICY,mint:h.mint});
    expect(Buffer.from(result,'base64')).toHaveLength(64);expect(h.ledger.submissions).toHaveLength(0);
    for(const bad of [{...challenge,recipient:h.outsider.address},{...challenge,amount:1001},{...challenge,message:challenge.message+'changed'},{...challenge,mint:h.outsider.address}]) {
      await expect(adapter.walletSignFaucetRequest(connection,bad,{...adapter.DEVNET_POLICY,mint:h.mint})).rejects.toThrow();
    }
    connection.signMessage=async({message}:any)=>{message[0]^=1;return[{signedMessage:message,signature:new Uint8Array(64)}];};
    await expect(adapter.walletSignFaucetRequest(connection,challenge,{...adapter.DEVNET_POLICY,mint:h.mint})).rejects.toThrow(/changed/);
  });
  test("connect identifies a Devnet signer without spending", async () => {
    const wallet = { name:"Local signing fixture",features:{ "standard:connect":{ connect:async()=>({ accounts:[account()] }) } } };
    expect((await adapter.connect(wallet,()=>{})).account.address).toBe(h.payer.address);
    expect(h.ledger.submissions).toHaveLength(0);
  });
  test("account without Devnet support is refused", async () => {
    const wallet = { features:{ "standard:connect":{ connect:async()=>({ accounts:[{ ...account(),chains:["solana:mainnet"] }] }) } } };
    await expect(adapter.connect(wallet,()=>{})).rejects.toThrow("cannot sign on Solana Devnet");
  });
  test("signTransaction preserves the exact offered message; altered wallet message is refused", async () => {
    const unsigned = encodeTransaction(await h.signedAuthorize({ salt:h.newSalt(),signers:[],extra:demoComputeInstructions(200_000) }));
    const connection = { account:account(),wallet:{ features:{ "solana:signTransaction":{ signTransaction:async ({transaction,chain}:any)=>{
      expect(chain).toBe("solana:devnet");
      const signed = await partiallySignTransaction([h.payer.keyPair],getTransactionDecoder().decode(transaction));
      return [{ signedTransaction:getBase64Encoder().encode(encodeTransaction(signed)) }];
    } } } } };
    const result = await adapter.walletSign(connection,unsigned); expect(result).not.toBe(unsigned); expect(h.ledger.submissions).toHaveLength(0);
    connection.wallet.features["solana:signTransaction"].signTransaction = async ({transaction}:any)=>{
      const tampered = new Uint8Array(transaction); tampered[tampered.length-1]! ^= 1;
      return [{ signedTransaction:tampered }];
    };
    await expect(adapter.walletSign(connection,unsigned)).rejects.toThrow("Wallet changed the offered transaction");
  });
  test("wallet input-buffer mutation cannot rewrite the comparison baseline", async () => {
    const unsigned = encodeTransaction(await h.signedAuthorize({ salt:h.newSalt(),signers:[],extra:demoComputeInstructions(200_000) }));
    const connection = { account:account(),wallet:{features:{"solana:signTransaction":{signTransaction:async({transaction}:any)=>{
      transaction[transaction.length-1] ^= 1;
      return [{signedTransaction:transaction}];
    }}}}};
    await expect(adapter.walletSign(connection,unsigned)).rejects.toThrow("Wallet changed the offered transaction");
    expect(adapter.signingReport()).toMatchObject({messageEqual:false,changedFields:["instructions"]});
    expect(h.ledger.submissions).toHaveLength(0);
  });
  test("a signature added for the sponsor is refused even when message bytes match", async () => {
    const unsigned = encodeTransaction(await h.signedAuthorize({salt:h.newSalt(),signers:[],extra:demoComputeInstructions(200_000)}));
    const connection = {account:account(),wallet:{features:{"solana:signTransaction":{signTransaction:async({transaction}:any)=>{
      const signed=await partiallySignTransaction([h.payer.keyPair,h.facilitatorKey.keyPair],getTransactionDecoder().decode(transaction));
      return [{signedTransaction:getBase64Encoder().encode(encodeTransaction(signed))}];
    }}}}};
    await expect(adapter.walletSign(connection,unsigned)).rejects.toThrow("only the payer signature");
    expect(adapter.signingReport().messageEqual).toBe(true);
    expect(adapter.signingReport().changedSignatureSlots.map((s:any)=>s.signer)).toEqual([h.facilitatorKey.address,h.payer.address]);
    expect(h.ledger.submissions).toHaveLength(0);
  });
  test("ordinary signature insertion changes only the payer slot, not the canonical message", async () => {
    const unsigned=encodeTransaction(await h.signedAuthorize({salt:h.newSalt(),signers:[],extra:demoComputeInstructions(200_000)}));
    const connection={account:account(),wallet:{features:{"solana:signTransaction":{signTransaction:async({transaction}:any)=>{
      const signed=await partiallySignTransaction([h.payer.keyPair],getTransactionDecoder().decode(transaction));
      return [{signedTransaction:getBase64Encoder().encode(encodeTransaction(signed))}];
    }}}}};
    await adapter.walletSign(connection,unsigned);
    const report=adapter.signingReport();
    expect(report).toMatchObject({messageEqual:true,changedFields:[],changedSignatureSlots:[{index:1,signer:h.payer.address,before:"absent",after:"present"}]});
    expect(report.before.messageSha256).toBe(report.after.messageSha256);
    expect(JSON.stringify(report)).not.toContain("signedTransaction");
  });

});

describe('merchant demo readable wallet consent',()=>{
  test('checks original order, payer, immutable limits and exact returned message before enabling any HTTP action',async()=>{
    Object.assign(window,{location:{origin:'https://demo.test'}});
    const {MerchantDemoConsent}=await import('../src/merchant-demo.ts');
    const now=Math.floor(Date.now()/1000),order={id:'a'.repeat(32),payer:h.payer.address,payment:h.outsider.address,scenario:'normal',captureDeadline:now+150,refundDeadline:now+180,now};
    const policy={...adapter.DEVNET_POLICY,programId:h.facilitator.programId,sponsor:h.facilitatorKey.address,merchant:h.server.address,mint:h.mint};
    const q=new MerchantDemoConsent('private-fixture-merchant-key-0123456789').challenge({schema:1,origin:window.location.origin,network:policy.network,programId:policy.programId,sponsor:policy.sponsor,merchant:policy.merchant,mint:policy.mint,budget:'100000000',order:order.id,payment:order.payment,payer:order.payer,scenario:order.scenario,captureDeadline:order.captureDeadline,refundDeadline:order.refundDeadline,capabilityHash:'b'.repeat(64)},BigInt(now));
    const {signBytes}=await import('@solana/kit');
    const connection={account:account(),signMessage:async({message}:any)=>[{signedMessage:new Uint8Array(message),signature:new Uint8Array(await signBytes(h.payer.keyPair.privateKey,message))}]};
    expect(Buffer.from(await adapter.walletSignMerchantDemo(connection,q,order,policy),'base64')).toHaveLength(64);
    for(const changed of [{order:'c'.repeat(32)},{payment:h.server.address},{budget:'101000000'},{mint:h.outsider.address},{origin:'https://foreign.example'},{merchant:h.outsider.address},{scenario:'refund'},{expiresAt:now+181},{message:q.message+' changed'}])await expect(adapter.walletSignMerchantDemo(connection,{...q,...changed},order,policy)).rejects.toThrow();
    connection.signMessage=async({message}:any)=>{message[0]^=1;return[{signedMessage:message,signature:new Uint8Array(64)}];};
    await expect(adapter.walletSignMerchantDemo(connection,q,order,policy)).rejects.toThrow(/changed/);
    expect(h.ledger.submissions).toHaveLength(0);
  });
});
