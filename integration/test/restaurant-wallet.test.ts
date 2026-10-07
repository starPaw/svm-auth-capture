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
