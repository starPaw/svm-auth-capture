// Real local signatures and accepted SBF simulation only. Never relay or broadcast a transaction.
import { beforeAll, afterAll, describe, expect, test } from "vitest";
import { getBase64Encoder, getCompiledTransactionMessageDecoder, getPublicKeyFromAddress, getTransactionDecoder, partiallySignTransaction, type SignatureBytes, verifySignature } from "@solana/kit";
import { Transaction as Web3Transaction, ComputeBudgetProgram, VersionedTransaction, PublicKey } from "@solana/web3.js";
import { buildDemoTransaction, demoComputeInstructions, demoComputeLimit, demoPriorityFeeLamports, demoSponsorComputeBounds, DEMO_COMPUTE, COMPUTE_PROGRAM } from "../src/demo-compute.js";
import { Reason } from "../src/types.js";
import { Facilitator } from "../src/facilitator.js";
import { authorizeInstruction, authorizePayload, encodeTransaction } from "../src/transactions.js";
import { createHarness, type Harness, DC, DR, M } from "./fixture.js";
import { getSetComputeUnitLimitInstruction, getSetComputeUnitPriceInstruction } from "./compute-budget.js";
let h: Harness, adapter: any;
beforeAll(async()=>{h=await createHarness();Object.assign(globalThis,{window:new EventTarget()});const path="../web/wallet.js";adapter=await import(path);});
afterAll(async()=>{expect(h.ledger.submissions).toHaveLength(0);await h.close();Reflect.deleteProperty(globalThis,"window");});
const decoder=getTransactionDecoder(), messageDecoder=getCompiledTransactionMessageDecoder();
function legacy(bytes:Parameters<typeof messageDecoder.decode>[0]){const m=messageDecoder.decode(bytes);if(m.version!=="legacy")throw new Error("legacy message expected");return m;}
async function args(){return{feePayer:h.facilitatorKey.address,lifetime:h.lifetime(),signers:[],instructions:[await authorizeInstruction({programId:h.facilitator.programId,payer:h.payer.address,server:h.server.address,mint:h.mint,funder:h.facilitatorKey.address,salt:h.newSalt(),maximum:M,captureDeadline:DC,refundDeadline:DR})]};}
const account=()=>({address:h.payer.address,chains:["solana:devnet"],features:["solana:signTransaction"]});
function connection(signTransaction:(input:any)=>Promise<any>){return{account:account(),wallet:{features:{"solana:signTransaction":{signTransaction}}}};}
async function payerSigned(wire:Uint8Array){return[{signedTransaction:getBase64Encoder().encode(encodeTransaction(await partiallySignTransaction([h.payer.keyPair],decoder.decode(wire))))}];}
const unsigned=async()=>encodeTransaction(await buildDemoTransaction(await args(),h.ledger));
describe("finalized restaurant compute budget",()=>{
  test("simulation is unsigned; the final budget exists before signing and sponsor signature verifies over the final message",async()=>{
    const start=h.ledger.simulated.length;
    const tx=await buildDemoTransaction({...await args(),signers:[h.facilitatorKey]},h.ledger);
    const probe=h.ledger.simulated[start]!;expect(Object.values(probe.signatures).every(s=>s===null)).toBe(true);
    const m=legacy(tx.messageBytes);
    expect(m.instructions).toHaveLength(3);
    expect(m.instructions.slice(0,2).map(ix=>m.staticAccounts[ix.programAddressIndex])).toEqual([COMPUTE_PROGRAM,COMPUTE_PROGRAM]);
    const consumed=await h.ledger.simulate(probe);expect(consumed.ok).toBe(true);
    if(!consumed.ok)throw new Error("local simulation failed");
    expect(new DataView(new Uint8Array(m.instructions[0]!.data!).buffer).getUint32(1,true)).toBe(demoComputeLimit(consumed.unitsConsumed!));
    expect(new DataView(new Uint8Array(m.instructions[1]!.data!).buffer).getBigUint64(1,true)).toBe(100000n);
    expect(await verifySignature(await getPublicKeyFromAddress(h.facilitatorKey.address),tx.signatures[h.facilitatorKey.address] as SignatureBytes,tx.messageBytes)).toBe(true);
    const result=decoder.decode(getBase64Encoder().encode(await adapter.walletSign(connection(async({transaction})=>payerSigned(transaction)),encodeTransaction(tx))));
    expect(Buffer.from(result.messageBytes)).toEqual(Buffer.from(tx.messageBytes));
    expect(result.signatures[h.facilitatorKey.address]).toEqual(tx.signatures[h.facilitatorKey.address]);
    expect(await verifySignature(await getPublicKeyFromAddress(h.facilitatorKey.address),result.signatures[h.facilitatorKey.address] as SignatureBytes,result.messageBytes)).toBe(true);
    expect(adapter.signingReport().changedSignatureSlots).toEqual([{index:1,signer:h.payer.address,before:"absent",after:"present"}]);
  });
  test("exact payer signing preserves the fully compiled budget and message",async()=>{
    await adapter.walletSign(connection(async({transaction})=>{
      const m=legacy(decoder.decode(transaction).messageBytes);
      expect(m.staticAccounts[m.instructions[0]!.programAddressIndex]).toBe(COMPUTE_PROGRAM);
      expect(m.staticAccounts[m.instructions[1]!.programAddressIndex]).toBe(COMPUTE_PROGRAM);
      return payerSigned(transaction);
    }),await unsigned());
    expect(adapter.signingReport()).toMatchObject({messageEqual:true,changedFields:[],changedSignatureSlots:[{signer:h.payer.address,before:"absent",after:"present"}]});
  });
  test.each([0,1])("wallet mutation of compute instruction %i is rejected even with a valid new payer signature",async(index)=>{
    await expect(adapter.walletSign(connection(async({transaction})=>{
      const mutated=Web3Transaction.from(transaction);mutated.instructions[index]!.data[1]! ^= 1;
      return payerSigned(new Uint8Array(mutated.serialize({requireAllSignatures:false,verifySignatures:false})));
    }),await unsigned())).rejects.toThrow("Wallet changed the offered transaction");
    expect(adapter.signingReport()).toMatchObject({messageEqual:false,changedFields:["instructions"]});
  });
  test("the diagnostic insertion changes header/account ordering/instructions while preserving economic instruction data",async()=>{
    const original=await h.signedAuthorize({salt:h.newSalt(),signers:[]});
    const before=legacy(original.messageBytes);
    const altered=Web3Transaction.from(new Uint8Array(getBase64Encoder().encode(encodeTransaction(original))));
    altered.add(ComputeBudgetProgram.setComputeUnitLimit({units:200000}),ComputeBudgetProgram.setComputeUnitPrice({microLamports:100000}));
    const after=legacy(decoder.decode(new Uint8Array(altered.serialize({requireAllSignatures:false,verifySignatures:false}))).messageBytes);
    expect(after.header.numReadonlyNonSignerAccounts).toBe(before.header.numReadonlyNonSignerAccounts+1);
    expect(after.staticAccounts).toHaveLength(before.staticAccounts.length+1);
    expect(after.instructions).toHaveLength(before.instructions.length+2);
    expect(Buffer.from(after.instructions[0]!.data!)).toEqual(Buffer.from(before.instructions[0]!.data!));
    expect(after.instructions[0]!.accountIndices).not.toEqual(before.instructions[0]!.accountIndices);
  });
  test("Solflare appending its default budget to the finalized message is rejected",async()=>{
    await expect(adapter.walletSign(connection(async({transaction})=>{
      const altered=Web3Transaction.from(transaction);
      altered.add(ComputeBudgetProgram.setComputeUnitLimit({units:200000}),ComputeBudgetProgram.setComputeUnitPrice({microLamports:100000}));
      return payerSigned(new Uint8Array(altered.serialize({requireAllSignatures:false,verifySignatures:false})));
    }),await unsigned())).rejects.toThrow("Wallet changed the offered transaction");
    expect(adapter.signingReport().changedFields).toContain("instructions");
  });
  test.each(["header","blockhash","feePayer","accountOrder","instructionCount","instructionOrder","program","accounts","data"])("wallet changing %s is rejected by exact message equality",async(field)=>{
    await expect(adapter.walletSign(connection(async({transaction})=>{
      const altered=VersionedTransaction.deserialize(transaction);
      if(altered.message.version!=="legacy")throw new Error("legacy expected");
      const m=altered.message;
      switch(field){
        case "header":m.header.numReadonlyUnsignedAccounts--;break;
        case "blockhash":m.recentBlockhash=h.outsider.address;break;
        case "feePayer":m.accountKeys[0]=new PublicKey(h.outsider.address);break;
        case "accountOrder":[m.accountKeys[2],m.accountKeys[3]]=[m.accountKeys[3]!,m.accountKeys[2]!];break;
        case "instructionCount":m.instructions.pop();break;
        case "instructionOrder":[m.instructions[0],m.instructions[1]]=[m.instructions[1]!,m.instructions[0]!];break;
        case "program":m.instructions[2]!.programIdIndex=m.instructions[0]!.programIdIndex;break;
        case "accounts":m.instructions[2]!.accounts.reverse();break;
        case "data":m.instructions[2]!.data="1";break;
      }
      return payerSigned(altered.serialize());
    }),await unsigned())).rejects.toThrow("Wallet changed the offered transaction");
    expect(adapter.signingReport().messageEqual).toBe(false);
  });
  test.each(["limit","price","missing","duplicate"])("a %s budget violation is refused before the wallet call",async(kind)=>{
    let called=false;
    const extra=kind==="missing"?[]:kind==="duplicate"?[...demoComputeInstructions(200000),getSetComputeUnitLimitInstruction(200000)]:[getSetComputeUnitLimitInstruction(kind==="limit"?200001:200000),getSetComputeUnitPriceInstruction(kind==="price"?100001n:100000n)];
    const offered=encodeTransaction(await h.signedAuthorize({salt:h.newSalt(),signers:[],extra}));
    await expect(adapter.walletSign(connection(async()=>{called=true;return[];}),offered)).rejects.toThrow(/compute/);
    expect(called).toBe(false);
  });
  test("only absent-to-present payer insertion is allowed; existing payer or changed sponsor is rejected",async()=>{
    const tx=await buildDemoTransaction({...await args(),signers:[h.facilitatorKey]},h.ledger);
    const alreadySigned=await partiallySignTransaction([h.payer.keyPair],tx);let called=false;
    await expect(adapter.walletSign(connection(async()=>{called=true;return[];}),encodeTransaction(alreadySigned))).rejects.toThrow("must be absent");expect(called).toBe(false);
    await expect(adapter.walletSign(connection(async({transaction})=>{
      const [signed]=await payerSigned(transaction);const wire=new Uint8Array(signed!.signedTransaction);wire[1]! ^= 1;return[{signedTransaction:wire}];
    }),encodeTransaction(tx))).rejects.toThrow("only the payer signature");
  });
  test.each(["failure","missing","zero","excessive"])("%s compute simulation stops preparation before signing",async(kind)=>{
    const a={...await args(),signers:[h.facilitatorKey]};
    await expect(buildDemoTransaction(a,{simulate:async()=>kind==="failure"?{ok:false,error:"failure",logs:[]}:{ok:true,...(kind==="missing"?{}:{unitsConsumed:kind==="zero"?0n:200000n})}})).rejects.toThrow(/compute/);
  });
  test("the Devnet sponsor accepts the preset price but refuses excessive limit or price without submission",async()=>{
    const facilitator=new Facilitator({network:h.ledger.network,programId:h.facilitator.programId,feePayer:h.facilitatorKey,ledger:h.ledger,...demoSponsorComputeBounds()});
    const offered=await buildDemoTransaction(await args(),h.ledger);
    const signed=await partiallySignTransaction([h.payer.keyPair],offered);
    expect(await facilitator.verify(h.body(authorizePayload(signed)))).toMatchObject({isValid:true});
    for(const extra of [[getSetComputeUnitLimitInstruction(200001),getSetComputeUnitPriceInstruction(100000n)],[getSetComputeUnitLimitInstruction(200000),getSetComputeUnitPriceInstruction(100001n)]]){
      const excessive=await h.signedAuthorize({salt:h.newSalt(),extra});
      expect(await facilitator.verify(h.body(authorizePayload(excessive)))).toMatchObject({isValid:false,invalidReason:Reason.instructions});
    }
    expect(h.ledger.submissions).toHaveLength(0);
  });
  test("priority fee exposure has an explicit 20,000 lamport ceiling with upward fee rounding",()=>{
    expect(demoPriorityFeeLamports(200000)).toBe(20000n);
    expect(demoPriorityFeeLamports(49000)).toBe(4900n);
    expect(demoPriorityFeeLamports(1)).toBe(1n);
    expect(()=>demoPriorityFeeLamports(200001)).toThrow("exposure bound");
    expect(()=>demoPriorityFeeLamports(200000,100001n)).toThrow("exposure bound");
    expect(demoSponsorComputeBounds()).toEqual({maxComputeUnitLimit:200000,maxComputeUnitPriceMicroLamports:100000n});
  });
  test("a wallet resetting only price to the offered 100,000 leaves message bytes identical",async()=>{
    await adapter.walletSign(connection(async({transaction})=>{
      const same=Web3Transaction.from(transaction);
      same.instructions[1]!.data=ComputeBudgetProgram.setComputeUnitPrice({microLamports:100000}).data;
      return payerSigned(new Uint8Array(same.serialize({requireAllSignatures:false,verifySignatures:false})));
    }),await unsigned());
    expect(adapter.signingReport()).toMatchObject({messageEqual:true,changedFields:[],changedSignatureSlots:[{signer:h.payer.address,before:"absent",after:"present"}]});
  });
  test("the deterministic margin rounds up and never silently clips an over-cap estimate",()=>{
    expect(demoComputeLimit(25001n)).toBe(28000);expect(demoComputeLimit(1n)).toBe(10000);
    expect(()=>demoComputeLimit(181819n)).toThrow("bound");expect(()=>demoComputeInstructions(DEMO_COMPUTE.maxUnitLimit+1)).toThrow("bound");
  });
});
