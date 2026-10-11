import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { generateKeyPairSigner, getAddressEncoder, getSignatureFromTransaction, partiallySignTransaction } from "@solana/kit";
import { createIsolatedRecoveryFixture } from "../../src/recovery-enrollment.ts";
import { applyRestaurantOutcome, restaurantOutcomeEvidence, type OutcomeApplyOptions, type OutcomeReader } from "../../src/restaurant-outcome-apply.ts";
import { authorizeInstruction, buildTransaction, captureInstruction, encodeTransaction } from "../../src/transactions.ts";
import { DISCRIMINATOR, NATIVE_MINT, paymentAddress } from "../../src/program.ts";
import { messageHash } from "../../src/submission-journal.ts";
export async function outcomeFixture(failure = false, lockOnly = false) {
  const f = createIsolatedRecoveryFixture(), [payer,merchant,sponsor] = await Promise.all([generateKeyPairSigner(),generateKeyPairSigner(),generateKeyPairSigner()]);
  const salt = new Uint8Array(32).fill(7), payment = await paymentAddress(f.identity.programId,payer.address,salt), id = "1234567890abcdef1234567890abcdef";
  const common = { programId:f.identity.programId,payment,payer:payer.address,server:merchant.address,mint:NATIVE_MINT };
  const lifetime = { blockhash:f.identity.genesisHash as any,lastValidBlockHeight:10n };
  const unsigned = await buildTransaction({ feePayer:sponsor.address,signers:[],instructions:[await authorizeInstruction({ ...common,funder:sponsor.address,salt,maximum:100000000n,captureDeadline:1000n,refundDeadline:1100n })],lifetime });
  const auth = await partiallySignTransaction([payer.keyPair,sponsor.keyPair],unsigned), authSignature = getSignatureFromTransaction(auth);
  const capture = await buildTransaction({ feePayer:sponsor.address,signers:[merchant],instructions:[await captureInstruction(common,40000000n,false,100000000n,0n)],lifetime });
  const signed = await partiallySignTransaction([sponsor.keyPair],capture), signature = getSignatureFromTransaction(signed);
  const authEvent = { action:"authorize",label:"Budget authorized",at:"synthetic",amount:"100000000",status:"finalized",transaction:authSignature,transactionBase64:encodeTransaction(auth),receipt:{ success:true,transaction:authSignature,network:f.identity.network } };
  const event = { action:"beer",label:"Beer + Ribs",at:"synthetic",amount:"40000000",status:"pending",transaction:"",transactionBase64:encodeTransaction(capture) };
  const order = { id,payer:payer.address,payment,capabilityHash:"synthetic-only",scenario:"normal",createdAt:1,status:"pending",unsigned:encodeTransaction(unsigned),
    required:{ accepts:[{ network:f.identity.network,payTo:merchant.address,asset:NATIVE_MINT,amount:"100000000",extra:{ captureDeadline:1000,refundDeadline:1100 } }] },events:lockOnly ? [authEvent] : [authEvent,event] };
  const persist = (path:string,value:unknown) => writeFileSync(path,typeof value === "string" ? value : JSON.stringify(value),{ mode:0o600 });
  const path = join(f.paths.orders,id+".json"),busyPath = path+".busy",lockPath = path+".beer.lock";
  persist(path,order);persist(path+".authorize.lock",authEvent);persist(lockPath,event);persist(busyPath,"beer");
  for (const [tx,sig,operation,h] of [[auth,authSignature,"authorize","0"],[signed,signature,"capture","100000000"]] as const) {
    persist(join(f.paths.facilitator,sig+".json"),{ signature:sig,transactionBase64:encodeTransaction(tx),messageHash:messageHash(tx.messageBytes),blockhash:f.identity.genesisHash,operation,payment,payer:payer.address,expectedHeld:h,expectedRefundable:"0",attempts:[{ preparedAt:"synthetic",outcome:{ result:operation === "authorize" ? "finalized-succeeded" : "unresolved",recordedAt:"synthetic" } }] });
  }
  const data = new Uint8Array(176), addresses = getAddressEncoder(),view = new DataView(data.buffer);
  data.set(DISCRIMINATOR);data.set(addresses.encode(payer.address),8);data.set(addresses.encode(merchant.address),40);data.set(addresses.encode(NATIVE_MINT),72);data.set(salt,104);
  view.setBigUint64(136,100000000n,true);view.setBigInt64(144,1000n,true);view.setBigInt64(152,1100n,true);view.setBigUint64(160,failure ? 100000000n : 60000000n,true);view.setBigUint64(168,failure ? 0n : 40000000n,true);
  const account = { owner:f.identity.programId,executable:false,lamports:1n,data };
  const reader: OutcomeReader = { verifyIdentity:async () => f.identity,
    getSignatureStatus:async sig => ({ kind:"found",commitment:"finalized",slot:sig===signature ? 40n : 30n,err:sig===signature && failure ? "InstructionError:synthetic" : null }),
    getAccountAtLeast:async (_address,minSlot) => { if (minSlot !== 40n) throw new Error("missing slot fence"); return { kind:"ok",slot:42n,account }; },
    findSignaturesByMessage:async () => { throw new Error("history should never substitute for originals"); },isBlockhashValid:async () => { throw new Error("expiry should never substitute for finality"); } };
  for (const method of ["sign","simulate","submit","settle","fulfillment","recordResult"]) Object.defineProperty(reader,method,{ get() { throw new Error("economic capability accessed: "+method); } });
  const request = { domain:f.domain,enrollment:f.enrollment,identity:f.identity,orderId:id,action:"beer" as const,signature };
  const evidenceDigest = await restaurantOutcomeEvidence(request),options: OutcomeApplyOptions = { ...request,evidenceDigest,reader };
  return { ...f,id,order,event,signature,authSignature,path,busyPath,lockPath,reader,account,options,persist,apply:() => applyRestaurantOutcome(options) };
}
