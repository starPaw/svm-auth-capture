import {expect,test} from 'vitest';
import {Facilitator} from '../src/facilitator.ts';
import {LOCAL_PROGRAM_ID} from '../src/program.ts';
import {authorizePayload} from '../src/transactions.ts';
import {Reason} from '../src/types.ts';
import {createHarness,NETWORK} from './fixture.ts';
test('budget failure prevents sponsor co-signature/submission; verify cannot reserve',async()=>{
 const h=await createHarness();let reserves=0;
 try{
 const facilitator=new Facilitator({network:NETWORK,programId:LOCAL_PROGRAM_ID,feePayer:h.facilitatorKey,ledger:h.ledger,sponsorBudget:{reserve:async(tx)=>{reserves++;expect(tx.signatures[h.facilitatorKey.address]).toBeNull();throw Error('budget cap/fsync');},observe:async()=>{throw Error('must not run');}}});
 const body=h.body(authorizePayload(await h.signedAuthorize({salt:h.newSalt()})));
 expect(await facilitator.verify(body)).toMatchObject({isValid:true});expect(reserves).toBe(0);
 expect(await facilitator.settle(body)).toMatchObject({success:false,errorReason:Reason.settlementNotSubmitted,transaction:''});expect(reserves).toBe(1);expect(h.ledger.submissions).toHaveLength(0);
 }finally{h.close();}
});
test('finalized budget lookup failure preserves submitted settlement outcome and original signature',async()=>{
 const h=await createHarness();let reserves=0,observations=0;
 try{
 const facilitator=new Facilitator({network:NETWORK,programId:LOCAL_PROGRAM_ID,feePayer:h.facilitatorKey,ledger:h.ledger,sponsorBudget:{reserve:async(tx,op)=>{reserves++;expect(op).toBe('authorize');expect(tx.signatures[h.facilitatorKey.address]).toBeNull();return 'durable-reservation';},observe:async(id,signature)=>{observations++;expect(id).toBe('durable-reservation');expect(signature).toBe(h.ledger.submissions[0]!.signature);throw Error('missing RPC proof');}}});
 const body=h.body(authorizePayload(await h.signedAuthorize({salt:h.newSalt()})));
 expect(await facilitator.settle(body)).toMatchObject({success:true,transaction:expect.any(String)});expect(reserves).toBe(1);expect(observations).toBe(1);expect(h.ledger.submissions).toHaveLength(1);
 }finally{h.close();}
});
