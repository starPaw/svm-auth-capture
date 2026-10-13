// A bounded gift of existing Devnet test tokens, outside x402 and escrow.
// The recipient signs an offchain request; only the existing sponsor signs the
// transfer from its separately provisioned token pool. No mint key is loaded.
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { type Address, type KeyPairSigner,
  getPublicKeyFromAddress, verifySignature, type SignatureBytes, partiallySignTransaction,
  getSignatureFromTransaction, isAddress } from '@solana/kit';
import { AccountState, getMintDecoder, getTokenDecoder, getTokenSize,
  getCreateAssociatedTokenIdempotentInstruction, getTransferCheckedInstruction } from '@solana-program/token';
import { Hono } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { requireBearerToken } from './auth.ts';
import { ata, TOKEN_PROGRAM_ADDRESS } from './program.ts';
import { buildDemoTransaction } from './demo-compute.ts';
import { encodeTransaction } from './transactions.ts';
import { messageDigest, verifiedProof } from './campaign-proof.ts';
import { CampaignBudget } from './campaign-budget.ts';
import type { BudgetBackend } from './campaign-sponsorship.ts';
import type { Ledger } from './ledger.ts';
import type { Lifetime } from './transactions.ts';
import { SponsorshipGuard } from './sponsorship.ts';
import { DevnetFaucetStore, FAUCET_AMOUNT, FaucetQuotaRefusal, type FaucetEntry } from './devnet-faucet-store.ts';

export type FaucetConfig = { store: DevnetFaucetStore; sponsor: KeyPairSigner;
  ledger: Ledger; backend: BudgetBackend; budget: CampaignBudget; admission: SponsorshipGuard;
  latest: ()=>Promise<Lifetime>; challengeKey: string; bearerToken: string };
type RequestIntent = { schema:1; id:string; recipient:Address; issuedAt:number; expiresAt:number; policyHash:string };
const sha = (value:string)=>createHash('sha256').update(value).digest('hex');
const canonical = (v:unknown)=>JSON.stringify(v);
const clock = (v:bigint) => {const n=Number(v);if(!Number.isSafeInteger(n)||n<=0)throw Error('invalid finalized faucet Clock');return n;};
const messageFor = (i:RequestIntent,origin:string,mint:Address) =>
  `Capture402 Devnet test-token request\nOrigin: ${origin}\nRecipient: ${i.recipient}\nMint: ${mint}\nAmount: 1000 test tokens\nNetwork: Solana Devnet\nRequest: ${i.id}\nExpires: ${i.expiresAt}\nNo funds or transaction authority are granted by this message.`;
export class FaucetRefusal extends Error {}

export class DevnetFaucet {
  readonly store: DevnetFaucetStore;
  private readonly config:FaucetConfig;
  private readonly policyHash:string;
  private challengeWindow={at:0,count:0};
  constructor(config:FaucetConfig) {
    this.store=config.store;this.config=config;this.policyHash=sha(canonical(this.store.policy));
    if(config.challengeKey.length<32 || config.challengeKey.trim()!==config.challengeKey ||
      config.sponsor.address!==this.store.policy.sponsor || config.ledger.network!==this.store.policy.network ||
      config.budget.policy.sponsor!==config.sponsor.address || config.budget.policy.genesisHash!==this.store.policy.genesisHash ||
      config.admission.attemptCount>600)throw Error('faucet runtime/policy mismatch');
  }
  blocked():boolean {return this.store.pending().length!==0;}
  async challenge(recipient:Address) {
    if(!isAddress(recipient)||recipient===this.store.policy.sponsor)throw new FaucetRefusal('Connect the recipient wallet.');
    if(this.blocked())throw new FaucetRefusal('Original faucet operation pending or unknown. New economics stopped.');
    if(this.store.summary().used>=100)throw new FaucetRefusal('The total test-token claim limit has been reached.');
    const wallNow=Date.now();
    if(Math.floor(wallNow/1000)<this.store.nextEligibleAt(recipient))throw new FaucetRefusal('This wallet may request 1000 test tokens once per 24 hours.');
    if(wallNow-this.challengeWindow.at>=60_000)this.challengeWindow={at:wallNow,count:0};
    if(++this.challengeWindow.count>60)throw new FaucetRefusal('Too many test-token requests. Try again later.');
    // No RPC, account allocation, signing or durable admission for unsigned challenges.
    const issuedAt=Math.floor(wallNow/1000);
    const i:RequestIntent={schema:1,id:randomBytes(32).toString('hex'),recipient,issuedAt,expiresAt:issuedAt+600,policyHash:this.policyHash};
    const payload=Buffer.from(canonical(i)).toString('base64url');
    const mac=createHmac('sha256',this.config.challengeKey).update('capture402-devnet-faucet-v1\0').update(payload).digest('base64url');
    return {id:i.id,recipient,amount:1000,mint:this.store.policy.mint,expiresAt:i.expiresAt,
      message:messageFor(i,this.store.policy.origin,this.store.policy.mint),token:`${payload}.${mac}`};
  }
  private intent(token:string):RequestIntent {
    if(typeof token!=='string'||token.length>2048||!/^[-_A-Za-z0-9]+\.[-_A-Za-z0-9]+$/.test(token))throw new FaucetRefusal('Invalid test-token request.');
    const [payload,mac]=token.split('.') as [string,string];
    const expected=createHmac('sha256',this.config.challengeKey).update('capture402-devnet-faucet-v1\0').update(payload).digest();
    const actual=Buffer.from(mac,'base64url');
    if(actual.length!==expected.length||actual.toString('base64url')!==mac||!timingSafeEqual(actual,expected))throw new FaucetRefusal('Invalid test-token request.');
    const i=JSON.parse(Buffer.from(payload,'base64url').toString('utf8')) as RequestIntent;
    if(!i || Object.keys(i).sort().join()!=='expiresAt,id,issuedAt,policyHash,recipient,schema' || i.schema!==1 ||
      !/^[a-f0-9]{64}$/.test(i.id)||!isAddress(i.recipient)||i.recipient===this.store.policy.sponsor||i.policyHash!==this.policyHash ||
      !Number.isSafeInteger(i.issuedAt)||i.issuedAt<=0||i.expiresAt!==i.issuedAt+600 || Buffer.from(canonical(i)).toString('base64url')!==payload)throw new FaucetRefusal('Invalid test-token request.');
    return i;
  }
  private view(e:FaucetEntry) {
    return {id:e.id,recipient:e.recipient,amount:1000,mint:this.store.policy.mint,
      status:e.stage==='finalized'?(e.outcome!.succeeded?'finalized':'failed'):e.stage==='refused'?'refused':e.stage==='reserved'?'pending':'unknown',
      signature:e.signature??null,finalizedSlot:e.outcome?.slot??null,nextEligibleAt:e.requestedAt+86400};
  }
  async observe(id:string) {
    const e=this.store.get(id);if(!e)throw new FaucetRefusal('Original test-token request unavailable.');
    if(e.stage==='signed') {
      const proof=await this.config.backend.finalized(e.signature!);
      if(proof) {
        const verified=await verifiedProof(e.signature!,proof);
        if(verified.messageHash!==e.messageHash || proof.wire!==e.signed ||
          verified.message.header.numSignerAccounts!==1 || verified.message.staticAccounts[0]!==this.config.sponsor.address)throw Error('faucet original finalized proof mismatch');
        await this.config.budget.finalize(e.budgetId!,e.signature!,proof);
        this.store.finalize(id,e.signature!,proof.slot,proof.error===null);
      }
    }
    return this.view(this.store.get(id)!);
  }
  async claim(token:string,signature:string) {
    const i=this.intent(token);
    if(typeof signature!=='string'||!/^[A-Za-z0-9+/]{86}==$/.test(signature))throw new FaucetRefusal('Wallet message signature required.');
    const bytes=Buffer.from(signature,'base64');
    if(bytes.length!==64||bytes.toString('base64')!==signature || !await verifySignature(await getPublicKeyFromAddress(i.recipient),bytes as unknown as SignatureBytes,
      new TextEncoder().encode(messageFor(i,this.store.policy.origin,this.store.policy.mint))))throw new FaucetRefusal('Wallet message signature differs from the original request.');
    // Replays only inspect the original; they never quote, sign, reserve or submit again.
    if(this.store.get(i.id))return this.observe(i.id);
    const now=clock(await this.config.ledger.now());
    if(now<i.issuedAt-30||now>=i.expiresAt)throw new FaucetRefusal('Test-token request expired. No transfer was started.');
    this.store.reserve(i.id,i.recipient,now,{message:messageFor(i,this.store.policy.origin,this.store.policy.mint),signature,
      tokenSha256:sha(token),issuedAt:i.issuedAt,expiresAt:i.expiresAt});
    try {
      const p=this.store.policy;
      if(await ata(p.sponsor,p.mint)!==p.pool)throw Error('faucet pool ATA mismatch');
      const mint=await this.config.ledger.getAccount(p.mint),pool=await this.config.ledger.getAccount(p.pool);
      if(!mint || mint.owner!==TOKEN_PROGRAM_ADDRESS || mint.data.length!==getMintDecoder().fixedSize ||
        !getMintDecoder().decode(mint.data).isInitialized || getMintDecoder().decode(mint.data).decimals!==6 ||
        !pool || pool.owner!==TOKEN_PROGRAM_ADDRESS || pool.data.length!==getTokenSize())throw new FaucetRefusal('Test-token supply is unavailable.');
      const balance=getTokenDecoder().decode(pool.data);
      if(balance.mint!==p.mint || balance.owner!==p.sponsor || balance.state!==AccountState.Initialized || balance.amount<FAUCET_AMOUNT)throw new FaucetRefusal('Test-token supply is unavailable.');
      const target=await ata(i.recipient,p.mint),lifetime=await this.config.latest();
      const instructions=[getCreateAssociatedTokenIdempotentInstruction({payer:this.config.sponsor,ata:target,owner:i.recipient,mint:p.mint,tokenProgram:TOKEN_PROGRAM_ADDRESS}),
        getTransferCheckedInstruction({source:p.pool,mint:p.mint,destination:target,authority:this.config.sponsor,amount:FAUCET_AMOUNT,decimals:6})];
      const tx=await buildDemoTransaction({feePayer:p.sponsor,signers:[],instructions,lifetime},this.config.ledger);
      const hash=messageDigest(tx.messageBytes),budgetId=`faucet-${i.id}`;
      this.store.prepare(i.id,{messageHash:hash,unsigned:encodeTransaction(tx),budgetId,blockhash:lifetime.blockhash,lastValidBlockHeight:String(lifetime.lastValidBlockHeight)});
      const denial=await this.config.admission.check();if(denial)throw new FaucetRefusal('Test-token spending capacity is unavailable.');
      const [fee,rent]=await Promise.all([this.config.backend.fee(tx),this.config.backend.rent(getTokenSize())]);
      if(fee<=0n||fee>25_000n||rent<=0n)throw Error('invalid bounded faucet quote');
      this.config.budget.reserve(budgetId,'sponsorship',hash,{fees:fee,rent,browserAllocation:0n});
      this.store.signing(i.id); // Durable stop before invoking the existing sponsor key.
      const signed=await partiallySignTransaction([this.config.sponsor.keyPair],tx);
      const original=getSignatureFromTransaction(signed);
      this.store.signed(i.id,original,encodeTransaction(signed)); // Exact original bytes before one submit.
      await this.config.ledger.submit(signed);
      return await this.observe(i.id);
    } catch(error) {
      const e=this.store.get(i.id)!;
      if(e.stage==='reserved') {this.store.refuseBeforeSigning(i.id);throw error;}
      // Signed/possibly signed or fsync ambiguity stays UNKNOWN with its full reserve.
      return this.view(e);
    }
  }
}

export function createDevnetFaucetApp(faucet:DevnetFaucet,bearerToken:string):Hono {
  const app=new Hono();
  app.use('*',requireBearerToken(bearerToken));
  app.use('*',bodyLimit({maxSize:4096,onError:c=>c.json({error:'request too large'},413)}));
  app.use('*',async(c,next)=>{c.header('Cache-Control','no-store');await next();});
  app.onError((e,c)=>c.json({error:e instanceof FaucetRefusal||e instanceof FaucetQuotaRefusal?e.message:'Original test-token operation unavailable. Inspect its receipt; do not repeat.'},409));
  app.get('/health',c=>c.json({blocked:faucet.blocked()}));
  app.post('/challenge',async c=>{const b=await c.req.json();if(!b||Object.keys(b).join()!=='recipient')return c.json({error:'recipient only'},400);return c.json(await faucet.challenge(b.recipient));});
  app.post('/claim',async c=>{const b=await c.req.json();if(!b||Object.keys(b).sort().join()!=='signature,token')return c.json({error:'original request and wallet signature only'},400);return c.json(await faucet.claim(b.token,b.signature));});
  app.get('/claims/:id',async c=>c.json(await faucet.observe(c.req.param('id'))));
  return app;
}
