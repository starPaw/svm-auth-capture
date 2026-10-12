// RPC scheduling is not economic admission. Retry reads only; a signed send uses
// one paced call. Every wait observes the caller's existing absolute deadline.
import { isSolanaError, SOLANA_ERROR__RPC__TRANSPORT_HTTP_ERROR } from '@solana/kit';

function aborted(signal: AbortSignal): never { throw signal.reason ?? new DOMException('RPC wait aborted', 'AbortError'); }
function wait(ms: number, signal: AbortSignal): Promise<void> {
  if(signal.aborted) aborted(signal);
  if(ms<=0) return Promise.resolve();
  return new Promise((resolve,reject) => {
    const finish=()=>{signal.removeEventListener('abort',cancel);resolve();};
    const timer=setTimeout(finish,Math.min(ms,2_147_483_647));
    const cancel=()=>{clearTimeout(timer);signal.removeEventListener('abort',cancel);reject(signal.reason ?? new DOMException('RPC wait aborted','AbortError'));};
    signal.addEventListener('abort',cancel,{once:true});
  });
}
export class RpcRequestScheduler {
  private readonly intervalMs:number;
  private readonly readRetries:number;
  private nextStart=0;
  private cooldownUntil=0;
  private tail:Promise<void>=Promise.resolve();
  constructor(intervalMs=0,readRetries=3) {
    if(!Number.isSafeInteger(intervalMs) || intervalMs<0 || intervalMs>5000 || !Number.isSafeInteger(readRetries) || readRetries<0 || readRetries>3) throw Error('Invalid RPC scheduling limits');
    this.intervalMs=intervalMs;this.readRetries=readRetries;
  }
  noteRateLimit(error:unknown,attempt=0):boolean {
    if(!isSolanaError(error,SOLANA_ERROR__RPC__TRANSPORT_HTTP_ERROR) || error.context.statusCode!==429)return false;
    let delay=250*2**attempt;
    // Only this standard header is consumed. Provider messages/headers/URLs are never retained.
    try {
      const value=error.context.headers.get('retry-after');
      if(value && /^\d+(?:\.\d+)?$/.test(value))delay=Number(value)*1000;
      else if(value && Number.isFinite(Date.parse(value)))delay=Math.max(0,Date.parse(value)-Date.now());
    } catch { /* A malformed header does not grant a shorter wait. */ }
    if(!Number.isFinite(delay) || delay<0)delay=250*2**attempt;
    this.cooldownUntil=Math.max(this.cooldownUntil,Date.now()+Math.ceil(delay));
    return true;
  }
  async pace(signal:AbortSignal):Promise<void> {
    const turn=this.tail.then(async()=>{
      if(signal.aborted)aborted(signal);
      while(Date.now()<Math.max(this.nextStart,this.cooldownUntil))await wait(Math.max(this.nextStart,this.cooldownUntil)-Date.now(),signal);
      if(signal.aborted)aborted(signal);
      this.nextStart=Date.now()+this.intervalMs;
    });
    this.tail=turn.then(()=>{},()=>{});
    return turn;
  }
  async read<T>(signal:AbortSignal,request:(signal:AbortSignal)=>Promise<T>):Promise<T> {
    for(let attempt=0;;attempt++) {
      await this.pace(signal);
      if(signal.aborted)aborted(signal);
      try{return await request(signal);}
      catch(error){if(!this.noteRateLimit(error,attempt) || attempt>=this.readRetries)throw error;}
    }
  }
}
