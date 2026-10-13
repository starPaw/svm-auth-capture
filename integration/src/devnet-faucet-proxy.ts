// Public restaurant routes proxy only the fixed private faucet API. The bearer
// never enters browser config, URLs or response headers; no redirects are followed.
export type FaucetProxy = { request(path:string,method:'GET'|'POST',body?:unknown):Promise<Response> };
export function devnetFaucetProxy(url:string,bearerToken:string):FaucetProxy {
  const base=new URL(url);
  if(base.protocol!=='http:' || !['127.0.0.1','[::1]'].includes(base.hostname) || base.username || base.password || base.search || base.hash || base.pathname!=='/')throw Error('faucet gateway must stay on trusted loopback');
  return {async request(path,method,body) {
    if(!['/health','/challenge','/claim'].includes(path) && !/^\/claims\/[a-f0-9]{64}$/.test(path))throw Error('unapproved faucet route');
    if((['/challenge','/claim'].includes(path))!==(method==='POST') || method==='GET' && body!==undefined)throw Error('unapproved faucet method');
    const encoded=body===undefined?undefined:JSON.stringify(body);
    if(encoded!==undefined && Buffer.byteLength(encoded)>4096)throw Error('faucet request too large');
    return fetch(new URL(`/faucet${path}`,base),{method,headers:{Authorization:`Bearer ${bearerToken}`,...(encoded?{'Content-Type':'application/json'}:{})},
      body:encoded,redirect:'error',signal:AbortSignal.timeout(30_000)});
  }};
}
