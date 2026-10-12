import { afterEach,expect,test,vi } from 'vitest';
import { SolanaError,SOLANA_ERROR__RPC__TRANSPORT_HTTP_ERROR } from '@solana/kit';
import { RpcRequestScheduler } from '../src/rpc-request-scheduler.ts';
const limited=(value?:string,statusCode=429)=>new SolanaError(SOLANA_ERROR__RPC__TRANSPORT_HTTP_ERROR,{statusCode,message:'SYNTHETIC_PRIVATE_DETAIL',headers:new Headers(value?{'Retry-After':value}:{})});
afterEach(()=>vi.useRealTimers());
test('429 read waits for Retry-After and then observes the same read',async()=>{
  vi.useFakeTimers();const scheduler=new RpcRequestScheduler(),controller=new AbortController();
  const request=vi.fn().mockRejectedValueOnce(limited('0.02')).mockResolvedValue('original-result');
  const result=scheduler.read(controller.signal,request);
  await vi.advanceTimersByTimeAsync(19);expect(request).toHaveBeenCalledOnce();
  await vi.advanceTimersByTimeAsync(1);expect(await result).toBe('original-result');expect(request).toHaveBeenCalledTimes(2);
});
test.each(['10','10000000000',new Date(Date.now()+60_000).toUTCString()])('long Retry-After %s cannot escape the caller deadline',async header=>{
  vi.useFakeTimers();const scheduler=new RpcRequestScheduler(),controller=new AbortController();
  const request=vi.fn().mockRejectedValue(limited(header));
  const result=scheduler.read(controller.signal,request);const refused=expect(result).rejects.toThrow();
  setTimeout(()=>controller.abort(),10);await vi.advanceTimersByTimeAsync(10);await refused;
  expect(request).toHaveBeenCalledOnce();expect(vi.getTimerCount()).toBe(0);
  await vi.advanceTimersByTimeAsync(120_000);expect(request).toHaveBeenCalledOnce();
});
test('non-429 failure is not retried and keeps the original exception',async()=>{
  const scheduler=new RpcRequestScheduler(),error=limited(undefined,503),request=vi.fn().mockRejectedValue(error);
  await expect(scheduler.read(new AbortController().signal,request)).rejects.toBe(error);expect(request).toHaveBeenCalledOnce();
});
test('repeated 429 reads are bounded to one initial call and three read retries',async()=>{
  const scheduler=new RpcRequestScheduler(),error=limited('0'),request=vi.fn().mockRejectedValue(error);
  await expect(scheduler.read(new AbortController().signal,request)).rejects.toBe(error);expect(request).toHaveBeenCalledTimes(4);
});
test('a malformed Retry-After uses bounded backoff rather than immediate requests',async()=>{
  vi.useFakeTimers();const scheduler=new RpcRequestScheduler(),request=vi.fn().mockRejectedValueOnce(limited('provider-private-message')).mockResolvedValue(1);
  const result=scheduler.read(new AbortController().signal,request);
  await vi.advanceTimersByTimeAsync(249);expect(request).toHaveBeenCalledOnce();
  await vi.advanceTimersByTimeAsync(1);expect(await result).toBe(1);
});
test('concurrent calls have spaced starts and abort never dispatches a queued read',async()=>{
  vi.useFakeTimers();const scheduler=new RpcRequestScheduler(25),controller=new AbortController(),started:number[]=[];
  const first=scheduler.read(new AbortController().signal,async()=>{started.push(Date.now());return 1;});
  const refused=scheduler.read(controller.signal,async()=>{started.push(Date.now());return 2;});const rejected=expect(refused).rejects.toThrow();
  const last=scheduler.read(new AbortController().signal,async()=>{started.push(Date.now());return 3;});
  await vi.advanceTimersByTimeAsync(5);controller.abort();await rejected;
  await vi.advanceTimersByTimeAsync(20);expect(await first).toBe(1);expect(await last).toBe(3);
  expect(started).toHaveLength(2);expect(started[1]!-started[0]!).toBe(25);
});
test('a send-side 429 shares cooldown but pacing never invokes another send',async()=>{
  vi.useFakeTimers();const scheduler=new RpcRequestScheduler(),controller=new AbortController(),send=vi.fn();
  await scheduler.pace(controller.signal);send();expect(scheduler.noteRateLimit(limited('0.03'))).toBe(true);
  const read=vi.fn().mockResolvedValue('same-signature'),result=scheduler.read(controller.signal,read);
  await vi.advanceTimersByTimeAsync(29);expect(read).not.toHaveBeenCalled();expect(send).toHaveBeenCalledOnce();
  await vi.advanceTimersByTimeAsync(1);expect(await result).toBe('same-signature');expect(send).toHaveBeenCalledOnce();
});
