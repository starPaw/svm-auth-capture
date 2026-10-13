// Browser/DOM fixtures only: no RPC, keypairs, signatures, wallet approvals or broadcasts.
// Run in an isolated network namespace with existing Playwright and Chromium:
// RESTAURANT_PLAYWRIGHT_MODULE=/path/to/playwright/index.mjs node browser/restaurant-check.mjs
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createServer } from 'node:https';
import { once } from 'node:events';
import { serve } from '@hono/node-server';
import { createPresentationApp } from '../src/restaurant-server.ts';
const { chromium } = await import(pathToFileURL(process.env.RESTAURANT_PLAYWRIGHT_MODULE));
const temp = mkdtempSync(join(tmpdir(), 'issue45-dom-'));
const output = process.env.RESTAURANT_QA_OUTPUT || temp;
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-keyout', join(temp, 'key.pem'), '-out', join(temp, 'cert.pem')], { stdio: 'pipe' });
const info = { programId:'11111111111111111111111111111111', network:'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1', configured:true, merchant:'11111111111111111111111111111111', mint:'11111111111111111111111111111111', sponsor:'11111111111111111111111111111111' };
const app = createPresentationApp(info); // No economic backend exists in this fixture.
const server = serve({ fetch:app.fetch, hostname:'127.0.0.1', port:0, createServer, serverOptions:{ key:readFileSync(join(temp,'key.pem')), cert:readFileSync(join(temp,'cert.pem')) } });
await once(server, 'listening');
const origin = `https://127.0.0.1:${server.address().port}`;
let browser;
const report = { scope:'Local HTTPS DOM fixtures; no Devnet, wallet signing or economic E2E claim.', browser:'', checks:[], viewports:[], requests:[] };
let lastActionBody, nextActionPreflight, definitiveResponse = false;
let renewalSequence=0;
let state, rpcFailure = false, posts = 0, gets = 0, loseResponse = false, delayPreflight = false, missingAuthority = false;
const secret = 'local-browser-fixture-credential-' + 'x'.repeat(32);
const id = 'a'.repeat(32);
const draft = () => ({ id, payer:info.merchant, payment:info.programId, scenario:'normal', status:'draft', authorized:0, captured:0, remaining:0, refunded:0, released:0, captureDeadline:Math.floor(Date.now()/1000)-5, refundDeadline:Math.floor(Date.now()/1000)+25, now:Math.floor(Date.now()/1000), events:[], actions:{beer:false,salmon:false,finish:false,void:false,refund:false,reclaim:false}, actionReasons:{beer:'Wallet approval is not finalized authorization.'}, balances:{payer:{amount:100,reason:''},merchant:{amount:0,reason:''}}, required:{accepts:[]}, unsigned:'unsigned-DOM-fixture-never-signed' });
const held = () => ({ ...draft(), status:'active', authorized:100, remaining:100, heldBaseUnits:'100000000', refundableBaseUnits:'0', captureDeadline:Math.floor(Date.now()/1000)+140, refundDeadline:Math.floor(Date.now()/1000)+170, actions:{beer:true,salmon:false,finish:false,void:true,refund:false,reclaim:false}, actionReasons:{beer:'',salmon:'Finalize capture 40 first.',finish:'Finalize captures 40 and 25 first.',void:'',refund:'No refundable captured balance.',reclaim:'Payer reclaim opens at the onchain capture deadline.'}, events:[{action:'authorize',label:'Local DOM authorize fixture',amount:100,at:new Date().toISOString(),status:'finalized',signature:'fixture-original-signature-not-onchain',chainStatus:{commitment:'finalized'}}] });
const check = name => report.checks.push(name);
try {
  browser = await chromium.launch({ headless:true }); report.browser = browser.version();
  const context = await browser.newContext({ ignoreHTTPSErrors:true, viewport:{width:1440,height:900} });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('request', req => { const u = new URL(req.url()); assert.equal(u.origin, origin, 'All runtime requests must be same origin'); assert(!req.url().includes(secret)); report.requests.push({path:u.pathname,method:req.method(),operatorBearer:!!req.headers().authorization}); });
  await page.route('**/api/orders**', async route => {
    const req = route.request(), path = new URL(req.url()).pathname;
    if (path === '/api/orders' && req.method() === 'POST') {
      posts++;
      const next = { ...draft(), id:'b'.repeat(32), captureDeadline:Math.floor(Date.now()/1000)+150, refundDeadline:Math.floor(Date.now()/1000)+180 };
      state = next;
      return route.fulfill({ status:402, contentType:'application/json', headers:{'PAYMENT-REQUIRED':Buffer.from(JSON.stringify(next.required)).toString('base64')}, body:JSON.stringify({order:next.id,unsigned:next.unsigned,required:next.required}) });
    }
    if(path.endsWith('/abandon-authorize') && req.method()==='POST') {
      posts++;state={...state,status:'abandoned',authorizeAbandonEligible:false,authorizeAbandoned:{kind:'expired-unfunded-authorize',order:state.id,payment:state.payment}};
      return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({abandoned:true,proof:{kind:'expired-unfunded-authorize',payment:state.payment}})});
    }
    if(path.endsWith('/reclaim-renewal') && req.method()==='POST') {
      posts++;const unsigned='renewed-DOM-fixture-never-signed-'+(++renewalSequence);state={...state,reclaimGeneration:createHash('sha256').update(unsigned).digest('hex'),reclaimDraftState:'ready',reclaimPreparation:false};
      return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({unsigned,payer:state.payer,proof:{kind:'expired-no-reclaim-effect'}})});
    }
    if (path.includes('/actions/')) {
      if (req.method() === 'GET') {
        gets++;
        if (nextActionPreflight) { state = nextActionPreflight; nextActionPreflight = undefined; }
        if (delayPreflight) await new Promise(resolve => setTimeout(resolve, 250));
        if (missingAuthority || req.headers().authorization !== `Bearer ${secret}`) return route.fulfill({status:401,contentType:'application/json',body:JSON.stringify({error:'fixture-refused'})});
        if (rpcFailure) return route.fulfill({status:409,contentType:'application/json',body:JSON.stringify({error:'fixture-RPC-unavailable'})});
        return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({...state,operatorAccess:true})});
      }
      posts++; lastActionBody = req.postData();
      if (loseResponse) return route.abort('failed');
      if (definitiveResponse) {
        const receipt={success:false,errorReason:'settlement_not_submitted',transaction:'',network:info.network,payer:state.payer};
        return route.fulfill({status:409,contentType:'application/json',headers:{'PAYMENT-RESPONSE':Buffer.from(JSON.stringify(receipt)).toString('base64')},body:JSON.stringify({receipt})});
      }
      return route.fulfill({status:409,contentType:'application/json',body:JSON.stringify({receipt:{success:false,errorReason:'settlement_pending',transaction:''}})});
    }
    return route.fulfill({status:rpcFailure?409:200,contentType:'application/json',body:JSON.stringify(rpcFailure?{error:'Finalized RPC state unavailable.'}:state)});
  });
  async function load(next, wallet = false) {
    nextActionPreflight = undefined; state = next; rpcFailure = false; posts = 0; gets = 0; loseResponse = false; missingAuthority = false; definitiveResponse = false;
    await page.goto(origin + '/customer');
    await page.evaluate(({state,id,wallet}) => {
      localStorage.clear(); if(state) localStorage.setItem('capture402-order',state.id);
      if(wallet) window.addEventListener('wallet-standard:app-ready', event => event.detail.register({name:'Local DOM wallet — cannot sign',features:{'standard:connect':{connect:async()=>({accounts:[{address:id,chains:['solana:devnet'],features:['solana:signTransaction']}]})},'solana:signTransaction':{supportedTransactionVersions:['legacy'],signTransaction:async()=>{window.fixtureSigns=(window.fixtureSigns||0)+1;throw new Error('DOM fixture cannot sign');}}}}), {once:true});
    }, {state:next,id:info.merchant,wallet});
    // Install registry before the module discovers wallets on the next navigation.
    await page.addInitScript(({wallet,id}) => { if(wallet) window.addEventListener('wallet-standard:app-ready', e=>e.detail.register({name:'Local DOM wallet — cannot sign',features:{'standard:connect':{connect:async()=>({accounts:[{address:id,chains:['solana:devnet'],features:['solana:signTransaction']}]})},'solana:signTransaction':{supportedTransactionVersions:['legacy'],signTransaction:async()=>{window.fixtureSigns=(window.fixtureSigns||0)+1;throw new Error('DOM fixture cannot sign');}}}}),{once:true}); }, {wallet,id:info.merchant});
    await page.reload(); if(next) await page.waitForFunction(()=>document.getElementById('payment-id').querySelector('a')); else await page.waitForFunction(()=>document.getElementById('clock-label').textContent.includes('no offer yet'));
  }
  await load(undefined);
  assert.equal(await page.locator('#clock').textContent(),'02:30'); assert(await page.locator('#authorize').isDisabled());
  assert((await page.locator('#authorize-reason').textContent()).includes('Connect')); check('Absent wallet, no offer: 02:30 and explicit disabled reason');
  assert.equal(await page.locator('img').count(),0); assert(!(await page.content()).includes('praguemarina.cz')); check('No photograph or external photo dependency');
  await load(held(), true);
  await page.locator('#connect-wallet').click(); await page.locator('#wallet-list button').first().click();
  assert.equal(await page.locator('#payer-key').textContent(),info.merchant); assert(await page.locator('[data-action=beer]').isDisabled());
  check('Connected payer wallet and original order grant no merchant authority');
  for (const [width,height] of [[1440,900],[1024,768],[768,1024],[390,844],[320,740]]) {
    await page.setViewportSize({width,height});
    const layout = await page.evaluate(() => ({scrollWidth:document.documentElement.scrollWidth,pageHeight:document.documentElement.scrollHeight,merchantBottom:document.getElementById('merchant-panel').getBoundingClientRect().bottom,receiptTop:document.getElementById('history-heading').getBoundingClientRect().top,receiptBottom:document.querySelector('.history-card').getBoundingClientRect().bottom}));
    assert.equal(layout.scrollWidth,width,`${width}px horizontal overflow`);
    assert(layout.merchantBottom<=height,`${width}px operator panel must fit the opening screen`);
    if(width>=390) assert(layout.receiptBottom<=height,`${width}px original receipt must fit the opening screen`);
    report.viewports.push({width,height,...layout});
    if(width===1440||width===390||width===320) await page.screenshot({path:join(output,`restaurant-${width}.png`),fullPage:true});
  }
  check('Responsive layout at five viewports and screenshot evidence');
  await page.setViewportSize({width:1440,height:900});
  const before = posts;
  await page.locator('#merchant-secret').fill('wrong-but-long-fixture-credential-000000'); await page.locator('#unlock-merchant').click();
  await page.waitForFunction(()=>document.getElementById('action-status').textContent.includes('no economic request'));
  assert.equal(posts,before); assert(await page.locator('[data-action=beer]').isDisabled()); assert.equal(await page.locator('#merchant-secret').inputValue(),'');
  check('Invalid credential uses GET only; clears input and never posts an economic action');
  async function unlock() { await page.locator('#merchant-secret').fill(secret); await page.locator('#unlock-merchant').click(); await page.waitForFunction(()=>document.getElementById('operator-status').textContent.includes('verified')); await page.waitForFunction(()=>!document.getElementById('unlock-merchant').disabled); }
  await unlock(); assert(!(await page.locator('[data-action=beer]').isDisabled())); assert(await page.locator('[data-action=salmon]').isDisabled());
  assert.equal(await page.locator('#merchant-secret').inputValue(),'');
  async function noSecretLeak() {
    const contents = await page.evaluate(()=>({html:document.documentElement.outerHTML,local:JSON.stringify(localStorage),session:JSON.stringify(sessionStorage),cookie:document.cookie,url:location.href}));
    for(const value of Object.values(contents)) assert(!value.includes(secret),'Credential must remain absent from DOM/storage/cookie/URL');
  }
  await noSecretLeak(); check('Verified operator unlock enables only eligible action; no secret in DOM or persistent storage');
  await page.locator('#lock-merchant').click(); assert(await page.locator('[data-action=beer]').isDisabled()); check('Explicit lock clears operator access');
  await unlock(); await page.reload(); await page.waitForFunction(()=>document.getElementById('payment-state').textContent.includes('Finalized'));
  assert(await page.locator('[data-action=beer]').isDisabled()); await noSecretLeak(); check('Navigation clears operator secret and access');
  await unlock(); missingAuthority = true;
  await page.locator('[data-action=beer]').click(); await page.waitForFunction(()=>document.getElementById('action-status').textContent.includes('credential refused'));
  assert.equal(posts,0); assert(await page.locator('[data-action=beer]').isDisabled()); check('Authority revoked before action preflight cannot produce an economic POST');
  missingAuthority = false;
  state.events[0].label = '<img src=x onerror="window.fixtureXss=true">';
  await page.locator('#refresh').click(); await page.waitForFunction(()=>document.getElementById('timeline').textContent.includes('<img'));
  assert.equal(await page.locator('#timeline img').count(),0); assert.equal(await page.evaluate(()=>window.fixtureXss),undefined); check('XSS-sensitive event labels render as escaped text');
  await unlock(); rpcFailure = true;
  await page.locator('#refresh').click(); await page.waitForFunction(()=>document.getElementById('payment-state').textContent.includes('RPC unavailable'));
  assert(await page.locator('[data-action=beer]').isDisabled()); assert((await page.locator('[data-reason=beer]').textContent()).includes('RPC')); check('RPC failure pauses state and merchant actions');
  await load({...held(),status:'pending',actions:Object.fromEntries(Object.keys(held().actions).map(a=>[a,false])),actionReasons:{beer:'Original operation pending or reserved; inspect its signatures.'}});
  await unlock(); assert(await page.locator('[data-action=beer]').isDisabled()); assert((await page.locator('[data-reason=beer]').textContent()).includes('pending')); check('Pending original payment stays ineligible after valid operator authentication');
  await load({...held(),captureDeadline:Math.floor(Date.now()/1000)-1,actions:{...held().actions,beer:false,void:false,reclaim:true},actionReasons:{beer:'Onchain capture deadline expired.',reclaim:''}});
  await unlock(); assert.equal(await page.locator('#clock').textContent(),'00:00'); assert(await page.locator('[data-action=beer]').isDisabled()); assert(await page.locator('#new-budget').isHidden());
  check('Funded expired hold never resets deadlines or exposes replacement');
  await load(held()); missingAuthority = true;
  await page.locator('#merchant-secret').fill(secret); await page.locator('#unlock-merchant').click(); await page.waitForFunction(()=>document.getElementById('action-status').textContent.includes('no economic request'));
  assert.equal(posts,0); assert(await page.locator('[data-action=beer]').isDisabled()); check('Missing operator authority fails closed without an economic POST');
  await load(draft(),true); await page.locator('#connect-wallet').click(); await page.locator('#wallet-list button').first().click();
  assert.equal(await page.locator('#clock').textContent(),'00:00'); assert(await page.locator('#authorize').isDisabled());
  await page.locator('#new-budget').click(); await page.waitForFunction(()=>localStorage.getItem('capture402-order')==='b'.repeat(32)&&document.getElementById('payment-state').textContent.includes('Unsigned'));
  assert.equal(posts,1); assert.equal(await page.evaluate(()=>window.fixtureSigns||0),0); assert.equal(await page.evaluate(()=>localStorage.getItem('capture402-order')),'b'.repeat(32));
  check('Expired never-submitted draft replaced only by explicit click; separate unsigned offer, no wallet signing');
  await load(held()); await unlock(); delayPreflight = true;
  await page.evaluate(()=>{const b=document.querySelector('[data-action=beer]');b.click();b.click();});
  await page.waitForFunction(()=>document.getElementById('payment-state').textContent.includes('Unknown') || document.getElementById('payment-state').textContent.includes('Pending'));
  assert.equal(posts,1); assert(await page.locator('[data-action=beer]').isDisabled()); check('Concurrent clicks produce one POST; pending response stays locked');
  delayPreflight = false;
  await load(held()); await unlock(); loseResponse = true;
  await page.locator('[data-action=beer]').click(); await page.waitForFunction(()=>document.getElementById('payment-state').textContent.includes('Unknown'));
  assert.equal(posts,1); assert(await page.locator('[data-action=beer]').isDisabled());
  await page.reload(); await page.waitForFunction(()=>document.getElementById('payment-state').textContent.includes('Unknown'));
  assert(await page.locator('[data-action=beer]').isDisabled()); assert(await page.locator('#new-budget').isHidden()); await noSecretLeak(); check('Lost economic response persists non-secret lock through reload and blocks replacement');
  const refundable = {...held(),status:'closed',remaining:0,heldBaseUnits:'0',refundableBaseUnits:'65000000',captured:65,released:35,
    actions:{...held().actions,beer:false,void:false,refund:true},actionReasons:{...held().actionReasons,refund:''},
    balances:{payer:{amount:935,reason:''},merchant:{amount:10,reason:''}}};
  await load(refundable); await unlock();
  assert.equal(await page.locator('[data-action=refund]').count(),1);
  assert.equal(await page.locator('[data-action=refund]').textContent(),'Refund 10');
  assert(!(await page.locator('[data-action=refund]').isDisabled()));
  await page.locator('[data-action=refund]').click();
  await page.waitForFunction(()=>document.getElementById('payment-state').textContent.includes('Unknown'));
  assert.equal(posts,1); assert(!lastActionBody);
  await noSecretLeak(); check('Normal refund 10 needs only 10 liquidity at F=65; one bodyless POST locks on pending response');
  await load({...refundable,balances:{...refundable.balances,merchant:{amount:9.999999,reason:''}}}); await unlock();
  assert(await page.locator('[data-action=refund]').isDisabled());
  assert((await page.locator('[data-reason=refund]').textContent()).includes('cannot fund'));
  assert.equal(posts,0); check('Normal refund UI rejects liquidity below selected 10 before POST');
  await load({...refundable,refundableBaseUnits:'5000000'}); await unlock();
  assert(await page.locator('[data-action=refund]').isDisabled());
  assert.equal(posts,0); check('Normal refund UI rejects F below selected 10 before POST');
  await load({...refundable,refundableBaseUnits:undefined}); await unlock();
  assert(await page.locator('[data-action=refund]').isDisabled());
  assert.equal(posts,0); check('Unavailable finalized F blocks normal refund UI');
  await load(refundable); await unlock();
  nextActionPreflight = {...refundable,balances:{...refundable.balances,merchant:{amount:9.999999,reason:''}}};
  await page.locator('[data-action=refund]').click();
  await page.waitForFunction(()=>document.getElementById('action-status').textContent.includes('cannot fund'));
  assert.equal(posts,0); check('Fresh operator preflight rechecks selected refund liquidity before POST');
  const fullRefund = {...refundable,scenario:'refund',remaining:60,heldBaseUnits:'60000000',refundableBaseUnits:'40000000',captured:40,released:0,
    balances:{payer:{amount:900,reason:''},merchant:{amount:40,reason:''}}};
  await load(fullRefund); await unlock();
  assert.equal(await page.locator('[data-action=refund]').textContent(),'Merchant-funded refund');
  await page.locator('[data-action=refund]').click();
  await page.waitForFunction(()=>document.getElementById('payment-state').textContent.includes('Unknown'));
  assert.equal(posts,1); assert(!lastActionBody); check('Dedicated full refund remains bodyless with its original control and pending lock');
  await load({...fullRefund,balances:{...fullRefund.balances,merchant:{amount:10,reason:''}}}); await unlock();
  assert(await page.locator('[data-action=refund]').isDisabled());
  assert.equal(posts,0); check('Dedicated refund UI still requires full F liquidity');
  await load(held());await unlock();definitiveResponse=true;
  await page.locator('[data-action=beer]').click();await page.waitForFunction(()=>document.getElementById('action-status').textContent.includes('refused'));
  assert.equal(posts,1);assert.equal(await page.evaluate(()=>localStorage.getItem('capture402-uncertain')),null);
  assert(await page.evaluate(()=>JSON.parse(localStorage.getItem('capture402-request-'+localStorage.getItem('capture402-order'))).path.endsWith('/actions/beer')));
  check('Exact pre-dispatch body/header releases only its fresh latch and retains source-bound request metadata');
  const recovery={order:id,payer:info.merchant,payment:info.programId,policySha256:'a'.repeat(64),originalEvidenceSha256:'b'.repeat(64),classification:'source-bound-pre-dispatch-refusal',continued:false};
  const expiredHeld={...held(),captureDeadline:Math.floor(Date.now()/1000)-1,actions:{...held().actions,reclaim:true},reclaimPreparation:true,b3Recovery:recovery};
  await load(expiredHeld,true);await page.locator('#connect-wallet').click();await page.locator('#wallet-list button').first().click();
  await page.evaluate(()=>localStorage.setItem('capture402-uncertain',localStorage.getItem('capture402-order')));
  await page.locator('#refresh').click();await page.waitForFunction(()=>!document.getElementById('reclaim').disabled);
  assert(!(await page.locator('#reclaim').isDisabled()));assert(await page.locator('[data-action=beer]').isDisabled());assert(await page.locator('#new-budget').isHidden());
  assert.equal(await page.evaluate(()=>localStorage.getItem('capture402-uncertain')),id);
  check('Reviewed legacy provenance enables only distinct payer reclaim while original latch stays retained');
  await page.evaluate(()=>localStorage.setItem('capture402-reclaim-wallet-attempt',localStorage.getItem('capture402-order')));
  await page.locator('#refresh').click();await page.waitForFunction(()=>document.getElementById('reclaim').disabled);
  assert.equal(posts,0);check('Original reclaim wallet-consent marker blocks replacement signing across refresh');
  await page.waitForFunction(()=>!document.getElementById('renew-reclaim').hidden);assert(await page.locator('#renew-reclaim').isVisible());
  await page.locator('#renew-reclaim').click();await page.waitForFunction(()=>!document.getElementById('reclaim').disabled);
  assert.equal(posts,1);assert.equal(await page.evaluate(()=>window.fixtureSigns||0),0);
  assert.equal(await page.evaluate(()=>localStorage.getItem('capture402-uncertain')),id);
  assert.equal(await page.evaluate(()=>localStorage.getItem('capture402-reclaim-wallet-attempt')),id);
  assert.equal(await page.locator('#action-status').textContent(),'Previous reclaim wire archived after finalized no-effect proof. Fresh unsigned draft prepared; request signature separately.');
  check('Successful reviewed renewal preserves its no-effect preparation message after refresh, without claiming a finalized reclaim');
  check('Explicit renewal prepares one unsigned draft without wallet signing or clearing original latch/consent');
  await page.reload();await page.waitForFunction(()=>document.getElementById('payment-id').querySelector('a'));
  await page.locator('#connect-wallet').click();await page.locator('#wallet-list button').first().click();
  await page.waitForFunction(()=>!document.getElementById('reclaim').disabled);
  assert(await page.locator('#renew-reclaim').isHidden());
  check('Retained valid generation survives navigation without offering replacement');
  const firstGeneration=state.reclaimGeneration;
  state={...state,reclaimDraftState:'expired-or-unavailable',reclaimPreparation:true};
  await page.locator('#refresh').click();await page.waitForFunction(()=>document.getElementById('reclaim').disabled && !document.getElementById('renew-reclaim').hidden);
  assert((await page.locator('#reclaim-description').textContent()).includes('expired or unavailable'));
  assert.equal(await page.evaluate(()=>window.fixtureSigns||0),0);
  check('Expired unsigned generation disables signing and exposes explicit proof-gated preparation');
  await page.locator('#renew-reclaim').click();await page.waitForFunction(()=>!document.getElementById('reclaim').disabled);
  assert.notEqual(state.reclaimGeneration,firstGeneration);assert.equal(posts,2);assert.equal(await page.evaluate(()=>window.fixtureSigns||0),0);
  check('Explicit repeated preparation changes generation without wallet signing or dispatch');
  state={...state,reclaimDraftState:'stopped',reclaimPreparation:false};
  await page.evaluate(id=>localStorage.setItem('capture402-reclaim-wallet-attempt-'+id,localStorage.getItem('capture402-reclaim-renewed-'+id)),id);
  await page.locator('#refresh').click();await page.waitForFunction(()=>document.getElementById('reclaim').disabled && document.getElementById('action-status').textContent.includes('All new operations stopped'));
  assert(await page.locator('#renew-reclaim').isHidden());
  assert((await page.locator('#action-status').textContent()).includes('All new operations stopped'));
  check('New generation wallet attempt locks further signing while old generation remains preserved');
  state=expiredHeld;await page.evaluate(id=>{localStorage.setItem('capture402-reclaim-uncertain',id);localStorage.removeItem('capture402-reclaim-renewed-'+id);},id);
  await page.locator('#refresh').click();await page.waitForFunction(()=>document.getElementById('reclaim').disabled && document.getElementById('action-status').textContent.includes('All new operations stopped'));
  assert(await page.locator('#renew-reclaim').isHidden());
  assert((await page.locator('#action-status').textContent()).includes('All new operations stopped'));
  check('UNKNOWN distinct reclaim response cannot use expiry-consent UI renewal');
  await load(expiredHeld,true);await page.locator('#connect-wallet').click();await page.locator('#wallet-list button').first().click();
  await page.evaluate(()=>localStorage.setItem('capture402-uncertain',localStorage.getItem('capture402-order')));

  await page.evaluate(()=>localStorage.removeItem('capture402-reclaim-wallet-attempt')); // Controlled DOM fixture only.
  state={...expiredHeld,b3Recovery:{...recovery,payment:'stale'}};await page.locator('#refresh').click();await page.waitForFunction(()=>document.getElementById('reclaim').disabled);
  assert.equal(posts,0);check('Wrong legacy payment provenance keeps payer reclaim locked');
  await load({...held(),scenario:'atomic',actions:{...held().actions,beer:false,atomic:true},actionReasons:{atomic:''}});await unlock();
  assert(!(await page.locator('[data-action=atomic]').isDisabled()));assert(await page.locator('[data-action=atomic]').isVisible());
  await page.locator('[data-action=atomic]').click();await page.waitForFunction(()=>document.getElementById('payment-state').textContent.includes('Unknown'));
  assert.equal(posts,1);check('Atomic scenario exposes a single explicit action and UNKNOWN still blocks new actions');
  await load({...fullRefund,status:'closed',remaining:0,heldBaseUnits:'0'},true);await page.locator('#connect-wallet').click();await page.locator('#wallet-list button').first().click();
  assert(!(await page.locator('[data-scenario=cancelled]').isDisabled()));await page.locator('[data-scenario=cancelled]').click();await page.locator('#new-budget').click();
  await page.waitForFunction(()=>localStorage.getItem('capture402-order')==='b'.repeat(32));assert.equal(posts,1);
  check('Closed original hold permits explicit selection of the next scenario before a separately unsigned offer');
  await load({...draft(),authorizeAbandonEligible:true},true);
  await page.evaluate(id=>localStorage.setItem('capture402-wallet-attempt',id),id);
  await page.locator('#refresh').click();await page.waitForFunction(()=>!document.getElementById('abandon-authorize').hidden);
  assert(await page.locator('#authorize').isDisabled());assert(await page.locator('#new-budget').isHidden());
  await page.locator('#abandon-authorize').click();await page.waitForFunction(()=>document.getElementById('payment-state').textContent.includes('archived'));
  assert.equal(posts,1);assert.equal(await page.evaluate(()=>window.fixtureSigns||0),0);assert(await page.locator('#new-budget').isVisible());
  assert.equal(await page.evaluate(()=>localStorage.getItem('capture402-wallet-attempt')),id);
  check('Selected abandoned unfunded draft preserves old consent and enables only explicit separate offer, with no signing/dispatch');
  await load({...draft(),authorizeAbandonEligible:true},true);
  await page.evaluate(id=>localStorage.setItem('capture402-signed-'+id,'retained-signed-original'),id);
  await page.locator('#refresh').click();assert(await page.locator('#abandon-authorize').isHidden());assert.equal(posts,0);
  check('Retained signed authorization forbids the narrow abandonment control');
  await page.evaluate(id=>{localStorage.removeItem('capture402-signed-'+id);localStorage.setItem('capture402-uncertain',id);},id);
  await page.locator('#refresh').click();assert(await page.locator('#abandon-authorize').isHidden());assert.equal(posts,0);
  check('UNKNOWN authorization cannot enter unfunded abandonment');
  const isolatedSignature='3'.repeat(88),isolated={...draft(),status:'pending',refundDeadline:Math.floor(Date.now()/1000)-1,
    events:[{action:'authorize',status:'pending',signature:isolatedSignature,label:'Preserved UNKNOWN original',amount:100,at:new Date().toISOString()}],
    authorizeIsolation:{kind:'expired-no-successful-authorize-effect',originalOutcome:'unknown',originalSignature:isolatedSignature,reserveRetained:true,
      proof:{kind:'expired-no-successful-authorize-effect',payment:info.programId,unsignedSha256:'a'.repeat(64),originSlot:'1',expirySlot:'2',paymentSlot:'3',clockSlot:'4',clockUnixTimestamp:String(Math.floor(Date.now()/1000))}}};
  await load(isolated,true);await page.locator('#connect-wallet').click();await page.locator('#wallet-list button').first().click();
  await page.evaluate(id=>{localStorage.setItem('capture402-uncertain',id);localStorage.setItem('capture402-wallet-attempt',id);localStorage.setItem('capture402-signed-'+id,'preserved-signed-original');},id);
  await page.locator('#refresh').click();await page.waitForFunction(()=>document.getElementById('payment-state').textContent.includes('new order available'));
  assert(await page.locator('#authorize').isDisabled());assert(await page.locator('[data-action=beer]').isDisabled());assert(await page.locator('#abandon-authorize').isHidden());
  await page.locator('#new-budget').waitFor({state:'visible'});assert.equal(posts,0);
  await page.locator('#new-budget').click();await page.waitForFunction(()=>localStorage.getItem('capture402-order')==='b'.repeat(32));
  assert.equal(posts,1);assert.equal(await page.evaluate(()=>window.fixtureSigns||0),0);
  const custody=await page.evaluate(id=>({latch:localStorage.getItem('capture402-uncertain'),attempt:localStorage.getItem('capture402-wallet-attempt'),signed:localStorage.getItem('capture402-signed-'+id),archive:JSON.parse(localStorage.getItem('capture402-isolation-archive-'+id))}),id);
  assert.equal(custody.latch,id);assert.equal(custody.attempt,id);assert.equal(custody.signed,'preserved-signed-original');assert.equal(custody.archive.evidence.originalOutcome,'unknown');assert.equal(custody.archive.evidence.reserveRetained,true);
  check('Selected expired signed UNKNOWN permits one explicit unsigned successor while preserving original latch, signed bytes and reserve evidence');
  await load({...isolated,authorizeIsolation:{...isolated.authorizeIsolation,reserveRetained:false}});
  assert(await page.locator('#new-budget').isHidden());assert.equal(posts,0);check('Incomplete isolation evidence never exposes a successor');
  await load(isolated);rpcFailure=true;await page.locator('#refresh').click();await page.waitForFunction(()=>document.getElementById('payment-state').textContent.includes('RPC unavailable'));
  assert(await page.locator('#new-budget').isHidden());assert.equal(posts,0);check('Stale RPC state hides the isolated successor and shows paused status');
  // Exercise actual app.js orchestration through both preflights. The wallet module
  // and HTTP backend are explicit non-economic stubs; no real signature is created.
  const flow=await context.newPage(),sequence=[];
  const flowUnsigned='unsigned-flow-fixture-never-signed';
  const flowHash=createHash('sha256').update(flowUnsigned).digest('hex');
  let flowState={...expiredHeld,reclaimGeneration:flowHash,reclaimDraftState:'ready',reclaimPreparation:false};
  await flow.route('**/wallet.js',route=>route.fulfill({contentType:'text/javascript',body:`
    const wallet={name:'Flow fixture wallet; no cryptography'};
    export const wallets=()=>[wallet];export const onWallets=()=>()=>{};
    export const connect=async()=>({wallet,account:{address:${JSON.stringify(info.merchant)}}});
    export const walletSign=async()=>{window.fixtureSigns=(window.fixtureSigns||0)+1;return 'signed-flow-stub-not-a-transaction';};
    export const walletSignMerchantDemo=async()=>{throw new Error('Merchant demo is disabled in this fixture');};
    export const walletSignFaucetRequest=async()=>{throw new Error('Faucet is disabled in the reclaim fixture');};
    export const encodeEnvelope=x=>btoa(JSON.stringify(x));export const decodeEnvelope=x=>JSON.parse(atob(x));
    export const signingReport=()=>undefined;export const assertDevnetPolicy=()=>{};
  `}));
  await flow.route('**/api/orders**',async route=>{
    const req=route.request(),u=new URL(req.url());
    if(u.pathname.endsWith('/signing-preflight')) {
      const dispatch=u.searchParams.get('phase')==='dispatch';sequence.push(dispatch?'dispatch-preflight':'consent-preflight');
      assert.equal(dispatch,sequence.includes('consent'));
      return route.fulfill({contentType:'application/json',body:JSON.stringify({id,operation:'reclaim',phase:dispatch?'dispatch':'consent',fresh:!dispatch,unsignedSha256:flowHash})});
    }
    if(u.pathname.endsWith('/wallet-consent')) {sequence.push('consent');assert.equal(req.postDataJSON().unsignedSha256,flowHash);return route.fulfill({contentType:'application/json',body:'{"reserved":true}'});}
    if(u.pathname.endsWith('/reclaim') && req.method()==='GET')return route.fulfill({contentType:'application/json',body:JSON.stringify({unsigned:flowUnsigned,payer:info.merchant})});
    if(u.pathname.endsWith('/reclaim') && req.method()==='POST') {
      sequence.push('dispatch');assert.equal(req.postDataJSON().transaction,'signed-flow-stub-not-a-transaction');
      flowState={...flowState,status:'closed',remaining:0,heldBaseUnits:'0',reclaimDraftState:'stopped',b3Recovery:{...recovery,continued:true},events:[...flowState.events,{action:'reclaim',status:'finalized',amount:100,at:new Date().toISOString(),label:'Fixture reclaimed',signature:'flow-receipt-not-onchain',chainStatus:{kind:'found',commitment:'finalized',err:null}}]};
      return route.fulfill({contentType:'application/json',body:JSON.stringify({receipt:{success:true,transaction:'flow-receipt-not-onchain'}})});
    }
    return route.fulfill({contentType:'application/json',body:JSON.stringify(flowState)});
  });
  await flow.goto(origin+'/customer');await flow.evaluate(id=>{localStorage.clear();localStorage.setItem('capture402-order',id);localStorage.setItem('capture402-uncertain',id);},id);
  await flow.reload();await flow.waitForFunction(()=>document.getElementById('payment-id').querySelector('a'));
  await flow.locator('#connect-wallet').click();await flow.locator('#wallet-list button').first().click();await flow.locator('#reclaim').click();
  await flow.waitForFunction(()=>document.getElementById('action-status').textContent.includes('Payer reclaim finalized'));
  assert.deepEqual(sequence,['consent-preflight','consent','dispatch-preflight','dispatch']);assert.equal(await flow.evaluate(()=>window.fixtureSigns),1);
  assert.equal(await flow.evaluate(()=>localStorage.getItem('capture402-uncertain')),id);assert.equal(await flow.evaluate(()=>localStorage.getItem('capture402-reclaim-uncertain')),null);
  assert(await flow.locator('#new-budget').isVisible());
  check('Actual UI sequence separates consent and post-sign dispatch preflight, dispatches once and retains historical capture evidence');
  await flow.close();
  // Separate DOM fixture: no actual wallet, signature, network or token transfer.
  const faucetContext=await browser.newContext({ignoreHTTPSErrors:true}),faucetPage=await faucetContext.newPage();
  let faucetPosts=0,faucetReads=0,faucetFinal=false;
  const faucetId='d'.repeat(64),faucetSignature='1'.repeat(64);
  const faucetResult=()=>({id:faucetId,recipient:info.merchant,amount:1000,mint:info.mint,status:faucetFinal?'finalized':'unknown',signature:faucetSignature,finalizedSlot:faucetFinal?'10':null});
  await faucetPage.route('**/wallet.js',route=>route.fulfill({contentType:'text/javascript',body:`
    const wallet={name:'Faucet DOM fixture; no cryptography'};
    export const wallets=()=>[wallet];export const onWallets=()=>()=>{};
    export const connect=async()=>({wallet,account:{address:${JSON.stringify(info.merchant)}}});
    export const walletSign=async()=>{throw new Error('No transaction signing in faucet DOM fixture');};
    export const walletSignMerchantDemo=async()=>{throw new Error('Merchant demo is disabled in this fixture');};
    export const walletSignFaucetRequest=async()=>{window.fixtureMessages=(window.fixtureMessages||0)+1;return 'unsigned-DOM-fixture-not-a-signature';};
    export const encodeEnvelope=x=>btoa(JSON.stringify(x));export const decodeEnvelope=x=>JSON.parse(atob(x));
    export const signingReport=()=>undefined;export const assertDevnetPolicy=()=>{};
  `}));
  await faucetPage.route('**/api/config',route=>route.fulfill({contentType:'application/json',body:JSON.stringify({...info,faucetEnabled:true})}));
  await faucetPage.route('**/api/faucet/**',route=>{
    const req=route.request(),path=new URL(req.url()).pathname;
    if(path.endsWith('/challenge'))return route.fulfill({contentType:'application/json',body:JSON.stringify({id:faucetId,recipient:info.merchant})});
    if(path.endsWith('/claim')){faucetPosts++;return route.abort();}
    faucetReads++;return route.fulfill({contentType:'application/json',body:JSON.stringify(faucetResult())});
  });
  await faucetPage.goto(origin+'/customer');await faucetPage.waitForSelector('#faucet-panel',{state:'visible'});
  assert(await faucetPage.locator('#claim-test-tokens').isDisabled());
  await faucetPage.locator('#connect-wallet').click();await faucetPage.locator('#wallet-list button').first().click();
  await faucetPage.locator('#claim-test-tokens').click();
  await faucetPage.waitForFunction(()=>localStorage.getItem('capture402-faucet-original') && !document.getElementById('refresh-test-tokens').hidden);
  assert.equal(faucetPosts,1);assert(await faucetPage.locator('#claim-test-tokens').isDisabled());assert(await faucetPage.locator('#authorize').isDisabled());
  await faucetPage.reload();await faucetPage.waitForFunction(()=>document.getElementById('faucet-status').textContent.includes('UNKNOWN'));
  assert.equal(faucetPosts,1);assert(faucetReads>=1);assert(await faucetPage.locator('#claim-test-tokens').isDisabled());
  faucetFinal=true;await faucetPage.locator('#refresh-test-tokens').click();
  await faucetPage.waitForFunction(()=>document.getElementById('faucet-status').textContent.includes('delivered'));
  assert.equal(await faucetPage.evaluate(()=>localStorage.getItem('capture402-faucet-original')),null);
  assert.equal(faucetPosts,1);assert(await faucetPage.locator('#faucet-receipt').isVisible());
  assert.equal(await faucetPage.locator('#faucet-receipt').getAttribute('href'),`https://explorer.solana.com/tx/${faucetSignature}?cluster=devnet`);
  check('Faucet DOM: message request, lost response/reload stop, read-only original observation and finalized receipt without a second POST');
  await faucetContext.close();
  // Public demo orchestration only: synthetic readable consent, no cryptography.
  const demoContext=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:390,height:844}}),demoPage=await demoContext.newPage();
  let demoPosts=0,demoMessages=0,demoChallenge=0,demoHeader='';const demoState=held();
  demoPage.on('pageerror',error=>errors.push(error.message));
  await demoPage.addInitScript(id=>localStorage.setItem('capture402-order',id),id);
  await demoPage.route('**/api/config',r=>r.fulfill({contentType:'application/json',body:JSON.stringify({...info,publicMerchantDemoEnabled:true})}));
  await demoPage.route('**/wallet.js',r=>r.fulfill({contentType:'text/javascript',body:`
    const wallet={name:'Public demo fixture wallet; no cryptography'};
    export const wallets=()=>[wallet];export const onWallets=()=>()=>{};
    export const connect=async()=>({wallet,account:{address:${JSON.stringify(info.merchant)}}});
    export const walletSign=async()=>{throw Error('Transaction signing disabled in fixture');};
    export const walletSignMerchantDemo=async()=>{window.demoMessages=(window.demoMessages||0)+1;return 'synthetic-message-proof';};
    export const walletSignFaucetRequest=async()=>{throw Error('Faucet disabled');};
    export const encodeEnvelope=x=>btoa(JSON.stringify(x));export const decodeEnvelope=x=>JSON.parse(atob(x));
    export const signingReport=()=>undefined;export const assertDevnetPolicy=()=>{};
  `}));
  await demoPage.route('**/api/orders**',r=>{
    const req=r.request(),path=new URL(req.url()).pathname;
    if(path.endsWith('/merchant-demo')){demoChallenge++;assert.equal(req.method(),'POST');return r.fulfill({contentType:'application/json',body:JSON.stringify({token:'synthetic-order-challenge',expiresAt:demoState.refundDeadline})});}
    if(path.includes('/actions/')){
      assert(req.headers().authorization.startsWith('Demo '));demoHeader=req.headers().authorization;
      if(req.method()==='GET')return r.fulfill({contentType:'application/json',body:JSON.stringify({...demoState,operatorAccess:true})});
      demoPosts++;return r.abort();
    }
    return r.fulfill({contentType:'application/json',body:JSON.stringify(demoState)});
  });
  await demoPage.goto(origin+'/customer');await demoPage.waitForSelector('#enable-demo-controls',{state:'visible'});
  assert(await demoPage.locator('#operator-credentials').isHidden());assert(await demoPage.locator('#enable-demo-controls').isDisabled());
  await demoPage.locator('#connect-wallet').click();await demoPage.locator('#wallet-list button').first().click();
  await demoPage.locator('#enable-demo-controls').click();await demoPage.waitForFunction(()=>!document.querySelector('[data-action=beer]').disabled);
  demoMessages=await demoPage.evaluate(()=>window.demoMessages);assert.equal(demoMessages,1);assert.equal(demoChallenge,1);assert.equal(demoPosts,0);
  assert(!(await demoPage.content()).includes(demoHeader));assert(!(await demoPage.evaluate(()=>JSON.stringify({...localStorage}))).includes(demoHeader));
  assert.equal(await demoPage.evaluate(()=>document.documentElement.scrollWidth),390);
  await demoPage.reload();await demoPage.waitForFunction(()=>document.querySelector('[data-action=beer]').disabled);assert(await demoPage.locator('#operator-credentials').isHidden());
  await demoPage.locator('#connect-wallet').click();await demoPage.locator('#wallet-list button').first().click();
  await demoPage.locator('#enable-demo-controls').click();await demoPage.waitForFunction(()=>!document.querySelector('[data-action=beer]').disabled);
  await demoPage.locator('[data-action=beer]').click();await demoPage.waitForFunction(()=>document.getElementById('payment-state').textContent.includes('Unknown'));
  assert.equal(demoPosts,1);assert(await demoPage.locator('#enable-demo-controls').isDisabled());
  await demoPage.reload();await demoPage.waitForFunction(()=>document.getElementById('payment-state').textContent.includes('Unknown'));assert.equal(demoPosts,1);assert(await demoPage.locator('#enable-demo-controls').isDisabled());
  check('Public demo DOM: explicit message/preflight, memory-only grant, reload clears access, mobile layout and UNKNOWN survive reload without another POST');
  await demoContext.close();
  assert.equal(errors.length,0,errors.join('\n'));
  check('No browser page errors or external runtime requests');
  writeFileSync(join(output,'restaurant-browser-report.json'),JSON.stringify(report,null,2));
  console.log(JSON.stringify({checks:report.checks.length,viewports:report.viewports,browser:report.browser,output,scope:report.scope}));
} finally { if(browser) await browser.close(); await new Promise(resolve=>server.close(resolve)); rmSync(temp,{recursive:true,force:true}); }
