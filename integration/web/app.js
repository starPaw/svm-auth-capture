import { wallets, onWallets, connect, walletSign, encodeEnvelope, decodeEnvelope, signingReport, assertDevnetPolicy } from './wallet.js';
import { definitiveReceipt, recoveryMatches } from './receipt-state.js';
const $ = id => document.getElementById(id);
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));
const explorer = (kind, value) => `https://explorer.solana.com/${kind}/${encodeURIComponent(value)}?cluster=devnet`;
const addressLink = value => `<a href="${explorer('address',value)}" target="_blank" rel="noopener noreferrer">${esc(value)} ↗</a>`;
const diagnosticOnly = new URLSearchParams(location.search).get('walletDiagnostic') === '1';
let config, order, scenario = 'normal', connection, busy = false, stale = false, reading = false;
let anchor = { clock: 0, at: Date.now() }, merchantSecret = '', accessId = '', credentialEpoch = 0, renderedClockStage = '';
const storedId = () => localStorage.getItem('capture402-order');
const uncertain = () => !!order && localStorage.getItem('capture402-uncertain') === order.id;
const recoveryAllowed = () => !!order && recoveryMatches(order.b3Recovery,order,localStorage.getItem('capture402-uncertain'));
const continued = () => recoveryAllowed() && order.b3Recovery.continued === true && order.remaining === 0 && localStorage.getItem('capture402-reclaim-uncertain') !== order.id;
const signedOffer = () => !!order && localStorage.getItem('capture402-wallet-attempt') === order.id;
const canReplace = () => !!order && !stale && (!uncertain() || continued()) && order.status !== 'pending' && order.remaining === 0 &&
  !(signedOffer() && order.status === 'draft') && (expiredDraft() || ['closed','rejected'].includes(order.status));
const setStatus = (message, error = false) => { $('action-status').hidden = !message; $('action-status').textContent = message; $('action-status').classList.toggle('connection-error', error); };
const safeOperatorTransport = () => { try { assertDevnetPolicy(config); return location.protocol === 'https:' && config.configured === true; } catch { return false; } };
const clockNow = () => anchor.clock + Math.floor((Date.now() - anchor.at) / 1000);
const clockStage = () => order ? `${clockNow() >= order.captureDeadline}:${clockNow() >= order.refundDeadline}` : 'no-offer';
const expiredDraft = () => order?.status === 'draft' && order.events.length === 0 && clockNow() >= order.captureDeadline;
function lockMerchant(message = 'Operator-only: separate merchant secret. Payer signing cannot unlock access.') {
  merchantSecret = ''; accessId = ''; credentialEpoch++; $('merchant-secret').value = '';
  $('operator-status').textContent = message;
}
// A memory-only secret must not survive a history/BFCache restoration or tab navigation.
for (const event of ['pagehide', 'beforeunload']) window.addEventListener(event, () => lockMerchant());
window.addEventListener('pageshow', event => { if (event.persisted) { lockMerchant(); stale = true; render(); } });
async function request(path, init = {}, allowed = []) {
  const target = new URL(path, location.origin);
  if (target.origin !== location.origin || !path.startsWith('/')) throw new Error('Same-origin request required.');
  const operator = !!init.headers?.Authorization;
  if (operator && !safeOperatorTransport()) throw new Error('Merchant operator access requires HTTPS on the configured Devnet demo.');
  // No redirects can carry an operator bearer to another endpoint or origin.
  let response;
  try { response = await fetch(path, { ...init, credentials: 'same-origin', redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(450_000) }); }
  catch { throw new Error('Response unavailable. Inspect original signatures; this operation will not be retried.'); }
  let data; try { data = await response.json(); } catch { throw new Error('Response unavailable. Inspect the original order; do not repeat a paid action.'); }
  if (operator && response.status === 401) { lockMerchant('Operator-only: missing or invalid merchant credential. Payer signing cannot unlock access.'); throw new Error('Operator-only: merchant credential refused.'); }
  if (!response.ok && !allowed.includes(response.status)) {
    // Never render provider/server error text from a credential-bearing request.
    if (operator) throw new Error(response.status === 503 ? 'Merchant operator access is unavailable; private configuration is required.' : 'Merchant action refused: finalized RPC evidence unavailable, order conflict or deadline expired. Refresh the original order.');
    throw new Error(data.error ?? data.receipt?.errorReason ?? `HTTP ${response.status}. Inspect the original order.`);
  }
  return { response, data };
}
function renderWallet() {
  const payer = connection?.account?.address;
  $('payer-key').textContent = payer ?? 'No wallet connected';
  $('wallet-label').textContent = connection ? connection.wallet.name : 'Your Solana wallet';
  $('connect-wallet').textContent = payer ? 'Change wallet' : 'Connect wallet';
  $('detail-payer').innerHTML = order?.payer ? addressLink(order.payer) : payer ? addressLink(payer) : 'Not connected';
}
function authorizeReason() {
  return busy ? 'One operation is already in flight.' : stale ? 'Fresh finalized RPC state unavailable; refresh the original order.' : !config?.configured ? 'Devnet backend provisioning required.' : uncertain() ? 'Original response unknown; inspect its signatures. No new signature or offer.' : !connection?.account ? 'Connect the payer wallet first.' : order && order.payer !== connection.account.address ? 'Connect the original payer wallet.' :
    order && order.status !== 'draft' ? 'Authorization submitted; original receipt below.' : expiredDraft() ? 'Unsigned offer expired. Explicitly prepare a new offer before signing.' : order?.balances?.payer && (order.balances.payer.amount === null || order.balances.payer.amount < 100) ? order.balances.payer.reason || 'Payer needs 100 test-mint tokens; operator funding required.' : '';
}
function refundReason() {
  const refundable = Number(order.refundableBaseUnits) / 1_000_000;
  const amount = order.scenario === 'normal' ? 10 : refundable;
  if (!Number.isFinite(refundable) || !Number.isFinite(amount) || amount <= 0 || refundable < amount) return 'Finalized refundable balance cannot cover the selected refund.';
  if (order.balances?.merchant?.amount === null || !Number.isFinite(order.balances?.merchant?.amount) || order.balances.merchant.amount < amount) return 'Merchant test-token balance cannot fund this refund.';
  return '';
}
function merchantReason(action) {
  const reason = diagnosticOnly ? 'Signing-only diagnostic disables merchant operations.' : !safeOperatorTransport() ? 'Merchant access requires HTTPS and configured Devnet.' : !order ? 'Original payer order required.' : busy ? 'One operation is already in flight.' : uncertain() ? 'Original response unknown; all new operations are locked.' : stale ? 'Fresh finalized RPC state unavailable; refresh the original order.' : accessId !== order.id || !merchantSecret ? 'Merchant operator access required.' :
    clockNow() >= (action === 'refund' ? order.refundDeadline : order.captureDeadline) ? 'Deadline reached on the informational timer; refresh Solana Clock eligibility.' : !order.actions?.[action] ? order.actionReasons?.[action] || 'Original finalized payment is not eligible for this action.' : '';
  return reason || (action === 'refund' ? refundReason() : '');
}
function render() {
  $('setup-notice').hidden = !!config?.configured; document.body.classList.toggle('has-order', !!order); document.body.classList.toggle('operator-locked', accessId !== order?.id || !merchantSecret);
  for (const key of ['authorized','captured','remaining','refunded']) $(key).textContent = (order?.[key] ?? 0).toLocaleString('en-US', { maximumFractionDigits: 6 });
  $('refundable').textContent = order?.refundableBaseUnits !== undefined ? (Number(order.refundableBaseUnits) / 1_000_000).toLocaleString('en-US', { maximumFractionDigits: 6 }) : '0';
  const state = order?.status ?? 'idle';
  $('payment-state').textContent = continued() ? 'Hold reclaimed · original refusal archived' : uncertain() ? 'Unknown response · locked' : stale ? 'RPC unavailable · paused' : ({ idle:'Awaiting authorization', draft:'Unsigned offer', active:'Finalized', closed:'Hold closed', pending:'Pending · inspect signatures', rejected:'Authorization refused' })[state] ?? state;
  $('payment-state').classList.toggle('live', !stale && !uncertain() && ['active','closed'].includes(state));
  $('released-copy').hidden = !(order?.released > 0); $('released-copy').textContent = order?.released > 0 ? `${order.released} test tokens released to payer` : 'No tokens released yet.';
  const reason = authorizeReason(); $('authorize').disabled = !!reason; $('authorize-reason').textContent = reason || 'Ready: sign the exact 100 test-token offer. Settlement must finalize.';
  $('authorize').textContent = diagnosticOnly ? 'Sign only · compare wallet response' : busy ? 'Waiting for original result…' : 'Authorize 100 test tokens';
  document.querySelectorAll('[data-action]').forEach(b => { const reason = merchantReason(b.dataset.action); b.disabled = !!reason; b.title = reason; document.querySelector(`[data-reason="${b.dataset.action}"]`).textContent = reason || 'Ready.'; });
  document.querySelector('[data-action=atomic]').closest('.step').hidden = (order?.scenario ?? scenario) !== 'atomic';
  document.querySelector('[data-action=refund]').textContent = (order?.scenario ?? scenario) === 'normal' ? 'Refund 10' : 'Merchant-funded refund';
  $('finish').textContent = `4 · Void ${scenario === 'refund' ? 60 : 35}`;
  $('unlock-merchant').disabled = busy || !safeOperatorTransport() || !order || uncertain() || stale;
  $('lock-merchant').hidden = !merchantSecret; $('merchant-secret').disabled = busy || !!merchantSecret;
  if (!safeOperatorTransport()) $('operator-status').textContent = 'Operator-only controls require HTTPS on the configured Devnet demo.';
  $('reclaim-box').hidden = !order || order.remaining <= 0;
  const payerMatches = order?.payer === connection?.account?.address;
  $('reclaim').disabled = diagnosticOnly || busy || stale || uncertain() && !recoveryAllowed() || localStorage.getItem('capture402-reclaim-uncertain') === order?.id || !payerMatches || !order?.actions?.reclaim;
  $('reclaim').textContent = recoveryAllowed() ? 'Resume payer reclaim · preserve original refusal evidence' : 'Reclaim remaining hold';
  $('reclaim-description').textContent = recoveryAllowed() ? 'Reviewed source-bound pre-dispatch evidence; fresh payer consent reclaims the expired hold. Original latch remains archived; this is a new operation.' : uncertain() ? 'Original response unknown; inspect its signatures.' : stale ? 'Fresh finalized RPC state unavailable.' : !payerMatches ? 'Connect the original payer wallet to reclaim.' : order?.actionReasons?.reclaim || 'Ready for payer-direct reclaim; the facilitator is not used.';
  document.querySelectorAll('[data-scenario]').forEach(b => { b.classList.toggle('selected', b.dataset.scenario === scenario); b.disabled = busy || !!order && !canReplace(); });
  $('new-budget').hidden = !order || stale || uncertain() && !continued() || busy || order.status === 'pending' || order.remaining > 0 || signedOffer() && order.status === 'draft' || !(expiredDraft() || ['closed','rejected'].includes(order.status));
  $('new-budget').textContent = expiredDraft() ? 'Replace expired unsigned offer explicitly' : 'Prepare a new offer explicitly';
  const balanceText = (role, fallback) => { const b = order?.balances?.[role]; return b ? `${role === 'payer' ? 'Payer' : 'Merchant'} test-mint balance: ${b.amount === null ? 'unavailable' : b.amount} ${b.reason}` : fallback; };
  $('payer-balance').textContent = balanceText('payer', 'Test-mint funding checked before an offer is prepared.');
  $('merchant-balance').textContent = balanceText('merchant', 'Merchant test-mint balance awaits an original order.');
  $('program-id').innerHTML = config ? addressLink(config.programId) : 'Loading accepted deployment…';
  $('mint-id').innerHTML = config?.mint ? `${addressLink(config.mint)} · six-decimal classic SPL test mint` : 'Awaiting test-mint provisioning';
  $('payment-id').innerHTML = order ? addressLink(order.payment) : 'No original offer';
  $('state-pair').textContent = order?.heldBaseUnits !== undefined ? `H=${order.heldBaseUnits} · F=${order.refundableBaseUnits} base units (finalized)` : 'No finalized payment account yet.';
  $('deadline-terms').textContent = order ? `Capture: ${new Date(order.captureDeadline * 1000).toISOString()}. Refund: ${new Date(order.refundDeadline * 1000).toISOString()}. Immutable original terms; eligibility uses Solana Clock.` : '150 seconds from offer generation; refund deadline 30 seconds later. UI timer is informational.';
  if (order?.events?.length) $('timeline').innerHTML = order.events.map(e => `<div class="timeline-event"><span>${e.status === 'finalized' ? '✓' : '◷'}</span><div><strong>${esc(e.label)} · ${esc(e.amount)} test tokens</strong><div class="event-meta"><small>${esc(new Date(e.at).toLocaleTimeString())}</small><span>${esc(e.status)}${e.chainStatus?.commitment ? ` · ${esc(e.chainStatus.commitment)}` : ''}</span></div></div>${e.signature ? `<a href="${explorer('tx', e.signature)}" target="_blank" rel="noopener noreferrer">Explorer receipt ↗</a>` : '<small>No submitted signature</small>'}</div>`).join('');
  else $('timeline').innerHTML = '<p>No transactions yet. Only original transaction signatures link to Devnet Explorer.</p>';
  renderedClockStage = clockStage(); renderWallet(); renderClock();
}
function renderClock() {
  if (!order) { $('clock').textContent = '02:30'; $('clock-label').textContent = '150 seconds from offer generation; no offer yet.'; return; }
  const seconds = Math.max(0, order.captureDeadline - clockNow());
  $('clock').textContent = `${String(Math.floor(seconds/60)).padStart(2,'0')}:${String(seconds%60).padStart(2,'0')}`;
  $('clock-label').textContent = stale ? 'Last observed Clock; RPC unavailable. Eligibility paused.' : seconds > 0 ? 'Offer deadline; eligibility uses Solana Clock.' : 'Capture window closed. Funded or pending deadlines never reset.';
}
async function refresh() {
  const id = storedId(); if (!id || !config?.configured) return;
  if (!/^[a-f0-9]{32}$/.test(id)) throw new Error('Original order ID invalid. Inspect the original order.');
  const { data } = await request(`/api/orders/${encodeURIComponent(id)}`);
  if (storedId() !== id || data.id !== id) throw new Error('Original order changed; inspect its state.');
  const selectedNext = order?.id === data.id && canReplace() ? scenario : data.scenario;
  stale = false; order = data; scenario = selectedNext; anchor = { clock: data.now, at: Date.now() }; render();
}
async function run(fn) {
  if (busy || reading) return; busy = true; render(); setStatus('Waiting for the original result. No automatic retry.');
  try { await fn(); await refresh(); setStatus(uncertain() || order?.status === 'pending' ? 'Original operation pending or unknown. All new operations stopped; inspect original signatures.' : 'Original state refreshed. Only finalized receipts confirm settlement.'); }
  catch (error) { setStatus(error.message + (diagnosticOnly && signingReport() ? '\n\n' + JSON.stringify(signingReport(),null,2) : ''), true); try { await refresh(); } catch { stale = true; accessId = ''; } }
  finally { busy = false; render(); }
}
async function operatorPreflight(action, candidate = merchantSecret) {
  if (!candidate || candidate.length < 32 || candidate.length > 512 || candidate.trim() !== candidate || /[\r\n]/.test(candidate)) throw new Error('Operator-only: enter a valid separate merchant credential. Payer signing cannot unlock access.');
  if (!order || uncertain()) throw new Error('Original order required and unknown responses must remain locked.');
  const id = order.id, epoch = credentialEpoch;
  const { data } = await request(`/api/orders/${id}/actions/${action}`, { headers: { Authorization: `Bearer ${candidate}` } });
  if (epoch !== credentialEpoch || order.id !== id || data.id !== id || data.operatorAccess !== true) throw new Error('Operator access changed. Unlock the original order explicitly.');
  // Only consume sanitized state fields; the credential is never rendered or persisted.
  order = { ...order, ...data }; anchor = { clock: data.now, at: Date.now() }; stale = false; accessId = id;
}
async function submitOriginal(path, init, allowed = []) {
  const originalId = order.id;
  const wireHash = async value => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value))),b=>b.toString(16).padStart(2,'0')).join('');
  localStorage.setItem(`capture402-request-${originalId}`,JSON.stringify({order:originalId,path,method:init.method,
    bodySha256:await wireHash(init.body ?? init.headers?.['PAYMENT-SIGNATURE'] ?? ''),at:new Date().toISOString()}));
  localStorage.setItem('capture402-uncertain', order.id); // Non-secret lost-response lock survives reload.
  const result = await request(path, init, allowed);
  if (order.id !== originalId || localStorage.getItem('capture402-uncertain') !== originalId) return result;
  const receipt = result.data.receipt, encoded = result.response.headers.get('PAYMENT-RESPONSE');
  let header; try { header = encoded ? decodeEnvelope(encoded) : undefined; } catch { /* Keep UNKNOWN. */ }
  if (definitiveReceipt(receipt,header,config.network,order.payer)) localStorage.removeItem('capture402-uncertain');
  else if (receipt && header && JSON.stringify(receipt) === JSON.stringify(header) && receipt.network === config.network && receipt.payer === order.payer && typeof receipt.success === 'boolean' && typeof receipt.transaction === 'string' && receipt.transaction) {
    await refresh();
    const event = order.events.find(e=>e.signature === receipt.transaction);
    if (event?.chainStatus?.kind === 'found' && event.chainStatus.commitment === 'finalized' &&
      (receipt.success === true && event.status === 'finalized' && event.chainStatus.err === null || receipt.success === false && event.status === 'rejected' && event.chainStatus.err !== null)) localStorage.removeItem('capture402-uncertain');
  }
  return result;
}
async function signingPreflight(unsigned, operation) {
  const {data} = await request(`/api/orders/${order.id}/signing-preflight?operation=${operation}`);
  const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(unsigned))),b=>b.toString(16).padStart(2,'0')).join('');
  if (data.id !== order.id || data.operation !== operation || data.fresh !== true || data.unsignedSha256 !== hash) throw new Error('Fresh original offer evidence differs; nothing signed.');
  return hash;
}
function showWallets() {
  const available = wallets(); $('wallet-help').hidden = !!available.length; $('wallet-list').replaceChildren();
  for (const wallet of available) {
    const button = document.createElement('button'); button.className = 'button secondary'; button.textContent = wallet.name;
    button.onclick = async () => {
      try { connection?.off?.(); connection = await connect(wallet, account => { if (connection) connection.account = account; render(); }, config); $('wallet-dialog').close(); render(); setStatus('Wallet connected; no payment submitted.'); }
      catch (error) { setStatus(error.message, true); $('wallet-dialog').close(); }
    }; $('wallet-list').append(button);
  }
}
onWallets(showWallets);
$('connect-wallet').onclick = () => { showWallets(); $('wallet-dialog').showModal(); };
$('close-wallet').onclick = () => $('wallet-dialog').close();
async function prepareOffer() {
  if (!connection?.account) throw new Error('Connect the payer wallet first.');
  const { response, data } = await request('/api/orders', { method:'POST', headers:{ 'Content-Type':'application/json' }, body:JSON.stringify({ payer:connection.account.address, scenario }) }, [402]);
  const header = response.headers.get('PAYMENT-REQUIRED');
  if (!header || !data.order || !data.unsigned) throw new Error(data.error || 'No real unsigned budget offer could be prepared.');
  const required = decodeEnvelope(header);
  lockMerchant(); localStorage.setItem('capture402-order', data.order); await refresh();
  return { required, unsigned:data.unsigned, id:data.order };
}
$('authorize').onclick = () => {
  if (authorizeReason()) return;
  return run(async () => {
    const draft = order?.status === 'draft' ? order : await prepareOffer();
    const { required, unsigned, id } = draft, offer = required.accepts[0];
    if (offer.amount !== '100000000' || offer.asset !== config.mint || offer.payTo !== config.merchant || offer.network !== config.network || offer.extra?.programId !== config.programId || offer.extra?.feePayer !== config.sponsor || offer.extra?.paymentFlow !== 'escrow') throw new Error('Offer differs from fixed policy. Nothing was signed.');
    if (expiredDraft()) throw new Error('Unsigned offer expired; explicitly replace it before signing.');
    const unsignedSha256 = await signingPreflight(unsigned,'authorize');
    if (signedOffer()) throw new Error('Original wallet consent already attempted; inspect its retained original before new signing.');
    await request(`/api/orders/${id}/wallet-consent`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({unsignedSha256})});
    localStorage.setItem('capture402-wallet-attempt',id);
    const signed = await walletSign(connection, unsigned, config);
    localStorage.setItem(`capture402-signed-${id}`,signed);
    if (diagnosticOnly) throw new Error('Signing-only diagnostic complete. Nothing was submitted.');
    if (expiredDraft()) throw new Error('Offer expired during wallet approval. Signed original retained; no replacement permitted without evidence.');
    await signingPreflight(unsigned,'authorize');
    const envelope = { x402Version:2, resource:required.resource, accepted:offer, payload:{ transaction:signed } };
    const { data } = await submitOriginal(`/resource?order=${id}`, { method:'POST', headers:{ 'PAYMENT-SIGNATURE':encodeEnvelope(envelope) } }, [402]);
    if (!data.receipt?.success) throw new Error(data.receipt?.errorReason ?? 'Authorization unresolved. Inspect this order.');
  });
};
$('unlock-merchant').onclick = () => run(async () => {
  const candidate = $('merchant-secret').value; $('merchant-secret').value = '';
  try { await operatorPreflight('beer', candidate); merchantSecret = candidate; $('operator-status').textContent = 'Devnet operator access verified. Explicit clicks only.'; }
  catch { lockMerchant('Operator-only: credential refused or finalized RPC evidence unavailable. Verify the separate merchant credential and refresh. Payer signing cannot unlock access.'); throw new Error('Merchant unlock failed; no economic request was sent.'); }
});
$('lock-merchant').onclick = () => { lockMerchant(); render(); };
for (const button of document.querySelectorAll('[data-action]')) button.onclick = () => {
  const action = button.dataset.action;
  if (merchantReason(action)) return;
  return run(async () => {
    await operatorPreflight(action);
    const reason = order.actionReasons?.[action] || (action === 'refund' ? refundReason() : '');
    if (!order.actions?.[action] || reason || clockNow() >= (action === 'refund' ? order.refundDeadline : order.captureDeadline)) throw new Error(reason || 'Original action eligibility changed; no operation sent.');
    const { data } = await submitOriginal(`/api/orders/${order.id}/actions/${action}`, { method:'POST', headers:{ Authorization:`Bearer ${merchantSecret}` } }, [409]);
    if (!data.receipt?.success) throw new Error('Merchant operation refused or pending. Inspect original signatures and finalized state.');
  });
};
$('reclaim').onclick = () => {
  if ($('reclaim').disabled) return;
  return run(async () => {
    const recovery = recoveryAllowed();
    if (recovery) localStorage.setItem(`capture402-recovery-archive-${order.id}`,JSON.stringify({originalLatch:localStorage.getItem('capture402-uncertain'),evidence:order.b3Recovery,acknowledgedAt:new Date().toISOString()}));
    const { data } = await request(`/api/orders/${order.id}/reclaim`);
    await signingPreflight(data.unsigned,'reclaim');
    const signed = await walletSign(connection, data.unsigned, config);
    localStorage.setItem(`capture402-reclaim-signed-${order.id}`,signed);
    await signingPreflight(data.unsigned,'reclaim');
    if (recovery) {
      localStorage.setItem('capture402-reclaim-uncertain',order.id);
      const {data:result} = await request(`/api/orders/${order.id}/reclaim`, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({transaction:signed})},[409]);
      await refresh();
      if (result.receipt?.success === true && order.events.some(e=>e.action === 'reclaim' && e.signature === result.receipt.transaction && e.status === 'finalized' && e.chainStatus?.commitment === 'finalized' && e.chainStatus.err === null)) localStorage.removeItem('capture402-reclaim-uncertain');
    } else await submitOriginal(`/api/orders/${order.id}/reclaim`, { method:'POST', headers:{ 'Content-Type':'application/json' }, body:JSON.stringify({ transaction:signed }) }, [409]);
  });
};
for (const button of document.querySelectorAll('[data-scenario]')) button.onclick = () => { if (!busy && (!order || canReplace())) { scenario = button.dataset.scenario; render(); } };
$('refresh').onclick = () => run(async () => {});
$('new-budget').onclick = () => { if (!$('new-budget').hidden) return run(async () => { await prepareOffer(); setStatus('Fresh unsigned offer prepared by explicit consent. Sign separately; old journals remain intact.'); }); };
setInterval(() => { if (!busy && clockStage() !== renderedClockStage) render(); else renderClock(); }, 1000);
setInterval(() => { if (!busy && !reading && order && config?.configured) { reading = true; refresh().catch(() => { stale = true; accessId = ''; render(); setStatus('Fresh finalized RPC state unavailable. Original actions paused.', true); }).finally(() => { reading = false; }); } }, 15000);
try { config = (await request('/api/config')).data; assertDevnetPolicy(config); render(); if (diagnosticOnly) setStatus('Signing-only diagnostic: no signed transaction is sent to the backend.'); await refresh(); } catch (error) { stale = true; render(); setStatus(error.message, true); }
