import { wallets, onWallets, connect, walletSign, encodeEnvelope, decodeEnvelope, signingReport, assertDevnetPolicy } from './wallet.js';
const $ = id => document.getElementById(id);
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));
const explorer = (kind, value) => `https://explorer.solana.com/${kind}/${encodeURIComponent(value)}?cluster=devnet`;
const addressLink = value => `<a href="${explorer('address',value)}" target="_blank" rel="noopener noreferrer">${esc(value)} ↗</a>`;
const diagnosticOnly = new URLSearchParams(location.search).get('walletDiagnostic') === '1';
const merchantView = location.pathname === '/merchant';
let config, order, scenario = 'normal', connection, busy = false, stale = false, anchor = { clock: 0, at: Date.now() };
const storedId = () => localStorage.getItem('capture402-order');
const setStatus = (message, error = false) => { $('action-status').hidden = !message; $('action-status').textContent = message; $('action-status').classList.toggle('connection-error', error); };
async function request(path, init = {}, allowed = []) {
  const response = await fetch(path, { ...init, credentials: 'same-origin', signal: AbortSignal.timeout(450_000) });
  let data; try { data = await response.json(); } catch { throw new Error('Response unavailable. Inspect the original order; do not repeat a paid action.'); }
  if (!response.ok && !allowed.includes(response.status)) throw new Error(data.error ?? data.receipt?.errorReason ?? `HTTP ${response.status}. Inspect the original order.`);
  return { response, data };
}
function renderWallet() {
  const payer = connection?.account?.address;
  $('payer-key').textContent = payer ?? 'No wallet connected';
  $('wallet-label').textContent = connection ? connection.wallet.name : 'Your Solana wallet';
  $('connect-wallet').textContent = payer ? 'Change Wallet ↗' : 'Connect Wallet ↗';
  $('detail-payer').innerHTML = order?.payer ? addressLink(order.payer) : payer ? addressLink(payer) : 'Not connected';
}
function render() {
  $('setup-notice').hidden = !!config?.configured;
  $('customer-panel').hidden = merchantView; $('merchant-panel').hidden = !merchantView;
  $('view-eyebrow').textContent = merchantView ? 'THE SAME TABLE. THE SAME BUDGET.' : 'YOUR TABLE. YOUR BUDGET.';
  $('view-title').innerHTML = merchantView ? 'Serve with care.<br><em>Settle with precision.</em>' : 'A little less friction.<br><em>A little more Marina.</em>';
  $('card-eyebrow').textContent = merchantView ? 'MERCHANT SERVICE' : 'YOUR SEVEN-DAY PASS';
  document.querySelectorAll('[data-view]').forEach(a => a.classList.toggle('active', (a.dataset.view === 'merchant') === merchantView));
  for (const key of ['authorized','captured','remaining','refunded']) $(key).textContent = (order?.[key] ?? 0).toLocaleString('en-US', { maximumFractionDigits: 6 });
  const state = order?.status ?? 'idle';
  $('payment-state').textContent = ({ idle:'Awaiting authorization', draft:'Awaiting wallet signature', active:'Budget open', closed:order?.events?.at(-1)?.action === 'reclaim' ? 'Unused budget reclaimed' : order?.events?.at(-1)?.action === 'void' ? 'Order cancelled' : order?.refunded ? 'Closed · refund recorded' : 'Order finished', pending:'Pending · inspect original signatures', rejected:'Authorization refused' })[state] ?? state;
  $('payment-state').classList.toggle('live', state === 'active' || state === 'closed');
  $('released-copy').textContent = order?.released > 0 ? `${order.released} demo USDC released to payer` : 'ready for future meals';
  const payerMatches = !order || order.payer === connection?.account?.address;
  $('authorize').disabled = busy || stale || !config?.configured || !connection?.account || !payerMatches || order && !['draft','rejected'].includes(order.status);
  $('authorize').textContent = diagnosticOnly ? 'Sign only · compare wallet response ↗' : busy ? 'Waiting for the original result…' : 'Authorize 100 demo USDC ↗';
  document.querySelectorAll('[data-action]').forEach(b => { b.disabled = true; b.title = 'Only an authenticated restaurant operator can perform this action.'; });
  $('finish').textContent = `Finish Order · Release remaining ${scenario === 'refund' ? 60 : 35} ↗`;
  $('reclaim-box').hidden = !order || order.remaining <= 0;
  $('reclaim').disabled = diagnosticOnly || busy || stale || !connection?.account || !payerMatches || !order?.actions?.reclaim;
  $('reclaim-description').textContent = order?.actions?.reclaim ? 'The onchain capture deadline has passed. Sign a payer-direct reclaim; the facilitator is not used.' : 'Your remaining hold can be reclaimed at the onchain capture deadline, including when the merchant is unavailable.';
  document.querySelectorAll('[data-scenario]').forEach(b => { b.classList.toggle('selected', b.dataset.scenario === scenario); b.disabled = busy || !!order; });
  $('new-budget').hidden = !order || order.status === 'pending' || order.remaining > 0 || busy;
  $('program-id').innerHTML = config ? addressLink(config.programId) : 'Loading accepted deployment…';
  $('mint-id').innerHTML = config?.mint ? `${addressLink(config.mint)} · six-decimal classic SPL test mint; not real USDC` : 'Awaiting provisioning · classic SPL test token, not real USDC';
  $('payment-id').innerHTML = order ? addressLink(order.payment) : 'Not authorized yet';
  $('state-pair').textContent = order?.heldBaseUnits !== undefined ? `H=${order.heldBaseUnits} · F=${order.refundableBaseUnits} (base units; finalized RPC state)` : 'No payment account yet';
  for (const [action,id] of [['beer','beer-dish'],['salmon','salmon-dish']]) $(id).classList.toggle('served', !!order?.events?.some(e => e.action === action && e.status === 'finalized'));
  if (order?.events?.length) $('timeline').innerHTML = order.events.map(e => `<div class="timeline-event"><span class="event-icon">${e.status === 'finalized' ? '✓' : '◷'}</span><div><strong>${esc(e.label)} · ${esc(e.amount)} demo USDC</strong><div class="event-meta"><small>${esc(new Date(e.at).toLocaleTimeString([], { hour:'2-digit', minute:'2-digit', second:'2-digit' }))}</small><span>${esc(e.status)}${e.chainStatus?.commitment ? ` · ${esc(e.chainStatus.commitment)}` : ''}</span></div></div>${e.signature ? `<a href="${explorer('tx', e.signature)}" target="_blank" rel="noopener noreferrer" title="${esc(e.signature)}">View transaction ↗</a>` : '<small>No confirmed signature</small>'}</div>`).join('');
  else $('timeline').innerHTML = '<div class="empty-history"><span>↗</span><p>No transactions yet.<br><small>Finalized operations and their Devnet Explorer links will appear here.</small></p></div>';
  renderWallet(); renderClock();
}
function renderClock() {
  if (!order) { $('clock').textContent = '02:30'; $('clock-label').textContent = 'Starts after the budget offer is issued.'; return; }
  const now = anchor.clock + Math.floor((Date.now() - anchor.at) / 1000);
  const seconds = Math.max(0, order.captureDeadline - now);
  $('clock').textContent = `${String(Math.floor(seconds/60)).padStart(2,'0')}:${String(seconds%60).padStart(2,'0')}`;
  $('clock-label').textContent = seconds > 0 ? 'Demo-only clock. Actual eligibility follows Solana cluster time.' : 'Capture window closed. Reclaim requires a positive hold and fresh chain state.';
}
async function refresh() {
  const id = storedId(); if (!id || !config?.configured) return;
  const { data } = await request(`/api/orders/${encodeURIComponent(id)}`);
  stale = false; order = data; scenario = data.scenario; anchor = { clock: data.now, at: Date.now() }; render();
}
async function run(fn) {
  if (busy) return; busy = true; render(); setStatus('Awaiting your signature or finalized Devnet result. Do not repeat this action.');
  try { await fn(); await refresh(); setStatus(order?.status === 'pending' ? 'The original result is pending. All new merchant actions are stopped; inspect the signatures.' : 'State refreshed from the real Devnet runtime.'); }
  catch (error) { setStatus(error.message + (diagnosticOnly && signingReport() ? '\n\n' + JSON.stringify(signingReport(),null,2) : ''), true); try { await refresh(); } catch { stale = true; } }
  finally { busy = false; render(); }
}
function showWallets() {
  const available = wallets(); $('wallet-help').hidden = !!available.length;
  $('wallet-list').replaceChildren();
  for (const wallet of available) {
    const button = document.createElement('button'); button.className = 'button secondary'; button.textContent = `${wallet.name} ↗`;
    button.onclick = async () => {
      try { connection?.off?.(); connection = await connect(wallet, account => { if (connection) connection.account = account; render(); }, config); $('wallet-dialog').close(); render(); setStatus('Wallet connected. No authorization or payment has been submitted.'); }
      catch (error) { setStatus(error.message, true); $('wallet-dialog').close(); }
    };
    $('wallet-list').append(button);
  }
}
onWallets(showWallets);
$('connect-wallet').onclick = () => { showWallets(); $('wallet-dialog').showModal(); };
$('authorize').onclick = () => run(async () => {
  if (!connection?.account) throw new Error('Connect the payer wallet first.');
  let required, unsigned, id;
  const draftExpired = order?.status === 'draft' && order.events.length === 0 && anchor.clock + Math.floor((Date.now()-anchor.at)/1000) >= order.captureDeadline;
  // This explicit click creates new consent only for a never-submitted, expired draft.
  // Pending/submitted attempts are never refreshed, re-signed or retried.
  if (order?.status === 'draft' && !draftExpired) { ({ required, unsigned, id } = order); }
  else {
    const { response, data } = await request(`/resource?payer=${encodeURIComponent(connection.account.address)}&scenario=${scenario}`, {}, [402]);
    const header = response.headers.get('PAYMENT-REQUIRED'); if (!header) throw new Error('No real PAYMENT-REQUIRED offer was returned.');
    required = decodeEnvelope(header); unsigned = data.unsigned; id = data.order;
    if (!id || !unsigned) throw new Error('The budget offer could not be prepared.');
    localStorage.setItem('capture402-order', id); await refresh();
  }
  const offer = required.accepts[0];
  if (offer.amount !== '100000000' || offer.asset !== config.mint || offer.payTo !== config.merchant || offer.network !== config.network || offer.extra?.programId !== config.programId || offer.extra?.feePayer !== config.sponsor || offer.extra?.paymentFlow !== 'escrow') throw new Error('Offer differs from the fixed restaurant policy. Nothing was signed.');
  const signed = await walletSign(connection, unsigned, config);
  if (diagnosticOnly) throw new Error('Signing-only diagnostic complete. Nothing was submitted.');
  const envelope = { x402Version:2, resource:required.resource, accepted:offer, payload:{ transaction:signed } };
  const { data } = await request(`/resource?order=${id}`, { method:'POST', headers:{ 'PAYMENT-SIGNATURE':encodeEnvelope(envelope) } }, [402]);
  if (!data.receipt?.success) throw new Error(data.receipt?.errorReason ?? 'Authorization unresolved. Inspect this order.');
});
$('reclaim').onclick = () => run(async () => {
  if (connection?.account?.address !== order.payer) throw new Error('Connect the original payer wallet.');
  const { data } = await request(`/api/orders/${order.id}/reclaim`);
  const signed = await walletSign(connection, data.unsigned, config);
  await request(`/api/orders/${order.id}/reclaim`, { method:'POST', headers:{ 'Content-Type':'application/json' }, body:JSON.stringify({ transaction:signed }) });
});
for (const button of document.querySelectorAll('[data-scenario]')) button.onclick = () => { if (!order) { scenario = button.dataset.scenario; render(); } };
$('refresh').onclick = () => run(async () => {});
$('new-budget').onclick = () => { localStorage.removeItem('capture402-order'); order = undefined; scenario = 'normal'; render(); setStatus('Choose a scenario and explicitly authorize a new budget. Previous journals remain intact.'); };
setInterval(renderClock, 1000);
setInterval(() => { if (!busy && order && config?.configured) refresh().catch(() => { stale = true; render(); setStatus('Fresh chain state unavailable. Actions are paused; inspect the original order.', true); }); }, 15000);
try { config = (await request('/api/config')).data; assertDevnetPolicy(config); render(); if(diagnosticOnly) setStatus('Signing-only diagnostic: stops after comparison. No signed transaction is sent to the backend.'); await refresh(); } catch (error) { stale = true; render(); setStatus(error.message, true); }
