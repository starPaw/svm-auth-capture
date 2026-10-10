'use strict';
const byId = id => document.getElementById(id);
const merchant = location.pathname === '/merchant';
byId('merchant-label').hidden = !merchant;
fetch('/api/config').then(r => r.json()).then(c => { byId('scope').textContent = `Snapshot ${c.snapshotAt}; viewer ${c.viewerSha}. ${c.scope}`; }).catch(() => { byId('scope').textContent = 'Retained snapshot unavailable.'; });
byId('view').onclick = async () => {
  const id = byId('order').value;
  if (!/^[a-f0-9]{32}$/.test(id)) { byId('result').textContent = 'Enter the known order ID.'; return; }
  try {
    const r = await fetch(`/api/orders/${id}${merchant ? '/actions/beer' : ''}`, { credentials: 'same-origin', headers: merchant ? { Authorization: `Bearer ${byId('merchant').value}` } : {} });
    byId('merchant').value = '';
    byId('result').textContent = JSON.stringify(await r.json(), null, 2);
  } catch { byId('result').textContent = 'Retained snapshot unavailable.'; }
};
