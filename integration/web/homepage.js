// Local illustration only. No wallet, network, storage, timers or payment operations.
(() => {
  const root = document.getElementById('c402-home-root');
  if (!root) return;
  const buttons = [...root.querySelectorAll('[data-step]')];
  const panels = [...root.querySelectorAll('[data-step-panel]')];
  const bar = root.querySelector('[data-model-bar]');
  const totals = [...root.querySelectorAll('[data-total]')];
  const previous = root.querySelector('[data-previous]');
  const next = root.querySelector('[data-next]');
  const refund = root.querySelector('[data-refund]');
  const disclosure = root.querySelector('[data-refund-disclosure]');
  const refundNote = root.querySelector('[data-refund-note]');
  const announcement = root.querySelector('[data-announcement]');
  if (buttons.length !== 4 || panels.length !== 4 || !bar || totals.length !== 3 ||
      !previous || !next || !refund || !disclosure || !refundNote || !announcement) return;
  const states = [
    { held: 100, captured: 0, released: 0 },
    { held: 70, captured: 30, released: 0 },
    { held: 0, captured: 50, released: 50 },
    { held: 0, captured: 50, released: 50 },
  ];
  let step = 0;
  let refundVisible = false;
  function select(target, showRefund = false, announce = true) {
    step = target;
    refundVisible = showRefund;
    const state = states[step];
    buttons.forEach((button, index) => button.setAttribute('aria-pressed', String(index === step)));
    panels.forEach((panel, index) => { panel.hidden = index !== step; });
    bar.className = `c402-home-bar c402-home-state-${step}`;
    totals.forEach(total => { total.textContent = String(state[total.dataset.total]); });
    previous.disabled = step === 0;
    next.textContent = step === 3 ? 'Start again' : 'Next step';
    refundNote.hidden = !showRefund;
    refund.textContent = showRefund ? 'Back to the closed hold' : 'Show a 15-unit refund';
    if (announce) announcement.textContent = `Step ${step + 1}. Held ${state.held}, captured ${state.captured}, unused returned ${state.released}.${showRefund ? ' Refunded 15. Merchant net 35. Hold stays closed.' : ''}`;
  }
  buttons.forEach((button, index) => button.addEventListener('click', () => select(index)));
  previous.addEventListener('click', () => select(Math.max(0, step - 1)));
  next.addEventListener('click', () => select(step === 3 ? 0 : step + 1));
  refund.addEventListener('click', () => select(3, !refundVisible));
  disclosure.addEventListener('toggle', () => {
    if (!disclosure.open && refundVisible) select(3);
  });
  // Enhance only after all controls exist and listeners are installed.
  root.classList.add('c402-home-enhanced');
  select(0, false, false);
  root.querySelector('[data-step-controls]').hidden = false;
  root.querySelector('[data-traversal]').hidden = false;
  refund.hidden = false;
  const menu = root.querySelector('.c402-home-menu');
  menu?.addEventListener('keydown', event => {
    if (event.key === 'Escape' && menu.open) {
      menu.open = false;
      menu.querySelector('summary').focus();
    }
  });
  menu?.querySelectorAll('a').forEach(anchor => anchor.addEventListener('click', () => { menu.open = false; }));
})();
