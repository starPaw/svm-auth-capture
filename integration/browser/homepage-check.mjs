// Browser QA against an ephemeral, unconfigured presentation fixture. No demo actions.
// Use an existing Playwright installation; no application dependency is added.
// HOMEPAGE_PLAYWRIGHT_MODULE=/absolute/path/to/playwright/index.mjs
// HOMEPAGE_QA_URL=http://127.0.0.1:18939 HOMEPAGE_QA_OUTPUT=/path/to/artifacts node homepage-check.mjs
import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
const { chromium } = await import(pathToFileURL(process.env.HOMEPAGE_PLAYWRIGHT_MODULE));
const url = process.env.HOMEPAGE_QA_URL;
assert.equal(new URL(url).hostname, '127.0.0.1', 'Use a loopback test fixture, never a live demo');
const output = process.env.HOMEPAGE_QA_OUTPUT;
await mkdir(output, { recursive: true });
const browser = await chromium.launch({ headless: true });
const report = { browser: browser.version(), fixture: url, viewports: [], states: [], errors: [], requests: [], checks: [], performance: {} };
const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
const page = await context.newPage();
page.on('pageerror', error => report.errors.push(error.message));
page.on('console', message => { if (message.type() === 'error') report.errors.push(message.text()); });
page.on('request', request => report.requests.push({ path: new URL(request.url()).pathname, method: request.method() }));
// A payment provider trap verifies that no code even touches wallet providers.
await page.addInitScript(() => {
  for (const name of ['solana', 'solflare', 'ethereum']) Object.defineProperty(window, name, { get() { throw new Error(`Wallet provider touched: ${name}`); } });
});
await page.goto(url, { waitUntil: 'networkidle' });
await page.screenshot({ path: join(output, 'desktop-opening.png') });
await page.screenshot({ path: join(output, 'desktop-full.png'), fullPage: true });
for (const [width, height] of [[320, 740], [390, 844], [768, 1024], [1024, 768], [1440, 900], [1920, 1080], [720, 450], [360, 225]]) {
  await page.setViewportSize({ width, height });
  const layout = await page.evaluate(() => ({ width: innerWidth, scrollWidth: document.documentElement.scrollWidth, pageHeight: document.documentElement.scrollHeight }));
  assert.equal(layout.scrollWidth, width, `${width}px must not scroll horizontally`);
  report.viewports.push({ width, height, ...layout, condition: width === 720 ? '200% reflow equivalent from 1440px' : width === 360 ? '400% reflow equivalent from 1440px' : 'specified viewport' });
  if (width === 390) {
    await page.screenshot({ path: join(output, 'mobile-opening.png') });
    await page.screenshot({ path: join(output, 'mobile-full.png'), fullPage: true });
  }
}
await page.setViewportSize({ width: 1440, height: 900 });
const expected = [[100, 0, 0], [70, 30, 0], [0, 50, 50], [0, 50, 50]];
const controls = page.locator('[data-step]');
async function assertState(index, refunded = false) {
  const totals = (await page.locator('[data-total]').allTextContents()).map(Number);
  assert.deepEqual(totals, expected[index]);
  assert.equal(totals.reduce((a, b) => a + b), 100);
  assert.equal(await page.locator('[data-step][aria-pressed=true]').getAttribute('data-step'), String(index));
  assert.equal(await page.locator('[data-refund-note]').isVisible(), refunded);
  assert.equal(await page.locator('[data-previous]').isDisabled(), index === 0);
  report.states.push({ step: index + 1, held: totals[0], grossCaptured: totals[1], releasedUnused: totals[2], refunded: refunded ? 15 : 0, merchantNet: totals[1] - (refunded ? 15 : 0) });
}
await assertState(0);
for (let index = 1; index < 4; index++) { await page.locator('[data-next]').click(); await assertState(index); }
assert.equal(await page.locator('[data-next]').innerText(), 'Start again');
await page.locator('[data-next]').click(); await assertState(0);
await controls.nth(1).focus(); await page.keyboard.press('Space'); await assertState(1);
await controls.nth(2).focus(); await page.keyboard.press('Enter'); await assertState(2);
await page.locator('[data-previous]').click(); await assertState(1);
for (const index of [3, 0, 2, 1, 3]) { await controls.nth(index).click({ delay: 0 }); await assertState(index); }
await controls.nth(0).click();
await page.locator('[data-refund-disclosure] summary').click();
await page.locator('[data-refund]').click(); await assertState(3, true);
assert.match(await page.locator('[data-refund-note]').innerText(), /Refunded 15 · Merchant net 35/);
await page.waitForFunction(() => {
  const bar = document.querySelector('[data-model-bar]');
  const release = bar.querySelector('.c402-home-released');
  return Math.abs(release.getBoundingClientRect().width / bar.getBoundingClientRect().width - .5) < .001 && getComputedStyle(document.querySelector('[data-step-panel="3"]')).opacity === '1';
});
await page.screenshot({ path: join(output, 'refund-state.png') });
await page.locator('[data-refund-disclosure] summary').click();
await page.waitForFunction(() => document.querySelector('[data-refund-note]').hidden);
await assertState(3);
await page.emulateMedia({ reducedMotion: 'reduce' });
assert.equal(await page.locator('[data-model-bar] .c402-home-first').evaluate(e => getComputedStyle(e).transitionDuration), '0s');
await controls.nth(0).click(); await assertState(0);
await page.setViewportSize({ width: 390, height: 844 });
const menu = page.locator('.c402-home-menu');
await menu.locator('summary').focus(); await page.keyboard.press('Enter');
assert.equal(await menu.evaluate(e => e.open), true);
await page.keyboard.press('Escape');
assert.equal(await menu.evaluate(e => e.open), false);
assert.equal(await menu.locator('summary').evaluate(e => e === document.activeElement), true);
await page.reload({ waitUntil: 'networkidle' });
await page.keyboard.press('Tab');
assert.equal(await page.evaluate(() => document.activeElement.textContent), 'Skip to content');
await page.keyboard.press('Enter');
assert.equal(await page.evaluate(() => document.activeElement.id), 'content');
await page.locator('#proof details summary').click();
assert.equal(await page.locator('#proof details').evaluate(e => e.scrollWidth <= e.clientWidth + 1), true);
assert.equal(await page.locator('#proof').evaluate(e => e.querySelectorAll('tbody tr').length), 4);
const outline = await page.locator('#c402-home-root').ariaSnapshot();
await writeFile(join(output, 'accessibility-tree.txt'), outline);
assert.match(outline, /heading "Authorize once\. Capture as you go\." \[level=1\]/);
report.checks.push('Keyboard native buttons, traversal, menu Escape, skip link; semantic accessibility snapshot retained (not a screen-reader session)');
report.checks.push('Four numeric states, rapid selection, Start again, separate refund, disclosure close, constant ceiling and no refund budget restoration');
report.checks.push('Reduced motion has zero-duration transitions; evidence details wrap at 390px');
// Check final rendered text contrast against its nearest opaque ancestor surface.
report.contrast = await page.evaluate(() => {
  function rgb(value) { return value.match(/[\d.]+/g).map(Number).slice(0, 3); }
  function luminance(color) { const c = color.map(v => { const n = v / 255; return n <= .04045 ? n / 12.92 : ((n + .055) / 1.055) ** 2.4; }); return c[0] * .2126 + c[1] * .7152 + c[2] * .0722; }
  const failures = []; let checked = 0; let minimum = 100;
  for (const element of document.querySelectorAll('#c402-home-root *')) {
    if (!element.getClientRects().length || element.closest('[aria-hidden=true]') || element.closest('.c402-home-sr') || element.matches(':disabled') || ![...element.childNodes].some(n => n.nodeType === 3 && n.textContent.trim())) continue;
    const style = getComputedStyle(element);
    if (style.visibility === 'hidden') continue;
    let ancestor = element; let background = 'rgba(0,0,0,0)';
    while (ancestor) { background = getComputedStyle(ancestor).backgroundColor; if (background !== 'rgba(0, 0, 0, 0)' && background !== 'transparent') break; ancestor = ancestor.parentElement; }
    const a = luminance(rgb(style.color)); const b = luminance(rgb(background)); const ratio = (Math.max(a,b) + .05) / (Math.min(a,b) + .05);
    const large = parseFloat(style.fontSize) >= 24 || (parseFloat(style.fontSize) >= 18.66 && Number(style.fontWeight) >= 700);
    checked++; minimum = Math.min(minimum, ratio);
    if (ratio < (large ? 3 : 4.5)) failures.push({ text: element.textContent.slice(0,80), color: style.color, background, ratio });
  }
  return { checked, minimum, failures };
});
assert.deepEqual(report.contrast.failures, []);
report.targetSizes = await page.locator('a,button,summary').evaluateAll(elements => elements.filter(e => e.getClientRects().length && !e.closest('.c402-home-skip')).map(e => ({ text: e.textContent.trim(), height: e.getBoundingClientRect().height, width: e.getBoundingClientRect().width })).filter(e => e.height < 44 || e.width < 44));
assert.deepEqual(report.targetSizes, []);
report.checks.push('Rendered text contrast >= AA thresholds; visible interactive targets at least 44x44px');

const fallbackContext = await browser.newContext({ javaScriptEnabled: false, viewport: { width: 390, height: 844 } });
const fallback = await fallbackContext.newPage();
const fallbackRequests = [];
fallback.on('request', r => fallbackRequests.push({ path: new URL(r.url()).pathname, method: r.method() }));
await fallback.goto(url);
for (let index = 0; index < 4; index++) assert.equal(await fallback.locator(`[data-step-panel="${index}"]`).isVisible(), true);
assert.equal(await fallback.locator('[data-step-controls]').isVisible(), false);
assert.equal(await fallback.locator('#proof tbody tr').count(), 4);
await fallback.locator('#proof summary').click();
assert.equal(await fallback.locator('#proof details').evaluate(e => e.open), true);
assert.equal(await fallback.evaluate(() => document.documentElement.scrollWidth), 390);
await fallback.screenshot({ path: join(output, 'mobile-no-js.png'), fullPage: true });
report.checks.push('JavaScript disabled: four ordered explanations, all evidence and native disclosures usable');
await fallbackContext.close();
// Inspect demo presentation without interacting with wallets or order creation.
for (const route of ['/customer', '/merchant']) {
  const demoContext = await browser.newContext({ javaScriptEnabled: false, viewport: { width: 1440, height: 900 } });
  const demo = await demoContext.newPage();
  await demo.goto(new URL(route, url).href);
  assert.match(await demo.locator('body').innerText(), /Pivovar Marina/);
  assert.equal(await demo.locator('link[href="/assets/homepage.css"]').count(), 0);
  await demo.screenshot({ path: join(output, `${route.slice(1)}-preserved.png`) });
  await demoContext.close();
}
report.checks.push('Both restaurant routes rendered with existing styles, JS disabled to prevent demo API actions');
assert.deepEqual([...new Set(report.requests.map(r => `${r.method} ${r.path}`))].sort(), ['GET /', 'GET /assets/homepage.css', 'GET /assets/homepage.js']);
assert.equal(report.errors.length, 0);
report.checks.push('Homepage input produces only root/CSS/JS GETs; no provider access, API/config/order/RPC/POST or console error');
// Explicit mobile lab conditions, no live-service performance claim.
const perfContext = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 1 });
const perfPage = await perfContext.newPage();
const cdp = await perfContext.newCDPSession(perfPage);
await cdp.send('Network.enable');
await cdp.send('Network.emulateNetworkConditions', { offline: false, latency: 150, downloadThroughput: 200000, uploadThroughput: 93750 });
await cdp.send('Emulation.setCPUThrottlingRate', { rate: 4 });
await perfPage.addInitScript(() => {
  window.homeMetrics = { lcp: 0, cls: 0 };
  new PerformanceObserver(list => { for (const entry of list.getEntries()) window.homeMetrics.lcp = entry.startTime; }).observe({ type: 'largest-contentful-paint', buffered: true });
  new PerformanceObserver(list => { for (const entry of list.getEntries()) if (!entry.hadRecentInput) window.homeMetrics.cls += entry.value; }).observe({ type: 'layout-shift', buffered: true });
});
await perfPage.goto(url, { waitUntil: 'networkidle' });
report.performance = { profile: 'Chromium, 390x844 CSS px, 4x CPU slowdown, 1.6Mbps download, 150ms simulated RTT; loopback SSH fixture, uncompressed responses, one cold lab navigation', ...await perfPage.evaluate(() => ({ ...window.homeMetrics, transferBytes: performance.getEntriesByType('navigation')[0].transferSize + performance.getEntriesByType('resource').reduce((n, e) => n + e.transferSize, 0) })) };
await perfContext.close();
report.requests = [...new Map(report.requests.map(r => [`${r.method} ${r.path}`, r])).values()];
report.fallbackRequests = fallbackRequests;
await writeFile(join(output, 'browser-results.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report, null, 2));
await browser.close();
