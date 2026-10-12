// Navigation gating matrix: every way of reaching a destination, against a
// blocklisted, a needs-review and a safe destination.
//
//   npm run test:e2e
//
// For each case we check where the user ends up, and whether the destination's
// server received a request. Blocklisted destinations must never be contacted.
// Needs-review destinations must never be shown; for link activations they
// must not be contacted either. Other sources (typed address, window.open,
// redirects) are gated after the request starts, which the table reports.

import assert from 'node:assert/strict';
import { installBlocklist, launch, makeChecker, startServer } from './harness.mjs';

const DESTS = {
  block: 'http://nice-looking-site.com/landing',
  review: 'http://paypal-account-verify.top/signin',
  safe: 'http://handmade-quilts.com/shop',
};

const html = (res, body) => {
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end(`<!doctype html><meta charset="utf-8"><title>test</title>${body}`);
};

// The page the user starts from, plus redirect helpers on the same host.
function launcher(req, res, url) {
  const to = url.searchParams.get('to') || '';
  if (url.pathname === '/redirect') {
    res.writeHead(302, { location: to }).end();
  } else if (url.pathname === '/js') {
    html(res, `<script>location.href = ${JSON.stringify(to)};</script>`);
  } else if (url.pathname === '/meta') {
    html(res, `<meta http-equiv="refresh" content="0;url=${to}">`);
  } else if (url.pathname === '/spa') {
    // A single-page app that handles its own link clicks.
    html(res, `<a id="app-link" href="${DESTS.review}">route</a><div id="view">home</div>
      <script>document.getElementById('app-link').addEventListener('click', (e) => {
        e.preventDefault(); document.getElementById('view').textContent = 'routed';
      });</script>`);
  } else {
    html(res, Object.entries(DESTS).map(([k, d]) => `
      <p><a id="same-${k}" href="${d}">${k}</a>
         <a id="blank-${k}" href="${d}" target="_blank">${k} new tab</a>
         <button id="open-${k}" onclick="window.open('${d}')">${k} window.open</button>
         <a id="redir-${k}" href="/redirect?to=${encodeURIComponent(d)}">${k} via redirect</a></p>`).join(''));
  }
}

const { server, hits, port } = await startServer({
  'start-page.com': launcher,
  'nice-looking-site.com': 'plain.html',
  'paypal-account-verify.top': 'phish-paypal.html',
  'handmade-quilts.com': 'plain.html',
});
const browser = await launch(port);
const { context, worker, gatePageRe } = browser;
await installBlocklist(worker, ['http://nice-looking-site.com/']);

const START = 'http://start-page.com/';

// How the user gets there. `newTab` sources end up in a new tab; `link`
// sources are link activations the content script sees before loading starts.
const SOURCES = [
  { name: 'typed address', act: (p, k) => p.goto(DESTS[k]).catch(() => {}), fromStart: false },
  { name: 'link click', link: true, act: (p, k) => p.click(`#same-${k}`) },
  { name: 'link click (pre-screened)', link: true, act: async (p, k) => { await p.waitForTimeout(700); await p.click(`#same-${k}`); } },
  { name: 'keyboard Enter', link: true, act: async (p, k) => { await p.focus(`#same-${k}`); await p.keyboard.press('Enter'); } },
  { name: 'target=_blank', link: true, newTab: true, act: (p, k) => p.click(`#blank-${k}`) },
  { name: 'Ctrl+click', link: true, newTab: true, act: (p, k) => p.click(`#same-${k}`, { modifiers: ['Control'] }) },
  { name: 'middle click', link: true, newTab: true, act: (p, k) => p.click(`#same-${k}`, { button: 'middle' }) },
  { name: 'window.open', newTab: true, act: (p, k) => p.click(`#open-${k}`) },
  { name: 'server redirect', act: (p, k) => p.click(`#redir-${k}`) },
  { name: 'script redirect', act: (p, k) => p.goto(`${START}js?to=${encodeURIComponent(DESTS[k])}`).catch(() => {}) },
  { name: 'meta refresh', act: (p, k) => p.goto(`${START}meta?to=${encodeURIComponent(DESTS[k])}`).catch(() => {}) },
];

/** Wait until `p` shows the destination or the gate page; report which. */
async function outcome(p, dest) {
  const destRe = new RegExp(`^${dest.replace(/[.?]/g, '\\$&')}`);
  await p.waitForURL((u) => gatePageRe.test(u.href) || destRe.test(u.href), { timeout: 6000 });
  // Give a late gate (onBeforeNavigate / document_start) time to take over.
  await p.waitForTimeout(600);
  if (gatePageRe.test(p.url())) {
    await p.waitForFunction(() => document.body.dataset.mode, null, { timeout: 4000 });
    return await p.evaluate(() => document.body.dataset.mode); // 'block' | 'review'
  }
  return destRe.test(p.url()) ? 'shown' : `other: ${p.url()}`;
}

const { check, finish } = makeChecker();
const table = [];

for (const source of SOURCES) {
  for (const kind of ['block', 'review', 'safe']) {
    await check(`${source.name} -> ${kind}`, async () => {
      const host = new URL(DESTS[kind]).hostname;
      const before = hits[host] || 0;
      const start = await context.newPage();
      if (source.fromStart !== false) await start.goto(START);
      let target = start;
      if (source.newTab) {
        const opened = context.waitForEvent('page', { timeout: 6000 });
        await source.act(start, kind);
        target = await opened;
      } else {
        await source.act(start, kind);
      }
      const result = await outcome(target, DESTS[kind]);
      const contacted = (hits[host] || 0) > before;
      table.push({ source: source.name, kind, result, contacted });

      const expected = { block: 'block', review: 'review', safe: 'shown' }[kind];
      assert.equal(result, expected, `ended on ${target.url()}`);
      if (kind === 'block') assert.equal(contacted, false, 'blocklisted site must not be contacted');
      if (kind === 'review' && source.link) assert.equal(contacted, false, 'link to a review site must be held before loading');
      if (kind === 'safe') assert.equal(contacted, true);

      for (const p of context.pages()) await p.close();
    });
  }
}

await check('links the page handles itself (single-page apps) are left alone', async () => {
  const p = await context.newPage();
  await p.goto(`${START}spa`);
  await p.click('#app-link');
  await p.waitForTimeout(500);
  assert.equal(await p.textContent('#view'), 'routed');
  assert.equal(p.url(), `${START}spa`);
  await p.close();
});

console.log('\nsource                     destination  result  request reached site');
for (const r of table) {
  console.log(`${r.source.padEnd(27)}${r.kind.padEnd(13)}${r.result.padEnd(8)}${r.contacted ? 'yes' : 'no'}`);
}

await browser.close();
server.close();
finish();
