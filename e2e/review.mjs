// Remote review flows in the browser, against the real review service
// (server/server.mjs) with a STAND-IN model whose answer each check sets.
// This exercises the plumbing (gating, fallback, caching, sanitization), not
// Jev itself.
//
//   npm run test:e2e

import assert from 'node:assert/strict';
import { launch, makeChecker, startServer } from './harness.mjs';
import { createReviewServer } from '../server/server.mjs';

// What the stand-in model does for the current check.
let behaviour = async () => ({ decision: 'allow', confidence: 0.95, category: null });
const received = [];
const review = createReviewServer({
  model: { name: 'stand-in', configured: true, classify: (req) => { received.push(req); return behaviour(req); } },
  modelTimeoutMs: 5000,
});
await new Promise((r) => review.listen(0, '127.0.0.1', r));
const reviewEndpoint = `http://127.0.0.1:${review.address().port}/review`;

const html = (res, body) => {
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end(`<!doctype html><meta charset="utf-8"><title>test</title>${body}`);
};

// Each check uses its own needs-review destination so cached reviews from
// one check don't answer the next.
const dest = (n) => `http://paypal-account-verify-${n}.top/signin/reset/9f8a7b6c5d4e3f2a1b0c?email=jane@example.com#top`;
const { server, hits, port } = await startServer({
  'start-page.com': (req, res, url) => html(res, `<a id="go" href="${url.searchParams.get('to')}">go</a>`),
  ...Object.fromEntries([1, 2, 3, 4, 5].map((n) => [`paypal-account-verify-${n}.top`, 'plain.html'])),
});
const browser = await launch(port);
const { context, worker, gatePageRe } = browser;
await worker.evaluate((cfg) => chrome.storage.local.set(cfg), { reviewEndpoint, reviewTimeoutMs: 1500 });

const { check, finish } = makeChecker();

async function clickThrough(to) {
  const p = await context.newPage();
  await p.goto(`http://start-page.com/?to=${encodeURIComponent(to)}`);
  await p.click('#go');
  return p;
}

async function settle(p, to) {
  const host = new URL(to).hostname;
  await p.waitForURL((u) => gatePageRe.test(u.href) || u.hostname === host, { timeout: 8000 });
  await p.waitForTimeout(400);
  if (!gatePageRe.test(p.url())) return 'shown';
  await p.waitForFunction(() => document.body.dataset.mode, null, { timeout: 5000 });
  return p.evaluate(() => document.body.dataset.mode);
}

await check('link: review says allow -> destination loads', async () => {
  behaviour = async () => ({ decision: 'allow', confidence: 0.95, category: null });
  const p = await clickThrough(dest(1));
  assert.equal(await settle(p, dest(1)), 'shown');
  assert.ok((hits['paypal-account-verify-1.top'] || 0) >= 1);
  await p.close();
});

await check('link: review says block -> block page, site never contacted', async () => {
  behaviour = async () => ({ decision: 'block', confidence: 0.97, category: 'credential_phish' });
  const p = await clickThrough(dest(2));
  assert.equal(await settle(p, dest(2)), 'block');
  assert.match(await p.textContent('#reasons'), /safety check confirmed/);
  assert.equal(hits['paypal-account-verify-2.top'] || 0, 0);
  await p.close();
});

await check('link: review service failing -> stays held for review, site never contacted', async () => {
  behaviour = async () => { throw new Error('upstream down'); };
  const p = await clickThrough(dest(3));
  assert.equal(await settle(p, dest(3)), 'review');
  assert.equal(hits['paypal-account-verify-3.top'] || 0, 0);
  await p.close();
});

await check('link: review too slow -> held for review within the timeout', async () => {
  behaviour = () => new Promise((r) => setTimeout(() => r({ decision: 'allow', confidence: 0.99, category: null }), 4000));
  const started = Date.now();
  const p = await clickThrough(dest(4));
  assert.equal(await settle(p, dest(4)), 'review');
  assert.ok(Date.now() - started < 4000, 'gate shown before the slow review returned');
  assert.equal(hits['paypal-account-verify-4.top'] || 0, 0);
  await p.close();
});

await check('typed address: gate page gets the review and continues on allow, without looping', async () => {
  behaviour = async () => ({ decision: 'allow', confidence: 0.95, category: null });
  const p = await context.newPage();
  await p.goto(dest(5)).catch(() => {});
  await p.waitForURL((u) => u.hostname === 'paypal-account-verify-5.top', { timeout: 8000 });
  await p.waitForTimeout(1500);
  assert.equal(new URL(p.url()).hostname, 'paypal-account-verify-5.top', `ended on ${p.url()}`);
  await p.close();
});

await check('the review service never receives query strings, fragments or identifiers', async () => {
  assert.ok(received.length >= 4, `only ${received.length} requests`);
  const all = JSON.stringify(received);
  for (const leak of ['jane@example.com', 'email=', '#top', '9f8a7b6c5d4e3f2a1b0c']) {
    assert.ok(!all.includes(leak), `leaked ${leak}`);
  }
  assert.ok(received.every((r) => r.destination.path === '/signin/reset/[id]'));
});

await browser.close();
server.close();
review.close();
finish();
