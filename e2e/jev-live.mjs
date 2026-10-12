// Live Jev check: the extension in Chromium, the real review service
// (server/server.mjs) and the real Jev adapter calling TypeSafe. Unlike
// e2e/review.mjs, nothing here is a stand-in, so it needs TYPESAFE_API_KEY
// and network access, costs a few Jev calls, and depends on Jev's answers.
// The destinations were chosen so those answers sit well clear of the
// thresholds (block confidence 0.88-0.92, the unsure one 0.54-0.66).
//
//   TYPESAFE_API_KEY=... npm run test:jev

import assert from 'node:assert/strict';

if (!process.env.TYPESAFE_API_KEY) {
  console.log('skipped: TYPESAFE_API_KEY is not set');
  process.exit(0);
}

// Loaded after the key check so a skip needs no Playwright either.
const { launch, makeChecker, startServer } = await import('./harness.mjs');
const { createReviewServer } = await import('../server/server.mjs');
const { createJevModel } = await import('../server/models/jev.mjs');

// The real adapter, wrapped only to record what goes to Jev and what it says.
const jev = createJevModel();
const calls = [];
const review = createReviewServer({
  model: {
    ...jev,
    async classify(req) {
      const started = Date.now();
      const answer = await jev.classify(req);
      calls.push({ req, answer, ms: Date.now() - started });
      return answer;
    },
  },
  modelTimeoutMs: 5000,
});
await new Promise((r) => review.listen(0, '127.0.0.1', r));
const reviewEndpoint = `http://127.0.0.1:${review.address().port}/review`;

const html = (res, body) => {
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end(`<!doctype html><meta charset="utf-8"><title>test</title>${body}`);
};

const PHISH_LINK = 'http://paypal-account-verify-live.top/signin?email=jane@example.com#top';
const PHISH_TYPED = 'http://secure-paypal-login-verify.top/signin';
const UNSURE = 'http://chase-community-bank-history.xyz/about';
const TECH_SUPPORT = 'https://win-alert-9921.online/';

const { server, hits, port } = await startServer({
  'start-page.com': (req, res, url) => html(res, `<a id="go" href="${url.searchParams.get('to')}">go</a>`),
  'paypal-account-verify-live.top': 'plain.html',
  'secure-paypal-login-verify.top': 'plain.html',
  'chase-community-bank-history.xyz': 'plain.html',
  'win-alert-9921.online': 'tech-support.html',
});
const browser = await launch(port);
const { context, worker, gatePageRe } = browser;
// A real Jev call plus the round trip can exceed the 1.5 s default on a slow
// network; the point here is Jev's answer, not the timeout (review.mjs covers that).
await worker.evaluate((cfg) => chrome.storage.local.set(cfg), { reviewEndpoint, reviewTimeoutMs: 4000 });

const { check, finish } = makeChecker();

async function clickThrough(to) {
  const p = await context.newPage();
  await p.goto(`http://start-page.com/?to=${encodeURIComponent(to)}`);
  await p.click('#go');
  return p;
}

async function gateMode(p, to) {
  const host = new URL(to).hostname;
  await p.waitForURL((u) => gatePageRe.test(u.href) || u.hostname === host, { timeout: 10000 });
  await p.waitForTimeout(400);
  if (!gatePageRe.test(p.url())) return 'shown';
  await p.waitForFunction(() => document.body.dataset.mode, null, { timeout: 8000 });
  return p.evaluate(() => document.body.dataset.mode);
}

const answerFor = (host) => calls.find((c) => c.req.destination.host === host)?.answer;

await check('link to a PayPal look-alike: Jev blocks it, the site is never contacted', async () => {
  const p = await clickThrough(PHISH_LINK);
  assert.equal(await gateMode(p, PHISH_LINK), 'block');
  assert.match(await p.textContent('#reasons'), /safety check confirmed/);
  assert.equal(hits['paypal-account-verify-live.top'] || 0, 0);
  const a = answerFor('paypal-account-verify-live.top');
  assert.equal(a?.decision, 'block');
  assert.equal(a?.category, 'credential_phish');
  await p.close();
});

await check('typed PayPal look-alike: the gate page gets Jev\'s block', async () => {
  const p = await context.newPage();
  await p.goto(PHISH_TYPED).catch(() => {});
  assert.equal(await gateMode(p, PHISH_TYPED), 'block');
  assert.equal(answerFor('secure-paypal-login-verify.top')?.decision, 'block');
  await p.close();
});

await check('address Jev is unsure about: stays held for review, site never contacted', async () => {
  const p = await clickThrough(UNSURE);
  assert.equal(await gateMode(p, UNSURE), 'review');
  assert.equal(hits['chase-community-bank-history.xyz'] || 0, 0);
  assert.equal(answerFor('chase-community-bank-history.xyz')?.decision, 'needs_review');
  await p.close();
});

await check('fake virus-warning page: reviewed with its content, Jev blocks it', async () => {
  const p = await context.newPage();
  await p.goto(TECH_SUPPORT);
  await p.waitForSelector('[data-granny-protect]', { state: 'attached', timeout: 10000 });
  const verdict = await worker.evaluate(async (url) => {
    for (let i = 0; i < 80; i++) {
      const [tab] = await chrome.tabs.query({ url });
      const entry = tab && (await chrome.storage.session.get(`tab:${tab.id}`))[`tab:${tab.id}`];
      if (entry?.verdict?.review) return entry.verdict;
      await new Promise((r) => setTimeout(r, 100));
    }
    return null;
  }, TECH_SUPPORT);
  assert.ok(verdict, 'page verdict was never reviewed');
  assert.equal(verdict.action, 'block');
  assert.equal(verdict.review.decision, 'block');
  const call = calls.find((c) => c.req.destination.host === 'win-alert-9921.online' && c.req.page);
  assert.ok(call, 'Jev was not sent the page content');
  assert.equal(call.answer.category, 'tech_support_scam');
  await p.close();
});

await check('Jev never receives query strings, fragments or the email in the link', async () => {
  const all = JSON.stringify(calls.map((c) => c.req));
  for (const leak of ['jane@example.com', 'email=', '#top']) assert.ok(!all.includes(leak), `leaked ${leak}`);
});

console.log('\nJev answers:');
for (const { req, answer, ms } of calls) {
  const what = `${req.destination.host}${req.destination.path}${req.page ? ' (page)' : ''}`;
  console.log(`  ${what.padEnd(52)} local ${req.local.decision.padEnd(12)} -> ${answer.decision} ${answer.confidence}` +
    ` ${answer.category ?? ''} ${answer.model} ${ms} ms`);
}

await browser.close();
server.close();
review.close();
finish();
