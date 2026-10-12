// End-to-end smoke test: loads the unpacked extension in Chromium and checks
// what the user sees on a few local test pages served under fake hostnames.
//
//   npm run test:e2e
//
// Needs Playwright with a Chromium build. Set PLAYWRIGHT_PATH to a Playwright
// module directory if it isn't installed in this project.

import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const { chromium } = await import('playwright').catch(() => import(process.env.PLAYWRIGHT_PATH));

const here = path.dirname(fileURLToPath(import.meta.url));
const extensionDir = path.resolve(here, '../extension');

const SITES = {
  'paypal-account-verify.top': 'phish-paypal.html',
  'grandmas-recipes.com': 'benign-login.html',
  'win-alert-9921.online': 'tech-support.html',
  'nice-looking-site.com': 'plain.html',
  'designer-bags-outlet.com': 'fake-shop.html',
  // Trusted host serving a scary-looking page: must stay local and unflagged.
  'www.paypal.com': 'phish-paypal.html',
};

// Stand-in for the granny_protect backend (Tier 3). Answers like Jev would
// for each test site, and records what the extension sent.
const BACKEND_HOST = 'gp-backend.test';
const MODEL_ANSWERS = {
  'paypal-account-verify.top': { p_phish: 0.97, category: 'credential_phish', category_confidence: 0.9 },
  'win-alert-9921.online': { p_phish: 0.98, category: 'tech_support_scam', category_confidence: 0.95 },
  'designer-bags-outlet.com': { p_phish: 0.93, category: 'fake_shop', category_confidence: 0.8 },
};
const backendRequests = [];

function handleBackend(req, res) {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => {
    const { summary } = JSON.parse(body || '{}');
    backendRequests.push({ installId: req.headers['x-install-id'], summary });
    const answer = MODEL_ANSWERS[summary?.url_host] ?? { p_phish: 0.03, category: 'benign', category_confidence: 0.9 };
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ...answer, pressure: 0, model: 'mock-jev' }));
  });
}

const server = http.createServer((req, res) => {
  const host = (req.headers.host || '').split(':')[0];
  if (host === BACKEND_HOST && req.url === '/classify' && req.method === 'POST') {
    handleBackend(req, res);
    return;
  }
  const file = SITES[host];
  if (!file) {
    res.writeHead(404).end();
    return;
  }
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end(fs.readFileSync(path.join(here, 'pages', file)));
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const port = server.address().port;

const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gp-e2e-'));
const context = await chromium.launchPersistentContext(userDataDir, {
  channel: 'chromium',
  headless: true,
  args: [
    `--disable-extensions-except=${extensionDir}`,
    `--load-extension=${extensionDir}`,
    `--host-resolver-rules=MAP * 127.0.0.1:${port}`,
  ],
});

let failures = 0;
async function check(name, fn) {
  try {
    await fn();
    console.log(`  ok   ${name}`);
  } catch (err) {
    failures++;
    console.log(`  FAIL ${name}\n       ${err.message.split('\n').join('\n       ')}`);
  }
}

const overlayClass = (page) => page.evaluate(() => !!document.querySelector('[data-granny-protect]'));

try {
  let [worker] = context.serviceWorkers();
  worker ??= await context.waitForEvent('serviceworker');
  const extId = new URL(worker.url()).host;

  // Close the onboarding tab opened on install.
  await new Promise((r) => setTimeout(r, 500));
  for (const p of context.pages()) if (p.url().includes('onboarding')) await p.close();

  const url = (host, p = '/') => `http://${host}${p}`;
  await worker.evaluate((u) => chrome.storage.local.set({ backendUrl: u }), url(BACKEND_HOST));

  await check('phishing login page: warning shown, password field locked', async () => {
    const page = await context.newPage();
    await page.goto(url('paypal-account-verify.top', '/signin'));
    await page.waitForSelector('[data-granny-protect]', { state: 'attached', timeout: 5000 });
    await page.click('#pw', { force: true }).catch(() => {});
    await page.keyboard.type('hunter2');
    assert.equal(await page.inputValue('#pw'), '', 'password field should stay empty');
    await page.close();
  });

  await check('ordinary login page: no warning, typing works', async () => {
    const page = await context.newPage();
    await page.goto(url('grandmas-recipes.com', '/login'));
    await page.waitForTimeout(800);
    assert.equal(await overlayClass(page), false, 'no overlay expected');
    await page.fill('#pw', 'hunter2');
    assert.equal(await page.inputValue('#pw'), 'hunter2');
    await page.close();
  });

  await check('tech support scam page: warning shown', async () => {
    const page = await context.newPage();
    await page.goto(url('win-alert-9921.online'));
    await page.waitForSelector('[data-granny-protect]', { state: 'attached', timeout: 5000 });
    await page.close();
  });

  await check('page scripts cannot dismiss the warning', async () => {
    const page = await context.newPage();
    await page.goto(url('paypal-account-verify.top', '/signin'));
    await page.waitForSelector('[data-granny-protect]', { state: 'attached', timeout: 5000 });
    // A closed shadow root hides the buttons from the page, and synthetic
    // clicks are ignored; removing the overlay still leaves fields locked.
    await page.evaluate(() => document.querySelector('[data-granny-protect]').remove());
    await page.click('#pw');
    await page.keyboard.type('hunter2');
    assert.equal(await page.inputValue('#pw'), '');
    await page.close();
  });

  await check('"I understand the risk" twice-confirmed unlocks the page', async () => {
    const page = await context.newPage();
    await page.goto(url('paypal-account-verify.top', '/signin'));
    await page.waitForSelector('[data-granny-protect]', { state: 'attached', timeout: 5000 });
    // Focus starts on "Take me to safety"; Tab -> "I understand the risk".
    await page.keyboard.press('Tab');
    await page.keyboard.press('Enter');
    // Focus moves to "No"; Shift+Tab -> "Yes, continue".
    await page.keyboard.press('Shift+Tab');
    await page.keyboard.press('Enter');
    await page.waitForSelector('[data-granny-protect]', { state: 'detached', timeout: 3000 });
    await page.fill('#pw', 'hunter2');
    assert.equal(await page.inputValue('#pw'), 'hunter2');
    await page.close();
  });

  await check('Tier 3: model-flagged fake shop warns, with the model\'s category', async () => {
    const page = await context.newPage();
    await page.goto(url('designer-bags-outlet.com', '/bags?ref=email&user=me@example.com'));
    await page.waitForSelector('[data-granny-protect]', { state: 'attached', timeout: 5000 });
    await page.click('#card', { force: true }).catch(() => {});
    await page.keyboard.type('4111111111111111');
    assert.equal(await page.inputValue('#card'), '', 'card field should stay empty');
    const sent = backendRequests.find((r) => r.summary.url_host === 'designer-bags-outlet.com');
    assert.ok(sent, 'summary should be sent to the backend');
    assert.match(sent.installId, /^[0-9a-f-]{36}$/);
    assert.equal(sent.summary.url_path, '/bags');
    assert.doesNotMatch(JSON.stringify(sent.summary), /me@example|ref=email/);
    assert.deepEqual(sent.summary.sensitive_fields, ['card']);
    const verdict = await worker.evaluate(async () => {
      const [tab] = await chrome.tabs.query({ url: 'http://designer-bags-outlet.com/*' });
      return (await chrome.storage.session.get(`tab:${tab.id}`))[`tab:${tab.id}`].verdict;
    });
    assert.equal(verdict.source, 'model');
    assert.equal(verdict.category, 'fake_shop');
    assert.equal(verdict.action, 'warn');
    await page.close();
  });

  await check('Tier 3: trusted sites are never sent to the backend', async () => {
    const page = await context.newPage();
    await page.goto(url('www.paypal.com', '/signin'));
    await page.waitForTimeout(800);
    assert.equal(await overlayClass(page), false, 'no overlay expected on a trusted site');
    await page.close();
    assert.ok(backendRequests.length > 0);
    assert.ok(backendRequests.every((r) => !/paypal\.com$/.test(r.summary.url_host)));
  });

  await check('Tier 3 off (backend down): heuristics still protect', async () => {
    await worker.evaluate(() => chrome.storage.local.set({ backendUrl: 'http://gp-backend-down.test/' }));
    const page = await context.newPage();
    await page.goto(url('win-alert-9921.online', '/?down'));
    await page.waitForSelector('[data-granny-protect]', { state: 'attached', timeout: 5000 });
    await page.close();
    const benign = await context.newPage();
    await benign.goto(url('grandmas-recipes.com', '/login'));
    await benign.waitForTimeout(800);
    await benign.fill('#pw', 'hunter2');
    assert.equal(await benign.inputValue('#pw'), 'hunter2');
    await benign.close();
    await worker.evaluate((u) => chrome.storage.local.set({ backendUrl: u }), url(BACKEND_HOST));
  });

  await check('blocklisted site: redirected to block page before loading', async () => {
    await worker.evaluate(() => chrome.storage.local.set({ feedUrls: ['http://nice-looking-site.com/'] }));
    const page = await context.newPage();
    await page.goto(url('nice-looking-site.com')).catch(() => {});
    await page.waitForURL(`chrome-extension://${extId}/interstitial/blocked.html*`, { timeout: 5000 });
    await page.waitForFunction(() => document.getElementById('reasons').children.length > 0);
    const headline = await page.textContent('#headline');
    assert.match(headline, /dangerous/i);
    await page.close();
  });
} finally {
  await context.close();
  server.close();
  fs.rmSync(userDataDir, { recursive: true, force: true });
}

if (failures) {
  console.log(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log('\nall checks passed');
