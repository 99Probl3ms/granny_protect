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
  'docs.google.com': 'plain.html',
};

const hits = {};
const server = http.createServer((req, res) => {
  const host = (req.headers.host || '').split(':')[0];
  if (req.url !== '/favicon.ico') hits[host] = (hits[host] || 0) + 1;
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
  const blockPageRe = new RegExp(`^chrome-extension://${extId}/interstitial/blocked\\.html`);

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

  // Install a blocklist and wait for the declarativeNetRequest rules.
  await worker.evaluate(() => chrome.storage.local.set({
    feedUrls: ['http://nice-looking-site.com/', 'http://docs.google.com/forms/d/e/bad123/viewform'],
  }));
  await worker.evaluate(async () => {
    for (let i = 0; i < 50; i++) {
      if ((await chrome.declarativeNetRequest.getDynamicRules()).length >= 2) return;
      await new Promise((r) => setTimeout(r, 100));
    }
    throw new Error('block rules were not installed');
  });

  await check('blocklisted site: block page shown and the site is never contacted', async () => {
    const page = await context.newPage();
    await page.goto(url('nice-looking-site.com', '/some/page?x=1')).catch(() => {});
    await page.waitForURL(blockPageRe, { timeout: 5000 });
    await page.waitForFunction(() => document.getElementById('reasons').children.length > 0);
    assert.match(await page.textContent('#headline'), /dangerous/i);
    assert.equal(await page.textContent('#address'), 'http://nice-looking-site.com/some/page?x=1');
    assert.equal(hits['nice-looking-site.com'] || 0, 0, 'server must not receive the request');
    await page.close();
  });

  await check('one bad page on a shared host is blocked, the rest of the host is not', async () => {
    const page = await context.newPage();
    await page.goto(url('docs.google.com', '/forms/d/e/bad123/viewform?usp=sf_link')).catch(() => {});
    await page.waitForURL(blockPageRe, { timeout: 5000 });
    assert.equal(hits['docs.google.com'] || 0, 0);
    await page.close();
    const other = await context.newPage();
    await other.goto(url('docs.google.com', '/forms/d/e/fine456/viewform'));
    assert.ok(!other.url().startsWith('chrome-extension://'), other.url());
    assert.equal(hits['docs.google.com'], 1);
    await other.close();
  });

  await check('"continue anyway" on the block page lets the user through', async () => {
    const page = await context.newPage();
    await page.goto(url('nice-looking-site.com')).catch(() => {});
    await page.waitForURL(blockPageRe, { timeout: 5000 });
    await page.click('#continue');
    await page.click('#yes');
    await page.waitForURL('http://nice-looking-site.com/', { timeout: 5000 });
    assert.equal(hits['nice-looking-site.com'], 1);
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
