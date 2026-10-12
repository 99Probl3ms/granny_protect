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
};

const server = http.createServer((req, res) => {
  const host = (req.headers.host || '').split(':')[0];
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
