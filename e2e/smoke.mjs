// Smoke test: page-level screening, the sensitive-input lock, the warning
// overlay, and the block page for listed sites.
//
//   npm run test:e2e

import assert from 'node:assert/strict';
import { installBlocklist, launch, makeChecker, startServer } from './harness.mjs';

const { server, hits, port } = await startServer({
  // Neutral addresses: only the page content gives these away.
  'account-review-center.com': 'phish-paypal.html',
  'win-alert-9921.online': 'tech-support.html',
  'grandmas-recipes.com': 'benign-login.html',
  'nice-looking-site.com': 'plain.html',
  'docs.google.com': 'plain.html',
});
const browser = await launch(port);
const { context, worker, gatePageRe } = browser;
const url = (host, p = '/') => `http://${host}${p}`;
const overlayShown = (page) => page.evaluate(() => !!document.querySelector('[data-granny-protect]'));
const { check, finish } = makeChecker();

await check('phishing login page: warning shown, password field locked', async () => {
  const page = await context.newPage();
  await page.goto(url('account-review-center.com', '/signin'));
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
  assert.equal(await overlayShown(page), false, 'no overlay expected');
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
  await page.goto(url('account-review-center.com', '/signin'));
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
  await page.goto(url('account-review-center.com', '/signin'));
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

await installBlocklist(worker, ['http://nice-looking-site.com/', 'http://docs.google.com/forms/d/e/bad123/viewform']);

await check('blocklisted site: block page shown and the site is never contacted', async () => {
  const page = await context.newPage();
  await page.goto(url('nice-looking-site.com', '/some/page?x=1')).catch(() => {});
  await page.waitForURL(gatePageRe, { timeout: 5000 });
  await page.waitForFunction(() => document.getElementById('reasons').children.length > 0);
  assert.match(await page.textContent('#headline'), /dangerous/i);
  assert.equal(await page.textContent('#address'), 'http://nice-looking-site.com/some/page?x=1');
  assert.equal(hits['nice-looking-site.com'] || 0, 0, 'server must not receive the request');
  await page.close();
});

await check('one bad page on a shared host is blocked, the rest of the host is not', async () => {
  const page = await context.newPage();
  await page.goto(url('docs.google.com', '/forms/d/e/bad123/viewform?usp=sf_link')).catch(() => {});
  await page.waitForURL(gatePageRe, { timeout: 5000 });
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
  await page.waitForURL(gatePageRe, { timeout: 5000 });
  await page.waitForFunction(() => document.body.dataset.mode === 'block');
  await page.click('#continue');
  await page.click('#yes');
  await page.waitForURL('http://nice-looking-site.com/', { timeout: 5000 });
  assert.equal(hits['nice-looking-site.com'], 1);
  await page.close();
});

await browser.close();
server.close();
finish();
