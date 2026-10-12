// Smoke test: page-level screening, the sensitive-input lock, the warning
// overlay, the enterprise no-passwords-over-http policy, and the block page
// for listed sites.
//
//   npm run test:e2e

import assert from 'node:assert/strict';
import { installBlocklist, launch, makeChecker, startServer } from './harness.mjs';

const { server, hits, port } = await startServer({
  // Neutral addresses: only the page content gives these away.
  'account-review-center.com': 'phish-paypal.html',
  'win-alert-9921.online': 'tech-support.html',
  'grandmas-recipes.com': 'benign-login.html',
  'intranet': 'benign-login.html',
  'handmade-quilts.com': 'form-to-http.html',
  'nice-looking-site.com': 'plain.html',
  'docs.google.com': 'plain.html',
});
const browser = await launch(port);
const { context, worker, gatePageRe } = browser;
const url = (host, p = '/') => `https://${host}${p}`;
const httpUrl = (host, p = '/') => `http://${host}${p}`;
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

// --- Enterprise policy: never a password over http ---------------------------

/** Try to type into #pw the way a user would; returns what ended up in it. */
async function tryTyping(page) {
  await page.click('#pw', { force: true }).catch(() => {});
  await page.keyboard.type('hunter2');
  return page.inputValue('#pw');
}

await check('policy: http login page is locked and offers no way to continue', async () => {
  const page = await context.newPage();
  await page.goto(httpUrl('grandmas-recipes.com', '/login'));
  await page.waitForSelector('[data-granny-protect]', { state: 'attached', timeout: 5000 });
  // Focus starts on "Take me to safety"; the only other button is "Stay on
  // this page", which removes the message but keeps the boxes locked.
  const verdict = await worker.evaluate(async () => Object.values(await chrome.storage.session.get(null)).find((v) => v?.verdict?.policy)?.verdict);
  assert.equal(verdict?.source, 'policy');
  await page.keyboard.press('Tab');
  await page.keyboard.press('Enter');
  await page.waitForSelector('[data-granny-protect]', { state: 'detached', timeout: 3000 });
  assert.equal(await tryTyping(page), '', 'still locked after staying on the page');
  await page.close();
});

await check('policy: applies to internal sites too', async () => {
  const page = await context.newPage();
  await page.goto(httpUrl('intranet', '/login'));
  await page.waitForSelector('[data-granny-protect]', { state: 'attached', timeout: 5000 });
  assert.equal(await tryTyping(page), '');
  await page.close();
});

await check('policy: https page whose password form posts to http is locked, even after "show password"', async () => {
  const page = await context.newPage();
  await page.goto(url('handmade-quilts.com', '/account'));
  await page.waitForSelector('[data-granny-protect]', { state: 'attached', timeout: 5000 });
  await page.keyboard.press('Tab');
  await page.keyboard.press('Enter'); // stay on the page
  await page.waitForSelector('[data-granny-protect]', { state: 'detached', timeout: 3000 });
  await page.click('#show'); // page turns the password box into a text box
  assert.equal(await page.getAttribute('#pw', 'type'), 'text');
  assert.equal(await tryTyping(page), '');
  await page.close();
});

await installBlocklist(worker, ['http://nice-looking-site.com/', 'http://docs.google.com/forms/d/e/bad123/viewform']);

await check('blocklisted site: block page shown and the site is never contacted', async () => {
  const page = await context.newPage();
  await page.goto(httpUrl('nice-looking-site.com', '/some/page?x=1')).catch(() => {});
  await page.waitForURL(gatePageRe, { timeout: 5000 });
  await page.waitForFunction(() => document.getElementById('reasons').children.length > 0);
  assert.match(await page.textContent('#headline'), /dangerous/i);
  assert.equal(await page.textContent('#address'), 'http://nice-looking-site.com/some/page?x=1');
  assert.equal(hits['nice-looking-site.com'] || 0, 0, 'server must not receive the request');
  await page.close();
});

await check('one bad page on a shared host is blocked, the rest of the host is not', async () => {
  const page = await context.newPage();
  await page.goto(httpUrl('docs.google.com', '/forms/d/e/bad123/viewform?usp=sf_link')).catch(() => {});
  await page.waitForURL(gatePageRe, { timeout: 5000 });
  assert.equal(hits['docs.google.com'] || 0, 0);
  await page.close();
  const other = await context.newPage();
  await other.goto(httpUrl('docs.google.com', '/forms/d/e/fine456/viewform'));
  assert.ok(!other.url().startsWith('chrome-extension://'), other.url());
  assert.equal(hits['docs.google.com'], 1);
  await other.close();
});

await check('"continue anyway" on the block page lets the user through', async () => {
  const page = await context.newPage();
  await page.goto(httpUrl('nice-looking-site.com')).catch(() => {});
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
