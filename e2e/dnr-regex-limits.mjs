// Exercise Chrome's actual compiled-regex limit, including the fallback gate.
import assert from 'node:assert/strict';
import { buildBlockRules } from '../extension/lib/dnrRules.js';
import { buildBlocklist } from '../extension/lib/lists.js';
import { installBlocklist, launch, startServer } from './harness.mjs';

const { server, hits, port } = await startServer({
  'known-scam.xyz': 'plain.html',
  'docs.google.com': 'plain.html',
});
const browser = await launch(port);
const { context, worker, gatePageRe } = browser;
try {
  const oversizedUrl = `https://docs.google.com/forms/${'a'.repeat(1200)}`;
  const validUrl = 'https://docs.google.com/forms/listed';
  // Confirm the fixture exceeds the compiled limit for this Chromium build.
  const [candidate] = buildBlockRules(buildBlocklist([oversizedUrl]), 'chrome-extension://test/interstitial/blocked.html');
  const support = await worker.evaluate((regex) =>
    chrome.declarativeNetRequest.isRegexSupported({ regex, requireCapturing: true, isCaseSensitive: true }),
    candidate.condition.regexFilter);
  assert.equal(support.isSupported, false);
  assert.equal(support.reason, 'memoryLimitExceeded');

  await worker.evaluate(() => chrome.storage.session.set({ dnrReady: false }));
  await installBlocklist(worker, ['https://known-scam.xyz/', oversizedUrl, validUrl]);
  const installed = await worker.evaluate(async () => ({
    rules: await chrome.declarativeNetRequest.getDynamicRules(),
    state: await chrome.storage.session.get(['dnrReady', 'dnrSkippedRuleIds']),
  }));
  assert.equal(installed.state.dnrReady, true);
  assert.deepEqual(installed.state.dnrSkippedRuleIds, [2]);
  assert.deepEqual(installed.rules.map((r) => r.id).sort(), [1, 3]);

  for (const url of ['https://known-scam.xyz/path', validUrl]) {
    const page = await context.newPage();
    await page.goto(url).catch(() => {});
    await page.waitForURL(gatePageRe, { timeout: 5000, waitUntil: 'domcontentloaded' });
    await page.close();
  }
  assert.equal(hits['known-scam.xyz'] || 0, 0, 'host rule still blocks before any request');
  assert.equal(hits['docs.google.com'] || 0, 0, 'supported exact URL still blocks before any request');

  const page = await context.newPage();
  await page.goto(oversizedUrl).catch(() => {});
  await page.waitForURL(gatePageRe, { timeout: 5000, waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => document.getElementById('address').textContent.includes('/forms/'));
  assert.equal(await page.textContent('#address'), oversizedUrl, 'rejected regex still gates the exact destination');
  await page.close();
  console.log('DNR compiled-regex limit: valid rules installed, rejected URL gated');
} finally {
  await browser.close();
  server.close();
}
