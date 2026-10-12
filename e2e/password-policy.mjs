// DOM-level regressions for the content script. The runtime bridge is mocked,
// but feature extraction, policy decisions, and browser events use real code.
// This does not replace the unpacked-extension integration suites.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { decide } from '../extension/lib/fusion.js';
import { describe } from '../extension/lib/messages.js';

const { chromium } = await import('playwright').catch(() => import(process.env.PLAYWRIGHT_PATH));
const browser = await chromium.launch({
  channel: 'chromium', headless: true,
  executablePath: process.env.CHROMIUM_EXECUTABLE_PATH || undefined,
});
after(() => browser.close());

async function withPage(html, run) {
  const context = await browser.newContext();
  const requests = [];
  await context.route('**/*', (route) => {
    requests.push(route.request().url());
    return route.fulfill({ contentType: 'text/html', body: `<!doctype html><title>Login</title>${html}` });
  });
  try {
    const page = await context.newPage();
    await page.goto('https://policy-check.test/');
    await page.exposeFunction('analyzeForTest', (features) => {
      const url = page.url();
      const verdict = decide({ url, page: { ...features, url } });
      return { verdict, text: describe(verdict) };
    });
    await page.evaluate(() => {
      chrome.runtime = { sendMessage: async (msg) => {
        if (msg.type === 'checkPage') return { gated: false };
        if (msg.type === 'screenUrls') return { decisions: {} };
        if (msg.type === 'analyzePage') {
          const result = await window.analyzeForTest(msg.features);
          window.policyVerdict = result.verdict;
          return result;
        }
        return null;
      } };
      document.addEventListener('submit', (event) => {
        setTimeout(() => { window.submissionPrevented = event.defaultPrevented; }, 0);
      }, true);
    });
    await page.addScriptTag({ path: fileURLToPath(new URL('../extension/content/content.js', import.meta.url)) });
    await page.waitForFunction(() => window.policyVerdict);
    await run(page, requests);
  } finally {
    await context.close();
  }
}

const form = '<form id="login" action="/session"><input id="pw" type="password"><button id="go">Sign in</button></form>';

test('HTTP formaction outside the form locks the password field', async () => {
  await withPage(`${form}<button form="login" formaction="http://collector.test/session">Alternate sign in</button>`, async (page) => {
    assert.equal(await page.evaluate(() => window.policyVerdict.policy), true);
    await page.locator('#pw').focus();
    await page.keyboard.type('test-password');
    assert.equal(await page.inputValue('#pw'), '');
  });
});

test('an HTTP override introduced after typing cannot submit the password', async () => {
  await withPage(form, async (page, requests) => {
    await page.locator('#pw').fill('test-password');
    await page.evaluate(() => document.getElementById('go').setAttribute('formaction', 'http://collector.test/session'));
    await page.click('#go');
    await page.waitForFunction(() => window.submissionPrevented === true);
    assert.ok(requests.every((url) => !url.startsWith('http:')));
  });
});

test('image submitter overrides and relative actions respect the document base', async () => {
  await withPage(`<base href="http://collector.test/">${form}<input type="image" form="login" formaction="/session">`, async (page) => {
    assert.equal(await page.evaluate(() => window.policyVerdict.policy), true);
  });
});

test('HTTPS forms with HTTPS submitter overrides still allow typing and submission', async () => {
  await withPage(`${form}<button id="alternate" form="login" formaction="https://policy-check.test/other">Alternate</button>`, async (page) => {
    assert.equal(await page.evaluate(() => window.policyVerdict.action), 'allow');
    await page.locator('#pw').fill('test-password');
    const allowed = await page.evaluate(() => document.getElementById('login').dispatchEvent(new SubmitEvent('submit', {
      bubbles: true, cancelable: true, submitter: document.getElementById('alternate'),
    })));
    assert.equal(allowed, true);
  });
});
