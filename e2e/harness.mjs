// Shared setup for the end-to-end tests: a local web server that answers for
// fake hostnames, and Chromium with the unpacked extension loaded.

import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const { chromium } = await import('playwright').catch(() => import(process.env.PLAYWRIGHT_PATH));

const here = path.dirname(fileURLToPath(import.meta.url));
export const extensionDir = path.resolve(here, '../extension');
export const page = (name) => fs.readFileSync(path.join(here, 'pages', name));

/**
 * @param {Record<string, string | ((req, res, url: URL) => void)>} sites
 *   hostname -> test page file name, or a request handler
 */
export async function startServer(sites) {
  const hits = {};
  const server = http.createServer((req, res) => {
    const host = (req.headers.host || '').split(':')[0];
    if (req.url !== '/favicon.ico') hits[host] = (hits[host] || 0) + 1;
    const site = sites[host];
    if (!site) {
      res.writeHead(404).end();
      return;
    }
    if (typeof site === 'function') {
      site(req, res, new URL(req.url, `http://${host}`));
      return;
    }
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(page(site));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { server, hits, port: server.address().port };
}

/** Launch Chromium with the extension, routing every hostname to `port`. */
export async function launch(port) {
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
  let [worker] = context.serviceWorkers();
  worker ??= await context.waitForEvent('serviceworker');
  const extId = new URL(worker.url()).host;

  // Close the onboarding tab opened on install.
  await new Promise((r) => setTimeout(r, 500));
  for (const p of context.pages()) if (p.url().includes('onboarding')) await p.close();

  return {
    context,
    worker,
    extId,
    gatePageRe: new RegExp(`^chrome-extension://${extId}/interstitial/blocked\\.html`),
    async close() {
      await context.close();
      fs.rmSync(userDataDir, { recursive: true, force: true });
    },
  };
}

/** Store a blocklist feed and wait until the redirect rules are installed. */
export async function installBlocklist(worker, feedUrls) {
  await worker.evaluate((urls) => chrome.storage.local.set({ feedUrls: urls }), feedUrls);
  await worker.evaluate(async () => {
    for (let i = 0; i < 50; i++) {
      const { dnrReady } = await chrome.storage.session.get('dnrReady');
      if (dnrReady && (await chrome.declarativeNetRequest.getDynamicRules()).length) return;
      await new Promise((r) => setTimeout(r, 100));
    }
    throw new Error('block rules were not installed');
  });
}

export function makeChecker() {
  let failures = 0;
  return {
    async check(name, fn) {
      try {
        await fn();
        console.log(`  ok   ${name}`);
      } catch (err) {
        failures++;
        console.log(`  FAIL ${name}\n       ${String(err.message).split('\n').slice(0, 6).join('\n       ')}`);
      }
    },
    finish() {
      if (failures) {
        console.log(`\n${failures} check(s) failed`);
        process.exitCode = 1;
      } else {
        console.log('\nall checks passed');
      }
    },
  };
}
