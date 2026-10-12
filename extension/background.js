// Service worker: owns lists and verdicts. Content scripts send page features
// here; we decide and reply. Navigations to known-bad sites are redirected to
// the block page before the site loads. Pages that aren't trusted or
// blocklisted are also sent (as a redacted summary) to the backend, which asks
// the Jev decision model (Tier 3).

import { buildBlocklist } from './lib/lists.js';
import { applyModel, decide, VERDICT } from './lib/fusion.js';
import { classifyRemote } from './lib/apiClient.js';
import { DEFAULT_BACKEND_URL, GRAY_ZONE, GRAY_ZONE_ONLY, MODEL_WAIT_MS } from './lib/config.js';
import { createTier3 } from './lib/tier3.js';
import { describe } from './lib/messages.js';
import { normalizeHost, registrableDomain } from './lib/domain.js';

const FEED_URL = 'https://openphish.com/feed.txt';
const FEED_ALARM = 'refresh-blocklist';
const FEED_REFRESH_MINUTES = 12 * 60;

// ---------------------------------------------------------------------------
// State. The service worker can be stopped at any time, so everything durable
// lives in chrome.storage and is reloaded lazily.

let statePromise;

function loadState() {
  statePromise ??= (async () => {
    const { userTrusted = [], feedUrls = [] } = await chrome.storage.local.get(['userTrusted', 'feedUrls']);
    return { userTrusted, blocklist: buildBlocklist(feedUrls) };
  })();
  return statePromise;
}

function invalidateState() {
  statePromise = undefined;
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && (changes.userTrusted || changes.feedUrls)) invalidateState();
});

/** Domains the user chose to visit anyway this browser session. */
async function sessionAllowed() {
  const { allowedDomains = [] } = await chrome.storage.session.get('allowedDomains');
  return allowedDomains;
}

async function allowForSession(domain) {
  const list = await sessionAllowed();
  if (!list.includes(domain)) await chrome.storage.session.set({ allowedDomains: [...list, domain] });
}

// ---------------------------------------------------------------------------
// Tier 3 (decision model via the backend).

async function getBackendUrl() {
  const { backendUrl } = await chrome.storage.local.get('backendUrl');
  return typeof backendUrl === 'string' ? backendUrl : DEFAULT_BACKEND_URL;
}

/** Random per-install ID, used by the backend for rate limiting only. */
async function getInstallId() {
  const { installId } = await chrome.storage.local.get('installId');
  if (installId) return installId;
  const id = crypto.randomUUID();
  await chrome.storage.local.set({ installId: id });
  return id;
}

const tier3 = createTier3({
  getBackendUrl,
  classify: async (summary, backendUrl) => classifyRemote(summary, { backendUrl, installId: await getInstallId() }),
  grayZoneOnly: GRAY_ZONE_ONLY,
  grayZone: GRAY_ZONE,
  waitMs: MODEL_WAIT_MS,
});

/**
 * Verdict for a URL, and for its page once loaded. With `useModel`, eligible
 * pages are also checked by Tier 3.
 */
async function evaluate(url, page, { useModel = false } = {}) {
  const { userTrusted, blocklist } = await loadState();
  let verdict = decide({ url, page, userTrusted, blocklist });
  if (useModel) verdict = applyModel(verdict, await tier3.ask(url, page, verdict));
  const allowed = await sessionAllowed();
  verdict.overridden = verdict.action !== VERDICT.ALLOW && allowed.includes(verdict.domain);
  return verdict;
}

// ---------------------------------------------------------------------------
// Blocklist feed.

async function refreshBlocklist() {
  try {
    const res = await fetch(FEED_URL, { cache: 'no-store' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const feedUrls = (await res.text()).split('\n').map((l) => l.trim()).filter(Boolean);
    await chrome.storage.local.set({ feedUrls, feedUpdatedAt: Date.now() });
  } catch (err) {
    console.warn('granny_protect: blocklist refresh failed', err);
  }
}

chrome.runtime.onInstalled.addListener(async ({ reason }) => {
  chrome.alarms.create(FEED_ALARM, { periodInMinutes: FEED_REFRESH_MINUTES, delayInMinutes: 1 });
  if (reason === 'install') chrome.tabs.create({ url: chrome.runtime.getURL('onboarding/onboarding.html') });
  refreshBlocklist();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === FEED_ALARM) refreshBlocklist();
});

// ---------------------------------------------------------------------------
// Per-tab verdicts, for the toolbar badge and popup.

async function rememberVerdict(tabId, url, verdict) {
  await chrome.storage.session.set({ [`tab:${tabId}`]: { url, verdict } });
  const show = verdict.action !== VERDICT.ALLOW && !verdict.overridden;
  await chrome.action.setBadgeText({ tabId, text: show ? '!' : '' });
  if (show) {
    await chrome.action.setBadgeBackgroundColor({
      tabId, color: verdict.action === VERDICT.BLOCK ? '#c62828' : '#ef6c00',
    });
  }
}

chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.session.remove(`tab:${tabId}`));

// ---------------------------------------------------------------------------
// Before the page loads: URL + lists only.

chrome.webNavigation.onBeforeNavigate.addListener(async ({ tabId, frameId, url }) => {
  if (frameId !== 0 || !/^https?:/.test(url)) return;
  const verdict = await evaluate(url);
  if (verdict.action !== VERDICT.BLOCK || verdict.overridden) return;
  await rememberVerdict(tabId, url, verdict);
  const blockPage = chrome.runtime.getURL(`interstitial/blocked.html?url=${encodeURIComponent(url)}`);
  chrome.tabs.update(tabId, { url: blockPage });
});

// ---------------------------------------------------------------------------
// Messages from the content script, block page and popup.

function fromExtensionPage(sender) {
  return !sender.tab || String(sender.url).startsWith(chrome.runtime.getURL(''));
}

const handlers = {
  // From the content script, once the page has loaded (and again if it changes).
  async analyzePage(msg, sender) {
    if (!sender.tab || sender.frameId !== 0) return null;
    // Judge the URL the browser reports for this frame, not one the page claims.
    const url = sender.url;
    const verdict = await evaluate(url, { ...msg.features, url }, { useModel: true });
    await rememberVerdict(sender.tab.id, url, verdict);
    return { verdict, text: describe(verdict) };
  },

  // From the block page, to show why a URL was blocked.
  async describeUrl(msg) {
    const verdict = await evaluate(msg.url);
    return { verdict, text: describe(verdict) };
  },

  async proceedAnyway(msg, sender) {
    // A content script may only lift the warning for its own page.
    const target = fromExtensionPage(sender) ? msg.url : sender.url;
    await allowForSession(registrableDomain(normalizeHost(new URL(target).hostname)));
    return { ok: true };
  },

  async goToSafety(msg, sender) {
    const tabId = msg.tabId ?? sender.tab?.id;
    if (tabId == null) return { ok: false };
    try {
      await chrome.tabs.goBack(tabId);
    } catch {
      await chrome.tabs.update(tabId, { url: 'chrome://newtab/' });
    }
    return { ok: true };
  },

  async getTabStatus(msg) {
    const key = `tab:${msg.tabId}`;
    const { [key]: entry } = await chrome.storage.session.get(key);
    const { userTrusted } = await loadState();
    const domain = msg.url ? registrableDomain(normalizeHost(new URL(msg.url).hostname)) : entry?.verdict?.domain;
    const current = entry && entry.url === msg.url ? entry.verdict : await evaluate(msg.url);
    return {
      domain,
      verdict: current,
      text: describe(current),
      userTrusted: userTrusted.includes(domain),
    };
  },

  async trustSite(msg, sender) {
    if (!fromExtensionPage(sender)) return { ok: false };
    const { userTrusted } = await loadState();
    const domain = registrableDomain(normalizeHost(msg.domain));
    if (!userTrusted.includes(domain)) await chrome.storage.local.set({ userTrusted: [...userTrusted, domain] });
    return { ok: true };
  },

  async untrustSite(msg, sender) {
    if (!fromExtensionPage(sender)) return { ok: false };
    const { userTrusted } = await loadState();
    const domain = registrableDomain(normalizeHost(msg.domain));
    await chrome.storage.local.set({ userTrusted: userTrusted.filter((d) => d !== domain) });
    return { ok: true };
  },
};

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Only accept messages from our own extension's pages and content scripts.
  if (sender.id !== chrome.runtime.id) return false;
  const handler = handlers[msg?.type];
  if (!handler) return false;
  handler(msg, sender).then(sendResponse, (err) => {
    console.error('granny_protect:', msg.type, err);
    sendResponse(null);
  });
  return true; // async response
});
