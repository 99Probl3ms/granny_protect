// Service worker: owns lists and verdicts. Content scripts send page features
// here; we decide and reply. Known scam sites are redirected to the block page
// by declarativeNetRequest rules before any request is sent; a webNavigation
// check covers anything the rules don't.

import { buildBlocklist } from './lib/lists.js';
import { decide, VERDICT } from './lib/fusion.js';
import { describe } from './lib/messages.js';
import { normalizeHost, registrableDomain } from './lib/domain.js';
import { allowRule, buildBlockRules, coveredByRules } from './lib/dnrRules.js';

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
  if (area === 'local' && (changes.userTrusted || changes.feedUrls)) {
    invalidateState();
    syncBlockRules();
  }
});

// ---------------------------------------------------------------------------
// declarativeNetRequest: block known scam sites before the request is sent.

const BLOCK_PAGE = 'interstitial/blocked.html';

// Runs one at a time: overlapping updates would collide on rule ids.
let syncQueue = Promise.resolve();
function syncBlockRules() {
  syncQueue = syncQueue.then(doSyncBlockRules);
  return syncQueue;
}

async function doSyncBlockRules() {
  try {
    const { userTrusted, blocklist } = await loadState();
    const addRules = buildBlockRules(blocklist, chrome.runtime.getURL(BLOCK_PAGE), userTrusted);
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: existing.map((r) => r.id),
      addRules,
    });
    await chrome.storage.session.set({ dnrReady: true });
  } catch (err) {
    // The webNavigation fallback below still blocks listed sites.
    console.warn('granny_protect: could not install block rules', err);
    await chrome.storage.session.set({ dnrReady: false });
  }
}

async function dnrReady() {
  const { dnrReady: ready = false } = await chrome.storage.session.get('dnrReady');
  return ready;
}

/** Domains the user chose to visit anyway this browser session. */
async function sessionAllowed() {
  const { allowedDomains = [] } = await chrome.storage.session.get('allowedDomains');
  return allowedDomains;
}

async function allowForSession(domain) {
  const list = await sessionAllowed();
  if (list.includes(domain)) return;
  const allowedDomains = [...list, domain];
  // Session rules outrank the block rules and are cleared with the session.
  await chrome.declarativeNetRequest.updateSessionRules({
    removeRuleIds: [allowedDomains.length],
    addRules: [allowRule(allowedDomains.length, domain)],
  });
  await chrome.storage.session.set({ allowedDomains });
}

async function evaluate(url, page) {
  const { userTrusted, blocklist } = await loadState();
  const verdict = decide({ url, page, userTrusted, blocklist });
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
  await syncBlockRules();
  refreshBlocklist();
});

chrome.runtime.onStartup.addListener(() => syncBlockRules());

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
// Before the page loads: URL + lists only. Listed sites are normally already
// redirected by the declarativeNetRequest rules; this catches the rest
// (entries over the rule limit, failed rule installs) and very risky URLs.

chrome.webNavigation.onBeforeNavigate.addListener(async ({ tabId, frameId, url }) => {
  if (frameId !== 0 || !/^https?:/.test(url)) return;
  const verdict = await evaluate(url);
  if (verdict.action !== VERDICT.BLOCK || verdict.overridden) return;
  if (verdict.source === 'blocklist' && await dnrReady()) {
    const { blocklist, userTrusted } = await loadState();
    if (coveredByRules(url, blocklist, userTrusted)) return;
  }
  await rememberVerdict(tabId, url, verdict);
  const blockPage = chrome.runtime.getURL(`${BLOCK_PAGE}?url=${encodeURIComponent(url)}`);
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
    const verdict = await evaluate(url, { ...msg.features, url });
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
