// Service worker: owns lists and decisions.
//
// Every destination gets one of three local decisions: allow, needs_review or
// block (lib/fusion.js). Anything other than allow is gated: the user sees the
// gate page (interstitial/blocked.html) instead of the destination.
//
// Where gating happens, earliest first:
//  1. declarativeNetRequest rules: blocklisted sites, before any request is
//     sent, for every navigation source (clicks, new tabs, typed addresses,
//     redirects).
//  2. Content script link gate: link clicks (same tab, new tab, Ctrl/middle
//     click, keyboard Enter) are checked before the browser starts loading.
//  3. webNavigation.onBeforeNavigate / webRequest.onBeforeRedirect: typed
//     addresses, script and meta redirects, window.open, server redirects.
//     These can't cancel the request, so the destination may receive it, but
//     the tab is moved to the gate page before the page is shown.
//  4. Content script at document_start: if a gated page starts loading
//     anyway, it is hidden and the tab is sent to the gate page.
//  5. After load: page content screening and the sensitive-input lock.

import { buildBlocklist } from './lib/lists.js';
import { decide, VERDICT } from './lib/fusion.js';
import { describe } from './lib/messages.js';
import { normalizeHost, registrableDomain } from './lib/domain.js';
import { allowRule, buildBlockRules, coveredByRules } from './lib/dnrRules.js';

const FEED_URL = 'https://openphish.com/feed.txt';
const FEED_ALARM = 'refresh-blocklist';
const FEED_REFRESH_MINUTES = 12 * 60;
const GATE_PAGE = 'interstitial/blocked.html';
const MAX_SCREEN_URLS = 500;

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

/** Decide for a URL (and, once loaded, its page features). */
async function evaluate(url, page, allowed) {
  const { userTrusted, blocklist } = await loadState();
  const verdict = decide({ url, page, userTrusted, blocklist });
  allowed ??= await sessionAllowed();
  verdict.overridden = verdict.action !== VERDICT.ALLOW && allowed.includes(verdict.domain);
  return verdict;
}

const isGated = (verdict) => verdict.action !== VERDICT.ALLOW && !verdict.overridden;

// ---------------------------------------------------------------------------
// declarativeNetRequest: block listed sites before the request is sent.

// Runs one at a time: overlapping updates would collide on rule ids.
let syncQueue = Promise.resolve();
function syncBlockRules() {
  syncQueue = syncQueue.then(doSyncBlockRules);
  return syncQueue;
}

async function doSyncBlockRules() {
  try {
    const { userTrusted, blocklist } = await loadState();
    const addRules = buildBlockRules(blocklist, chrome.runtime.getURL(GATE_PAGE), userTrusted);
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: existing.map((r) => r.id),
      addRules,
    });
    await chrome.storage.session.set({ dnrReady: true });
  } catch (err) {
    // The navigation checks below still gate listed sites.
    console.warn('granny_protect: could not install block rules', err);
    await chrome.storage.session.set({ dnrReady: false });
  }
}

/** Will a declarativeNetRequest rule already redirect this URL? */
async function handledByRules(url, verdict) {
  if (verdict.source !== 'blocklist') return false;
  const { dnrReady = false } = await chrome.storage.session.get('dnrReady');
  if (!dnrReady) return false;
  const { blocklist, userTrusted } = await loadState();
  return coveredByRules(url, blocklist, userTrusted);
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
  const show = isGated(verdict);
  await chrome.action.setBadgeText({ tabId, text: show ? '!' : '' });
  if (show) {
    await chrome.action.setBadgeBackgroundColor({
      tabId, color: verdict.action === VERDICT.BLOCK ? '#c62828' : '#ef6c00',
    });
  }
}

chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.session.remove(`tab:${tabId}`));

// ---------------------------------------------------------------------------
// Gating

function gateUrl(url) {
  return chrome.runtime.getURL(`${GATE_PAGE}?url=${encodeURIComponent(url)}`);
}

/** Send a tab to the gate page for `url`. */
async function gateTab(tabId, url, verdict) {
  await rememberVerdict(tabId, url, verdict);
  // Several gates can fire for one navigation (onBeforeNavigate, then the
  // content script's document_start check); don't reload the gate page.
  const target = gateUrl(url);
  const tab = await chrome.tabs.get(tabId).catch(() => null);
  if (tab && (tab.pendingUrl || tab.url) === target) return;
  await chrome.tabs.update(tabId, { url: target });
}

/**
 * Open `url` the way the user asked (same tab, new tab, background tab or new
 * window), or the gate page in its place.
 */
async function openAs(disposition, url, sender) {
  const tab = sender.tab;
  if (disposition === 'window') return chrome.windows.create({ url });
  return chrome.tabs.create({
    url,
    active: disposition !== 'background',
    openerTabId: tab?.id,
    index: tab ? tab.index + 1 : undefined,
  });
}

// Typed addresses, bookmarks, script/meta redirects, window.open, links the
// content script didn't see.
chrome.webNavigation.onBeforeNavigate.addListener(async ({ tabId, frameId, url }) => {
  if (frameId !== 0 || !/^https?:/.test(url)) return;
  const verdict = await evaluate(url);
  if (!isGated(verdict) || await handledByRules(url, verdict)) return;
  await gateTab(tabId, url, verdict);
});

// Server-side redirects (302 etc.) don't fire onBeforeNavigate for the new
// address.
chrome.webRequest.onBeforeRedirect.addListener(async ({ tabId, redirectUrl }) => {
  if (tabId < 0 || !/^https?:/.test(redirectUrl)) return;
  const verdict = await evaluate(redirectUrl);
  if (!isGated(verdict) || await handledByRules(redirectUrl, verdict)) return;
  await gateTab(tabId, redirectUrl, verdict);
}, { urls: ['<all_urls>'], types: ['main_frame'] });

// ---------------------------------------------------------------------------
// Messages from the content script, gate page and popup.

function fromExtensionPage(sender) {
  return !sender.tab || String(sender.url).startsWith(chrome.runtime.getURL(''));
}

const handlers = {
  // Content script, at document_start: should this page be showing at all?
  async checkPage(msg, sender) {
    if (!sender.tab || sender.frameId !== 0) return { gated: false };
    const verdict = await evaluate(sender.url);
    if (!isGated(verdict)) return { gated: false };
    await gateTab(sender.tab.id, sender.url, verdict);
    return { gated: true };
  },

  // Content script: decisions for the links on a page, so clicks on links
  // already known to be safe aren't held up.
  async screenUrls(msg) {
    const urls = (msg.urls || []).slice(0, MAX_SCREEN_URLS);
    const decisions = {};
    const allowed = await sessionAllowed();
    for (const url of urls) {
      const verdict = await evaluate(url, undefined, allowed);
      decisions[url] = verdict.overridden ? VERDICT.ALLOW : verdict.action;
    }
    return { decisions };
  },

  // Content script: the user activated a link to `url`. Allowed same-tab
  // navigations are performed by the content script; everything else is
  // opened (or gated) here.
  async checkNavigation(msg, sender) {
    if (!sender.tab) return { allow: false };
    const { url } = msg;
    const disposition = ['same', 'tab', 'background', 'window'].includes(msg.disposition) ? msg.disposition : 'same';
    if (!/^https?:/.test(url)) return { allow: false };
    const verdict = await evaluate(url);
    if (!isGated(verdict)) {
      if (disposition === 'same') return { allow: true };
      await openAs(disposition, url, sender);
      return { allow: true, handled: true };
    }
    if (disposition === 'same') {
      await gateTab(sender.tab.id, url, verdict);
    } else {
      await openAs(disposition, gateUrl(url), sender);
    }
    return { allow: false, handled: true };
  },

  // Content script, once the page has loaded (and again if it changes).
  async analyzePage(msg, sender) {
    if (!sender.tab || sender.frameId !== 0) return null;
    // Judge the URL the browser reports for this frame, not one the page claims.
    const url = sender.url;
    const verdict = await evaluate(url, { ...msg.features, url });
    await rememberVerdict(sender.tab.id, url, verdict);
    return { verdict, text: describe(verdict) };
  },

  // Gate page: why was this URL gated?
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
