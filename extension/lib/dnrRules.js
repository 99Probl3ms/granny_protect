// Turn the blocklist into declarativeNetRequest rules, so Chrome redirects
// known scam sites to our block page before any request leaves the browser.
//
// - Listed hosts go into a few rules using `requestDomains` (which also
//   matches subdomains), chunked to keep each rule a reasonable size.
// - Exact-URL entries on shared hosts (one bad Google Form) get a regex rule
//   each. Chrome allows at most 1000 regex rules, so these are capped; the
//   webNavigation check in background.js still covers anything left over.
//
// Every rule is a regex rule so the original URL can be passed to the block
// page in its fragment: blocked.html#https://bad.example/path?x=1

import { hostMatches, normalizeHost } from './domain.js';

export const BLOCK_RULE_PRIORITY = 1;
export const ALLOW_RULE_PRIORITY = 2;
export const DOMAINS_PER_RULE = 1000;
// Leave headroom under Chrome's 1000-regex-rule limit for the host rules.
export const MAX_URL_RULES = 900;

const HOST_RE = /^[a-z0-9.-]+$/;

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Is `host` or one of its parent domains in `set`? */
function inHostSet(host, set) {
  const labels = normalizeHost(host).split('.');
  for (let i = 0; i < labels.length - 1; i++) if (set.has(labels.slice(i).join('.'))) return true;
  return false;
}

/** Hosts and exact URLs from the blocklist, minus anything the user trusts. */
function entries(blocklist, userTrusted) {
  const trusted = (host) => userTrusted.some((d) => hostMatches(host, d));
  const hosts = [...blocklist.hosts].filter((h) => HOST_RE.test(h) && !trusted(h));
  const hostSet = new Set(hosts);
  const coveredByHost = (host) => inHostSet(host, hostSet);
  const urls = [];
  for (const u of blocklist.urls) {
    const host = u.split('/')[0];
    if (!HOST_RE.test(host) || trusted(host) || coveredByHost(host)) continue;
    urls.push(u);
    if (urls.length >= MAX_URL_RULES) break;
  }
  return { hosts, hostSet, urls };
}

/**
 * @param {{urls:Set<string>, hosts:Set<string>}} blocklist  from buildBlocklist()
 * @param {string} blockPageUrl  chrome.runtime.getURL('interstitial/blocked.html')
 * @param {string[]} [userTrusted]
 * @returns {chrome.declarativeNetRequest.Rule[]}
 */
export function buildBlockRules(blocklist, blockPageUrl, userTrusted = []) {
  const { hosts, urls } = entries(blocklist, userTrusted);
  const redirect = {
    type: 'redirect',
    redirect: { regexSubstitution: `${blockPageUrl}#\\0` },
  };
  const rules = [];
  let id = 1;

  for (let i = 0; i < hosts.length; i += DOMAINS_PER_RULE) {
    rules.push({
      id: id++,
      priority: BLOCK_RULE_PRIORITY,
      action: redirect,
      condition: {
        regexFilter: '^https?://.*',
        requestDomains: hosts.slice(i, i + DOMAINS_PER_RULE),
        resourceTypes: ['main_frame'],
      },
    });
  }

  for (const u of urls) {
    const slash = u.indexOf('/');
    const host = slash < 0 ? u : u.slice(0, slash);
    const path = slash < 0 ? '' : u.slice(slash);
    rules.push({
      id: id++,
      priority: BLOCK_RULE_PRIORITY,
      action: redirect,
      condition: {
        regexFilter: `^https?://(www\\.)?${escapeRegex(host)}(:[0-9]+)?${escapeRegex(path)}/*([?#].*)?$`,
        resourceTypes: ['main_frame'],
      },
    });
  }
  return rules;
}

/**
 * Would the rules from buildBlockRules() redirect this URL? Used so the
 * webNavigation fallback doesn't redirect a second time.
 */
export function coveredByRules(url, blocklist, userTrusted = []) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  const { hostSet, urls } = entries(blocklist, userTrusted);
  const host = normalizeHost(u.hostname);
  if (inHostSet(host, hostSet)) return true;
  const norm = `${host}${u.pathname.replace(/\/+$/, '')}`;
  return urls.includes(norm);
}

/** Session rule that lets the user through to a domain they chose to visit. */
export function allowRule(id, domain) {
  return {
    id,
    priority: ALLOW_RULE_PRIORITY,
    action: { type: 'allow' },
    condition: { requestDomains: [domain], resourceTypes: ['main_frame'] },
  };
}
