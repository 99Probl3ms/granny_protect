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

import { isInternalHost, normalizeHost } from './domain.js';
import { BUILTIN_TRUSTED, isTrusted } from './lists.js';

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
  const trusted = (host) => isInternalHost(host) || isTrusted(host, userTrusted);
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
  const excludedRequestDomains = [...new Set([...BUILTIN_TRUSTED, ...userTrusted]
    .map(normalizeHost).filter((host) => HOST_RE.test(host) && isTrusted(host, userTrusted)))];
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
        excludedRequestDomains,
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
        isUrlFilterCaseSensitive: true,
        regexFilter: `^https?://(www\\.)?${escapeRegex(host)}(:[0-9]+)?${escapeRegex(path)}/*([?#].*)?$`,
        resourceTypes: ['main_frame'],
      },
    });
  }
  return rules;
}

/**
 * Chrome limits compiled regex memory, not pattern length. Ask its RE2
 * compiler before the atomic update so one rejected URL cannot invalidate
 * every host rule. Capture support is needed for the redirect's \0.
 */
export async function supportedBlockRules(rules, isRegexSupported) {
  const addRules = [];
  const skippedRuleIds = [];
  const support = new Map();
  for (const rule of rules) {
    const regex = rule.condition.regexFilter;
    const isCaseSensitive = rule.condition.isUrlFilterCaseSensitive ?? false;
    const key = JSON.stringify([regex, isCaseSensitive]);
    let supported = support.get(key);
    if (supported === undefined) {
      const result = await isRegexSupported({
        regex,
        isCaseSensitive,
        requireCapturing: true,
      });
      supported = result.isSupported;
      support.set(key, supported);
    }
    if (supported) addRules.push(rule);
    else skippedRuleIds.push(rule.id);
  }
  return { addRules, skippedRuleIds };
}

/**
 * Would the rules from buildBlockRules() redirect this URL? Used so the
 * webNavigation fallback doesn't redirect a second time. Compiler-rejected
 * rules are excluded so their destinations still use the fallback.
 */
export function coveredByRules(url, blocklist, userTrusted = [], skippedRuleIds = []) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  const { hosts, hostSet, urls } = entries(blocklist, userTrusted);
  const skipped = new Set(skippedRuleIds);
  const host = normalizeHost(u.hostname);
  if (isInternalHost(host) || isTrusted(host, userTrusted)) return false;
  if (inHostSet(host, hostSet) && hosts.some((domain, index) =>
    (host === domain || host.endsWith('.' + domain)) &&
    !skipped.has(Math.floor(index / DOMAINS_PER_RULE) + 1))) return true;
  const norm = `${host}${u.pathname.replace(/\/+$/, '')}`;
  const index = urls.indexOf(norm);
  return index >= 0 && !skipped.has(Math.ceil(hosts.length / DOMAINS_PER_RULE) + index + 1);
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
