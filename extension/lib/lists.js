// Tier 0: trusted / blocked lists, plus host categories used by the heuristics.

import { allBrandDomains } from './brands.js';
import { POPULAR_DOMAINS } from './trustedDomains.js';
import { hostMatches, normalizeHost, registrableDomain } from './domain.js';

const BUILTIN_TRUSTED = [...new Set([...allBrandDomains(), ...POPULAR_DOMAINS])];

// Hosts where anyone can publish a page. They are never trusted, even when the
// parent domain is (docs.google.com forms are a common phishing vehicle).
// `subOnly` means only subdomains are user content, not the apex itself.
const USER_CONTENT_HOSTS = [
  { domain: 'sites.google.com' }, { domain: 'docs.google.com' }, { domain: 'drive.google.com' },
  { domain: 'forms.gle' }, { domain: 'storage.googleapis.com' }, { domain: 'firebasestorage.googleapis.com' },
  { domain: 'googleusercontent.com' }, { domain: 'forms.office.com' }, { domain: 'sharepoint.com' },
  { domain: '1drv.ms' }, { domain: 'onedrive.live.com' }, { domain: 'dropboxusercontent.com' },
  { domain: 'wordpress.com', subOnly: true }, { domain: 'wixsite.com' }, { domain: 'weebly.com', subOnly: true },
  { domain: 'squarespace.com', subOnly: true }, { domain: 'blogspot.com' }, { domain: 'github.io' },
  { domain: 'gitlab.io' }, { domain: 'netlify.app' }, { domain: 'vercel.app' }, { domain: 'pages.dev' },
  { domain: 'workers.dev' }, { domain: 'web.app' }, { domain: 'firebaseapp.com' }, { domain: 'glitch.me' },
  { domain: 'repl.co' }, { domain: 'replit.app' }, { domain: 'herokuapp.com' }, { domain: 'onrender.com' },
  { domain: 'azurewebsites.net' }, { domain: 'web.core.windows.net' }, { domain: 'blob.core.windows.net' },
  { domain: 'amazonaws.com' }, { domain: 'cloudfront.net' }, { domain: '000webhostapp.com' },
  { domain: 'webflow.io' }, { domain: 'notion.site' }, { domain: 'typedream.app' }, { domain: 'framer.website' },
  { domain: 'ipfs.io' }, { domain: 'dweb.link' }, { domain: 'r2.dev' }, { domain: 'ngrok.io' },
  { domain: 'ngrok-free.app' }, { domain: 'trycloudflare.com' },
];

export const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly',
  'cutt.ly', 'shorturl.at', 'rb.gy', 'tiny.cc', 'bl.ink', 's.id', 'v.gd', 't.ly',
];

// TLDs disproportionately used for phishing (cheap or free registration).
export const RISKY_TLDS = new Set([
  'top', 'xyz', 'icu', 'click', 'link', 'live', 'online', 'site', 'website', 'shop',
  'store', 'buzz', 'rest', 'cfd', 'sbs', 'bond', 'cyou', 'monster', 'quest', 'fun',
  'support', 'help', 'zip', 'mov', 'tk', 'ml', 'ga', 'cf', 'gq', 'cam', 'lol',
  'mom', 'work', 'country', 'kim', 'xin', 'win', 'bid', 'loan', 'date', 'review',
]);

export function isUserContentHost(host) {
  host = normalizeHost(host);
  return USER_CONTENT_HOSTS.some(({ domain, subOnly }) =>
    subOnly ? host.endsWith('.' + domain) : hostMatches(host, domain));
}

export function isShortener(host) {
  return URL_SHORTENERS.some((d) => hostMatches(host, d));
}

/**
 * Is this host trusted? `userTrusted` is the list of domains the user has
 * marked as safe from the popup.
 */
export function isTrusted(host, userTrusted = []) {
  host = normalizeHost(host);
  if (!host || isUserContentHost(host)) return false;
  return [...BUILTIN_TRUSTED, ...userTrusted].some((d) => hostMatches(host, d));
}

// ---------------------------------------------------------------------------
// Blocklist. Feeds (e.g. OpenPhish) list full URLs. We match the exact URL
// (without query/hash) everywhere, and the whole host only when that host is
// not a shared/user-content or trusted host, so one bad Google Form doesn't
// block all of docs.google.com.

export function normalizeUrlForList(url) {
  try {
    const u = new URL(url);
    const path = u.pathname.replace(/\/+$/, '');
    return `${normalizeHost(u.hostname)}${path}`;
  } catch {
    return null;
  }
}

/**
 * Build an index from a list of feed URLs.
 * @returns {{urls: Set<string>, hosts: Set<string>}}
 */
export function buildBlocklist(feedUrls) {
  const urls = new Set();
  const hosts = new Set();
  for (const raw of feedUrls) {
    const line = String(raw).trim();
    if (!line || line.startsWith('#')) continue;
    const withScheme = /^[a-z]+:\/\//i.test(line) ? line : `http://${line}`;
    const norm = normalizeUrlForList(withScheme);
    if (!norm) continue;
    urls.add(norm);
    const host = normalizeHost(new URL(withScheme).hostname);
    if (!isUserContentHost(host) && !isTrusted(host) && !isShortener(host)) hosts.add(host);
  }
  return { urls, hosts };
}

/** @param {{urls: Set<string>, hosts: Set<string>}} blocklist */
export function isBlocklisted(url, blocklist) {
  if (!blocklist) return false;
  const norm = normalizeUrlForList(url);
  if (!norm) return false;
  if (blocklist.urls.has(norm)) return true;
  const host = norm.split('/')[0];
  if (blocklist.hosts.has(host)) return true;
  // Also match the registrable domain for hosts listed with a random subdomain.
  return blocklist.hosts.has(registrableDomain(host));
}
