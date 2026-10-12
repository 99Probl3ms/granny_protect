// Tier 1: signals from the URL alone. Runs before the page loads.

import { BRANDS } from './brands.js';
import {
  domainLabel, hostMatches, isIpHost, normalizeHost, publicSuffix,
  registrableDomain, subdomainLabels, toUnicodeHost,
} from './domain.js';
import { RISKY_TLDS, isShortener, isUserContentHost } from './lists.js';
import { noisyOr } from './score.js';

// Brand keywords that are ordinary words, or short enough to appear inside
// unrelated names. They only count as an exact hostname token, never as a
// substring or near-miss spelling.
export const COMMON_BRAND_WORDS = new Set([
  'apple', 'windows', 'outlook', 'meta', 'chase', 'discover', 'spectrum', 'citi',
  'ups', 'att', 'irs', 'ssa', 'pnc', 'aol', 'msn', 'amex', 'bofa', 'dhl', 'usps',
  'ebay', 'norton', 'venmo', 'zelle', 'google', 'gmail',
]);

// Latin look-alikes from other scripts, plus digit swaps used in typosquats.
const CONFUSABLES = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j',
  'ѕ': 's', 'һ': 'h', 'ԁ': 'd', 'ɡ': 'g', 'ӏ': 'l', 'ո': 'n', 'ս': 'u', 'ᴠ': 'v', 'ԝ': 'w',
  'α': 'a', 'ο': 'o', 'ρ': 'p', 'ν': 'v', 'ι': 'i', 'κ': 'k', 'τ': 't', 'ε': 'e',
  'ı': 'i', 'ł': 'l', 'ß': 'b', 'à': 'a', 'á': 'a', 'â': 'a', 'ä': 'a', 'å': 'a', 'é': 'e',
  'è': 'e', 'ê': 'e', 'ë': 'e', 'í': 'i', 'ì': 'i', 'ï': 'i', 'ó': 'o', 'ò': 'o', 'ô': 'o',
  'ö': 'o', 'ú': 'u', 'ù': 'u', 'ü': 'u', 'ñ': 'n', 'ç': 'c',
};
const DIGIT_SWAPS = { '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b' };

/** Collapse look-alike characters so "pаypa1" and "paypal" compare equal. */
export function skeleton(text) {
  let out = '';
  for (const ch of String(text).toLowerCase()) out += CONFUSABLES[ch] ?? DIGIT_SWAPS[ch] ?? ch;
  return out.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/-/g, '');
}

export function levenshtein(a, b) {
  if (a === b) return 0;
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let diag = prev[0];
    prev[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = prev[j];
      prev[j] = Math.min(prev[j] + 1, prev[j - 1] + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1));
      diag = tmp;
    }
  }
  return prev[b.length];
}

/** Is `host` one of the brand's own domains? */
export function isBrandHost(brand, host) {
  return brand.domains.some((d) => hostMatches(host, d));
}

/** Split a host into word tokens: "secure-paypal.com.verify.xyz" -> [secure, paypal, com, verify, xyz]. */
function hostTokens(host) {
  return host.split(/[.\-_]/).filter(Boolean);
}

const SUSPICIOUS_HOST_WORDS = [
  'login', 'signin', 'sign-in', 'logon', 'verify', 'verification', 'secure', 'security',
  'account', 'update', 'confirm', 'unlock', 'suspended', 'support', 'helpdesk', 'billing',
  'wallet', 'recovery', 'refund', 'invoice', 'webscr', 'authenticate', 'auth',
];

/**
 * @param {string} url
 * @returns {{risk: number, reasons: {code: string, weight: number, detail?: string}[], brand?: string}}
 */
export function analyzeUrl(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return { risk: 0, reasons: [] };
  }
  if (!['http:', 'https:'].includes(u.protocol)) return { risk: 0, reasons: [] };

  const host = normalizeHost(u.hostname);
  const reasons = [];
  const add = (code, weight, detail) => reasons.push({ code, weight, detail });
  let brandHit;

  if (u.protocol === 'http:' && !['localhost', '127.0.0.1'].includes(host)) add('not_https', 0.1);

  if (isIpHost(host)) {
    add('ip_address_host', 0.35);
    return finish(reasons);
  }

  // "https://paypal.com@evil.example/" really goes to evil.example.
  if (u.username || u.password) add('credentials_in_url', 0.3);

  const unicodeHost = toUnicodeHost(host);
  const hasNonAscii = /[^\x00-\x7f]/.test(unicodeHost);
  if (hasNonAscii) add('non_ascii_domain', 0.25, unicodeHost);

  const label = domainLabel(host);
  const unicodeLabel = domainLabel(unicodeHost);
  const reg = registrableDomain(host);
  const subs = subdomainLabels(host);
  const tokens = hostTokens(host);

  for (const brand of BRANDS) {
    if (isBrandHost(brand, host)) continue;

    for (const kw of brand.keywords) {
      // 1. Look-alike: the registrable label spells the brand once look-alike
      //    characters are collapsed, but isn't literally the brand.
      if (skeleton(unicodeLabel) === kw && unicodeLabel !== kw) {
        add('lookalike_brand_domain', 0.75, brand.name);
        brandHit ??= brand.name;
        break;
      }
      // 2. Near-miss spelling of a distinctive brand ("paypall", "amazom").
      if (!COMMON_BRAND_WORDS.has(kw) && kw.length >= 6 && label !== kw) {
        const d = levenshtein(skeleton(label), kw);
        if (d > 0 && d <= (kw.length >= 9 ? 2 : 1)) {
          add('typosquat_brand_domain', 0.6, brand.name);
          brandHit ??= brand.name;
          break;
        }
      }
      // 3. Brand name used somewhere in a host the brand doesn't own
      //    ("paypal.com.secure-login.xyz", "amazon-refunds.net").
      const inTokens = tokens.includes(kw);
      const inSubstring = !COMMON_BRAND_WORDS.has(kw) && kw.length >= 5 && host.includes(kw);
      if (inTokens || inSubstring) {
        add('brand_in_unrelated_domain', subs.some((s) => s.includes(kw)) ? 0.5 : 0.4, brand.name);
        brandHit ??= brand.name;
        break;
      }
    }
  }

  // A brand's own registrable domain sitting in the subdomain of another one:
  // "www.paypal.com.account-check.io".
  if (subs.length && /(^|\.)(com|net|org)(\.|$)/.test(subs.join('.'))) {
    add('domain_in_subdomain', 0.3);
  }

  const tld = publicSuffix(host).split('.').pop();
  if (RISKY_TLDS.has(tld)) add('risky_tld', 0.15, tld);
  if (isShortener(host)) add('url_shortener', 0.1);
  if (isUserContentHost(host)) add('free_hosting', 0.2, reg);
  if (subs.length >= 3) add('many_subdomains', 0.15, String(subs.length));
  if (host.length > 45) add('long_hostname', 0.1);
  if ((host.match(/-/g) || []).length >= 3) add('many_hyphens', 0.1);

  const susWords = SUSPICIOUS_HOST_WORDS.filter((w) => host.includes(w));
  if (susWords.length) add('suspicious_words_in_domain', susWords.length > 1 ? 0.2 : 0.1, susWords.join(','));

  return finish(reasons, brandHit);
}

function finish(reasons, brand) {
  return { risk: noisyOr(reasons.map((r) => r.weight)), reasons, brand };
}
