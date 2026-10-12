// Tier 3 input: a compact, privacy-stripped summary of a page that is sent to
// the backend (and from there to Jev). Never includes typed form values,
// cookies, query strings or fragments. Text is redacted and truncated.
// The backend imports this module too and re-applies `sanitizeSummary`, so
// the rules are enforced on both sides.

import { normalizeHost, registrableDomain } from './domain.js';

export const LIMITS = {
  title: 200,
  siteName: 100,
  path: 120,
  text: 1500,
  identity: 6,
  identityText: 120,
  forms: 5,
  reasons: 12,
};

const EMAIL_RE = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
const PHONE_RE = /(?:\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b/g;
// Runs of 6+ digits, optionally broken up by spaces/dashes (card, account, SSN numbers).
const DIGITS_RE = /\d(?:[\s-]?\d){5,}/g;
const SSN_RE = /\b\d{3}-\d{2}-\d{4}\b/g;
const URL_QUERY_RE = /(https?:\/\/[^\s?#]+)[?#]\S*/gi;

/** Remove personal details from free text. */
export function redactText(text) {
  return String(text ?? '')
    .replace(URL_QUERY_RE, '$1')
    .replace(EMAIL_RE, '[email]')
    .replace(SSN_RE, '[number]')
    .replace(PHONE_RE, '[phone]')
    .replace(DIGITS_RE, '[number]')
    .replace(/\s+/g, ' ')
    .trim();
}

function clip(text, max) {
  const s = redactText(text);
  return s.length > max ? s.slice(0, max) : s;
}

function redactPath(pathname) {
  // Long opaque segments (tokens, ids) are replaced; words are kept because
  // paths like /signin or /verify-account are a useful signal.
  const segments = String(pathname || '/').split('/').map((seg) => {
    if (seg.length > 24 || /\d{4,}/.test(seg) || /^[A-Za-z0-9_-]{16,}$/.test(seg)) return '*';
    return redactText(seg);
  });
  const out = segments.join('/') || '/';
  return out.length > LIMITS.path ? out.slice(0, LIMITS.path) : out;
}

const FIELD_KINDS = ['password', 'card', 'ssn', 'giftCard', 'otp'];

/**
 * @typedef {Object} PageSummary
 * @property {string} url_host
 * @property {string} url_domain            registrable domain
 * @property {string} url_path              redacted path, no query or fragment
 * @property {boolean} https
 * @property {string|null} claimed_brand
 * @property {string} title
 * @property {string} site_name
 * @property {string[]} identity_texts      logo alt text, top headings
 * @property {string} visible_text_excerpt
 * @property {string[]} sensitive_fields    kinds of sensitive inputs on the page
 * @property {{action_domain:string, has_password:boolean}[]} forms
 * @property {number} phone_numbers
 * @property {boolean} fullscreen
 * @property {string[]} heuristic_reasons
 * @property {number} heuristic_risk
 */

/**
 * Build the summary sent to Tier 3.
 * @param {string} url
 * @param {import('./pageHeuristics.js').PageFeatures} page
 * @param {import('./fusion.js').Verdict} verdict  the Tier 0-2 verdict
 * @returns {PageSummary}
 */
export function buildSummary(url, page, verdict) {
  const u = new URL(url);
  const host = normalizeHost(u.hostname);
  const fields = page.fields || {};
  return sanitizeSummary({
    url_host: host,
    url_domain: registrableDomain(host),
    url_path: u.pathname,
    https: u.protocol === 'https:',
    claimed_brand: verdict.brand ?? null,
    title: page.title,
    site_name: page.siteName,
    identity_texts: page.identityTexts,
    visible_text_excerpt: page.text,
    sensitive_fields: FIELD_KINDS.filter((k) => fields[k] > 0),
    forms: (page.forms || []).map((f) => ({
      action_domain: registrableDomain(normalizeHost(f.actionHost || host)),
      has_password: !!f.hasPassword,
    })),
    phone_numbers: page.phoneNumbers,
    fullscreen: page.fullscreen,
    heuristic_reasons: (verdict.reasons || []).map((r) => r.code),
    heuristic_risk: verdict.risk,
  });
}

/**
 * Coerce an untrusted object into a valid, redacted PageSummary. Throws on
 * input that can't be a summary (missing host).
 * @returns {PageSummary}
 */
export function sanitizeSummary(s) {
  if (!s || typeof s !== 'object') throw new TypeError('summary must be an object');
  const host = normalizeHost(String(s.url_host || ''));
  if (!host || host.length > 253 || !/^[a-z0-9.\-\[\]:\u0080-￿]+$/i.test(host)) {
    throw new TypeError('summary.url_host is invalid');
  }
  const str = (v, max) => clip(typeof v === 'string' ? v : '', max);
  const num = (v, lo, hi) => (Number.isFinite(v) ? Math.min(Math.max(v, lo), hi) : lo);
  const list = (v) => (Array.isArray(v) ? v : []);
  return {
    url_host: host,
    url_domain: registrableDomain(host),
    url_path: redactPath(typeof s.url_path === 'string' ? s.url_path.split(/[?#]/)[0] : '/'),
    https: !!s.https,
    claimed_brand: s.claimed_brand ? str(s.claimed_brand, 60) : null,
    title: str(s.title, LIMITS.title),
    site_name: str(s.site_name, LIMITS.siteName),
    identity_texts: list(s.identity_texts).map((t) => str(t, LIMITS.identityText)).filter(Boolean)
      .slice(0, LIMITS.identity),
    visible_text_excerpt: str(s.visible_text_excerpt, LIMITS.text),
    sensitive_fields: list(s.sensitive_fields).filter((k) => FIELD_KINDS.includes(k)),
    forms: list(s.forms).slice(0, LIMITS.forms).map((f) => ({
      action_domain: registrableDomain(normalizeHost(String(f?.action_domain || host))).slice(0, 253),
      has_password: !!f?.has_password,
    })),
    phone_numbers: Math.round(num(s.phone_numbers, 0, 99)),
    fullscreen: !!s.fullscreen,
    heuristic_reasons: list(s.heuristic_reasons).filter((c) => typeof c === 'string' && /^[a-z_]{1,48}$/.test(c))
      .slice(0, LIMITS.reasons),
    heuristic_risk: num(s.heuristic_risk, 0, 1),
  };
}
