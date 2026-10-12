// Build the minimal, sanitized context sent for remote review (Jev).
//
// Sent: the destination's scheme and host (plus its unicode form), a redacted
// path, the local decision's signal codes and any impersonated brand, and,
// for a loaded page, a redacted text summary. Never sent: query strings,
// fragments, user:password@ parts, typed form values, cookies, or long
// identifiers, numbers and email addresses found in paths or text.

import { registrableDomain, toUnicodeHost, normalizeHost } from './domain.js';

export const LIMITS = { path: 120, title: 200, text: 1500, identity: 5 };

const EMAIL_RE = /[^\s@/]+@[^\s@/]+\.[a-z]{2,}/gi;
const IS_EMAIL = /[^\s@/]+@[^\s@/]+\.[a-z]{2,}/i;
const PHONE_RE = /(?:\+?\d[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b/g;
const DIGITS_RE = /\d{5,}/g;
// Long runs of letters+digits look like tokens, session ids, reset codes.
const TOKEN_RE = /\b(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{16,}\b/g;

/** Redact personal data and identifiers from free text. */
export function redactText(text, max) {
  const out = String(text || '')
    .replace(EMAIL_RE, '[email]')
    .replace(TOKEN_RE, '[id]')
    .replace(PHONE_RE, '[phone]')
    .replace(DIGITS_RE, '[number]')
    .replace(/\s+/g, ' ')
    .trim();
  return out.length > max ? `${out.slice(0, max)}…` : out;
}

/** Path with identifiers redacted, no query or fragment. */
export function redactPath(pathname) {
  const segments = String(pathname || '/').split('/').map((seg) => {
    let s = seg;
    try {
      s = decodeURIComponent(seg);
    } catch { /* keep as is */ }
    if (IS_EMAIL.test(s)) return '[email]';
    return s.replace(TOKEN_RE, '[id]').replace(DIGITS_RE, '[number]');
  });
  const path = segments.join('/');
  return path.length > LIMITS.path ? `${path.slice(0, LIMITS.path)}…` : path;
}

/**
 * @param {string} url
 * @param {import('./fusion.js').Verdict} verdict  the local decision
 * @param {import('./pageHeuristics.js').PageFeatures} [page]
 */
export function buildReviewRequest(url, verdict, page) {
  const u = new URL(url);
  const host = normalizeHost(u.hostname);
  const request = {
    destination: {
      scheme: u.protocol.replace(':', ''),
      host,
      hostUnicode: toUnicodeHost(host),
      registrableDomain: registrableDomain(host),
      path: redactPath(u.pathname),
    },
    local: {
      decision: verdict.action,
      risk: verdict.risk,
      signals: (verdict.reasons || []).map((r) => r.code),
      brand: verdict.brand || null,
    },
  };
  if (page) {
    request.page = {
      title: redactText(page.title, LIMITS.title),
      siteName: redactText(page.siteName, LIMITS.title),
      identity: (page.identityTexts || []).slice(0, LIMITS.identity).map((t) => redactText(t, LIMITS.title)),
      text: redactText(page.text, LIMITS.text),
      fields: { ...page.fields },
      formTargets: [...new Set((page.forms || []).map((f) => normalizeHost(f.actionHost)).filter(Boolean))],
    };
  }
  return request;
}

/** Cache key: what the request is about, never the raw URL. */
export function reviewKey(request) {
  const d = request.destination;
  return `${request.page ? 'page' : 'url'}:${d.scheme}://${d.host}${d.path}`;
}
