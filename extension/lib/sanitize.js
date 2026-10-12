// Build the minimal, sanitized context sent for remote review (Jev).
//
// Sent: the destination's scheme and host (plus its unicode form), a redacted
// path, the local decision's signal codes and any impersonated brand, and,
// for a loaded page, a redacted text summary. Never sent: query strings,
// fragments, user:password@ parts, typed form values, cookies, or long
// identifiers, numbers and email addresses found in paths or text.

import { registrableDomain, toUnicodeHost, normalizeHost } from './domain.js';

// Full destination identity stays on-device and is never serialized for review.
const destinations = new WeakMap();

export const LIMITS = { path: 120, title: 200, text: 1500, identity: 5 };

const EMAIL_RE = /[^\s@/]+@[^\s@/]+\.[a-z]{2,}/gi;
const IS_EMAIL = /[^\s@/]+@[^\s@/]+\.[a-z]{2,}/i;
const PHONE_RE = /(?:\+?\d[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b/g;
const DIGITS_RE = /\d{5,}/g;
// Long runs of letters+digits look like tokens, session ids, reset codes.
const TOKEN_RE = /\b(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{16,}\b/g;
// File types that say "this is a program or a container for one". Kept even
// when the rest of a path segment is redacted or the path is cut short: the
// type is the strongest signal in a download link and identifies no one.
const FILE_TYPE_RE = /\.(exe|msi|msix|msixbundle|appx|scr|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|lnk|dll|jar|apk|dmg|pkg|deb|rpm|sh|py|bin|elf|zip|rar|7z|gz|tgz|xz|tar|iso|img|vhd|docm|xlsm|pptm|one)$/i;
const fileType = (s) => s.match(FILE_TYPE_RE)?.[0] || '';

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
    // Decode once before matching personal data. Drop malformed or
    // double-encoded segments rather than forward a hidden identifier.
    let s;
    try {
      s = decodeURIComponent(seg);
    } catch {
      return `[id]${fileType(seg)}`;
    }
    if (s.includes('%')) return `[id]${fileType(s)}`;
    if (IS_EMAIL.test(s)) return '[email]';
    return s.replace(TOKEN_RE, '[id]').replace(PHONE_RE, '[phone]').replace(DIGITS_RE, '[number]');
  });
  const path = segments.join('/');
  if (path.length <= LIMITS.path) return path;
  const type = fileType(segments.at(-1));
  return `${path.slice(0, LIMITS.path - type.length)}…${type}`;
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
  destinations.set(request, u.href);
  return request;
}

/** Cache only identical evidence and destinations. The key never leaves the device. */
export function reviewKey(request) {
  return JSON.stringify([destinations.get(request) ?? null, request]);
}
