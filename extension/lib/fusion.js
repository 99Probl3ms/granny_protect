// Combine tiers into one of three decisions:
//   allow         go ahead
//   needs_review  uncertain: hold the navigation / page until reviewed
//                 (by the user now; by Jev in phase 2)
//   block         known or near-certain scam
// Hard rules (internal, trusted, blocklisted) always win; heuristic scores are
// combined with noisy-OR and compared to thresholds.

import { isInternalHost, normalizeHost, registrableDomain } from './domain.js';
import { isBlocklisted, isTrusted } from './lists.js';
import { analyzePage } from './pageHeuristics.js';
import { noisyOr } from './score.js';
import { analyzeUrl } from './urlHeuristics.js';

export const THRESHOLDS = { block: 0.85, review: 0.5 };

export const VERDICT = { ALLOW: 'allow', REVIEW: 'needs_review', BLOCK: 'block' };

/**
 * @typedef {Object} Verdict
 * @property {'allow'|'needs_review'|'block'} action
 * @property {number} risk
 * @property {'internal'|'trusted'|'blocklist'|'heuristics'} source
 * @property {'credential_phish'|'tech_support_scam'|'payment_scam'|'suspicious_site'|null} category
 * @property {string|undefined} brand     brand being impersonated, if any
 * @property {{code:string, weight:number, detail?:string}[]} reasons
 * @property {string} domain              registrable domain the verdict is for
 */

/**
 * @param {Object} input
 * @param {string} input.url
 * @param {import('./pageHeuristics.js').PageFeatures} [input.page]  omitted for URL-only decisions
 * @param {string[]} [input.userTrusted]
 * @param {{urls:Set<string>, hosts:Set<string>}} [input.blocklist]
 * @returns {Verdict}
 */
export function decide({ url, page, userTrusted = [], blocklist }) {
  let host = '';
  try {
    const u = new URL(url);
    if (u.protocol === 'http:' || u.protocol === 'https:') host = normalizeHost(u.hostname);
  } catch {
    /* not a URL we judge */
  }
  const domain = registrableDomain(host);
  const base = { domain, brand: undefined, category: null };
  const allow = (source) => ({ ...base, action: VERDICT.ALLOW, risk: 0, source, reasons: [] });

  if (!host) return allow('heuristics');
  if (isInternalHost(host)) return allow('internal');
  if (isTrusted(host, userTrusted)) return allow('trusted');
  if (isBlocklisted(url, blocklist)) {
    return {
      ...base, action: VERDICT.BLOCK, risk: 1, source: 'blocklist', category: 'suspicious_site',
      reasons: [{ code: 'known_phishing_site', weight: 1 }],
    };
  }

  const urlResult = analyzeUrl(url);
  const pageResult = page ? analyzePage(page, { userTrusted }) : { risk: 0, reasons: [] };
  const reasons = [...urlResult.reasons, ...pageResult.reasons].sort((a, b) => b.weight - a.weight);
  const risk = noisyOr([urlResult.risk, pageResult.risk]);

  const action = risk >= THRESHOLDS.block ? VERDICT.BLOCK
    : risk >= THRESHOLDS.review ? VERDICT.REVIEW
      : VERDICT.ALLOW;
  return {
    ...base,
    action,
    risk,
    source: 'heuristics',
    brand: pageResult.brand ?? urlResult.brand,
    category: action === VERDICT.ALLOW ? null : categorize(reasons),
    reasons,
  };
}

/** Decision for a destination before it loads (lists + URL checks only). */
export function decideUrl(url, opts = {}) {
  return decide({ url, ...opts });
}

function categorize(reasons) {
  const codes = new Set(reasons.map((r) => r.code));
  if (codes.has('tech_support_scam_language') || codes.has('tech_support_language')) return 'tech_support_scam';
  if (codes.has('unusual_payment_request') || codes.has('gift_card_code_field')) return 'payment_scam';
  if ([...codes].some((c) => /brand|password|secrets|ssn|card_field|one_time/.test(c))) return 'credential_phish';
  return 'suspicious_site';
}
