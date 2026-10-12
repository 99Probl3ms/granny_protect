// Combine tiers into a verdict. Hard rules (trusted / blocklisted) always win;
// heuristic scores are combined with noisy-OR and compared to thresholds.

import { normalizeHost, registrableDomain } from './domain.js';
import { isBlocklisted, isTrusted } from './lists.js';
import { analyzePage } from './pageHeuristics.js';
import { noisyOr } from './score.js';
import { analyzeUrl } from './urlHeuristics.js';

export const THRESHOLDS = { block: 0.85, warn: 0.6 };

export const VERDICT = { ALLOW: 'allow', WARN: 'warn', BLOCK: 'block' };

/**
 * @typedef {Object} Verdict
 * @property {'allow'|'warn'|'block'} action
 * @property {number} risk
 * @property {'trusted'|'blocklist'|'heuristics'} source
 * @property {'credential_phish'|'tech_support_scam'|'payment_scam'|'suspicious_site'|null} category
 * @property {string|undefined} brand     brand being impersonated, if any
 * @property {{code:string, weight:number, detail?:string}[]} reasons
 * @property {string} domain              registrable domain the verdict is for
 */

/**
 * @param {Object} input
 * @param {string} input.url
 * @param {import('./pageHeuristics.js').PageFeatures} [input.page]  omitted before the page loads
 * @param {string[]} [input.userTrusted]
 * @param {{urls:Set<string>, hosts:Set<string>}} [input.blocklist]
 * @returns {Verdict}
 */
export function decide({ url, page, userTrusted = [], blocklist }) {
  let host = '';
  try {
    host = normalizeHost(new URL(url).hostname);
  } catch {
    /* not a URL we judge */
  }
  const domain = registrableDomain(host);
  const base = { domain, brand: undefined, category: null };

  if (!host) return { ...base, action: VERDICT.ALLOW, risk: 0, source: 'heuristics', reasons: [] };

  if (isTrusted(host, userTrusted)) {
    return { ...base, action: VERDICT.ALLOW, risk: 0, source: 'trusted', reasons: [] };
  }
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

  const action = risk >= THRESHOLDS.block ? VERDICT.BLOCK : risk >= THRESHOLDS.warn ? VERDICT.WARN : VERDICT.ALLOW;
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

function categorize(reasons) {
  const codes = new Set(reasons.map((r) => r.code));
  if (codes.has('tech_support_scam_language') || codes.has('tech_support_language')) return 'tech_support_scam';
  if (codes.has('unusual_payment_request') || codes.has('gift_card_code_field')) return 'payment_scam';
  if ([...codes].some((c) => /brand|password|secrets|ssn|card_field|one_time/.test(c))) return 'credential_phish';
  return 'suspicious_site';
}
