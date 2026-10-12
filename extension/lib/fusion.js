// Combine tiers into a verdict. Hard rules (trusted / blocklisted) always win;
// heuristic scores are combined with noisy-OR and compared to thresholds.
// `applyModel` then folds in the Tier 3 decision model (Jev) when available.

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
 * @property {'trusted'|'blocklist'|'heuristics'|'model'} source
 * @property {'credential_phish'|'tech_support_scam'|'payment_scam'|'fake_shop'|'suspicious_site'|null} category
 * @property {string|undefined} brand     brand being impersonated, if any
 * @property {{code:string, weight:number, detail?:string}[]} reasons
 * @property {string} domain              registrable domain the verdict is for
 * @property {number} [heuristicRisk]      Tiers 1-2 risk, when a model result was applied
 * @property {ModelResult} [model]         Tier 3 output, when available
 */

/**
 * Tier 3 output, as returned by the backend's POST /classify.
 * @typedef {Object} ModelResult
 * @property {number} p_phish                 P(page is trying to trick the user)
 * @property {'credential_phish'|'tech_support_scam'|'fake_shop'|'gift_card_or_payment_scam'|'impersonation_other'|'benign'} category
 * @property {number} category_confidence
 * @property {number|null} pressure          0 (calm) .. 3 (threats / countdowns)
 * @property {string} model                  resolved model version
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

// Fusion of heuristics with the decision model: a weighted average, so the
// model can both raise and lower risk. With these weights the model alone
// (heuristic risk 0) can WARN but never BLOCK; blocking needs both to agree.
export const MODEL_WEIGHTS = { heuristics: 0.35, model: 0.65 };

// Below this confidence the model's category isn't used for the warning text.
const MIN_CATEGORY_CONFIDENCE = 0.5;

const MODEL_CATEGORY = {
  credential_phish: 'credential_phish',
  tech_support_scam: 'tech_support_scam',
  gift_card_or_payment_scam: 'payment_scam',
  fake_shop: 'fake_shop',
  impersonation_other: 'suspicious_site',
};

/**
 * Fold a Tier 3 result into a heuristics verdict. Hard-rule verdicts
 * (trusted, blocklist) are returned unchanged: the model can never block an
 * allowlisted site or clear a blocklisted one. Nor can it fully clear a page
 * the heuristics alone would block; it can only lower that to a warning.
 * @param {Verdict} verdict
 * @param {ModelResult|null|undefined} result
 * @returns {Verdict}
 */
export function applyModel(verdict, result) {
  if (verdict.source !== 'heuristics' || !result || !Number.isFinite(result.p_phish)) return verdict;
  const h = verdict.risk;
  const p = Math.min(Math.max(result.p_phish, 0), 1);
  let risk = MODEL_WEIGHTS.heuristics * h + MODEL_WEIGHTS.model * p;
  if (h >= THRESHOLDS.block) risk = Math.max(risk, THRESHOLDS.warn);
  risk = Math.round(risk * 1000) / 1000;

  const action = risk >= THRESHOLDS.block ? VERDICT.BLOCK : risk >= THRESHOLDS.warn ? VERDICT.WARN : VERDICT.ALLOW;
  const reasons = [...verdict.reasons];
  if (p >= 0.5) reasons.push({ code: 'model_flagged', weight: p });
  reasons.sort((a, b) => b.weight - a.weight);

  let category = null;
  if (action !== VERDICT.ALLOW) {
    const fromModel = result.category_confidence >= MIN_CATEGORY_CONFIDENCE && MODEL_CATEGORY[result.category];
    category = fromModel || categorize(reasons);
  }
  return {
    ...verdict,
    action,
    risk,
    source: 'model',
    category,
    reasons,
    heuristicRisk: h,
    model: result,
  };
}
