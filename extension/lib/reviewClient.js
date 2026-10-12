// Client for the review service (the local proxy in server/, later the
// on-prem Jev endpoint). Only destinations whose local decision is
// needs_review are sent.
//
// Guarantees:
//  - a response is used only if it validates; anything else is "unavailable"
//  - every call finishes within `timeoutMs` (then "unavailable")
//  - identical requests in flight share one network call
//  - results are cached for `ttlMs` (failures are not cached)
// On "unavailable" the caller keeps the local decision (needs_review stays
// gated), so a slow or broken service never lets a destination through.

import { reviewKey } from './sanitize.js';

export const DECISIONS = ['allow', 'needs_review', 'block'];
export const CATEGORIES = ['credential_phish', 'tech_support_scam', 'payment_scam', 'malware_download', 'suspicious_site'];

/**
 * @typedef {Object} Review
 * @property {'ok'|'unavailable'} status
 * @property {'allow'|'needs_review'|'block'} [decision]
 * @property {number} [confidence]   0..1
 * @property {string|null} [category]
 * @property {string} [model]
 * @property {string} [reason]       why it is unavailable
 * @property {boolean} [cached]
 */

/** Validate a service response; returns a clean Review or null. */
export function validateReview(body) {
  if (!body || typeof body !== 'object') return null;
  const { decision, confidence, category = null, model } = body;
  if (!DECISIONS.includes(decision)) return null;
  if (typeof confidence !== 'number' || !(confidence >= 0 && confidence <= 1)) return null;
  if (category !== null && !CATEGORIES.includes(category)) return null;
  return {
    status: 'ok',
    decision,
    confidence,
    category,
    model: typeof model === 'string' ? model.slice(0, 64) : undefined,
  };
}

/**
 * @param {Object} opts
 * @param {string} opts.endpoint      POST URL of the review service
 * @param {number} [opts.timeoutMs]
 * @param {number} [opts.ttlMs]
 * @param {number} [opts.maxEntries]
 * @param {typeof fetch} [opts.fetch]
 * @param {() => number} [opts.now]
 */
export function createReviewer({ endpoint, timeoutMs = 1500, ttlMs = 30 * 60 * 1000, maxEntries = 500, fetch: doFetch = fetch, now = Date.now }) {
  const cache = new Map(); // key -> { review, at }
  const pending = new Map(); // key -> Promise<Review>

  async function call(request) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await doFetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(request),
        signal: controller.signal,
        credentials: 'omit',
        cache: 'no-store',
      });
      if (!res.ok) return { status: 'unavailable', reason: `http_${res.status}` };
      const review = validateReview(await res.json().catch(() => null));
      return review || { status: 'unavailable', reason: 'invalid_response' };
    } catch (err) {
      return { status: 'unavailable', reason: err?.name === 'AbortError' ? 'timeout' : 'network_error' };
    } finally {
      clearTimeout(timer);
    }
  }

  /** @returns {Promise<Review>} */
  async function review(request) {
    const key = reviewKey(request);
    const hit = cache.get(key);
    if (hit && now() - hit.at < ttlMs) return { ...hit.review, cached: true };
    if (pending.has(key)) return pending.get(key);

    const p = call(request).then((result) => {
      pending.delete(key);
      if (result.status === 'ok') {
        cache.set(key, { review: result, at: now() });
        if (cache.size > maxEntries) cache.delete(cache.keys().next().value);
      }
      return result;
    });
    pending.set(key, p);
    return p;
  }

  /** A cached review only: never calls the service. */
  function peek(request) {
    const hit = cache.get(reviewKey(request));
    return hit && now() - hit.at < ttlMs ? { ...hit.review, cached: true } : null;
  }

  return { review, peek, _cache: cache, _pending: pending };
}

/**
 * Combine the local needs_review decision with a review. Only a validated,
 * confident review changes it; otherwise the destination stays gated.
 * @param {import('./fusion.js').Verdict} local
 * @param {Review} review
 * @param {{minConfidence?: number}} [opts]
 */
export function applyReview(local, review, { minConfidence = 0.8 } = {}) {
  if (local.action !== 'needs_review' || local.policy) return local;
  if (review?.status !== 'ok' || review.confidence < minConfidence || review.decision === 'needs_review') {
    return { ...local, review: { status: review?.status || 'unavailable', reason: review?.reason, decision: review?.decision } };
  }
  const reasons = review.decision === 'block'
    ? [{ code: 'remote_review_block', weight: review.confidence }, ...(local.reasons || [])]
    : local.reasons;
  return {
    ...local,
    action: review.decision,
    reasons,
    source: 'review',
    category: review.decision === 'allow' ? null : (review.category || local.category),
    review: { status: 'ok', decision: review.decision, confidence: review.confidence, model: review.model },
  };
}
