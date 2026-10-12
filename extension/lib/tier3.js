// Tier 3 orchestration in the service worker: decides which pages go to the
// decision model, shares in-flight requests, caches results and backs off
// when the backend is down or switched off. Kept free of chrome.* so it can
// be tested in Node.

import { ModelDisabledError } from './apiClient.js';
import { buildSummary } from './summary.js';

const CACHE_SIZE = 200;
const CACHE_TTL_MS = 60 * 60 * 1000;
const ERROR_BACKOFF_MS = 60 * 1000;
const DISABLED_BACKOFF_MS = 10 * 60 * 1000;

/**
 * @param {Object} deps
 * @param {() => Promise<string>} deps.getBackendUrl   '' when Tier 3 is off
 * @param {(summary:object, backendUrl:string) => Promise<import('./fusion.js').ModelResult>} deps.classify
 * @param {boolean} deps.grayZoneOnly
 * @param {{min:number, max:number}} deps.grayZone
 * @param {number} deps.waitMs
 * @param {() => number} [deps.now]
 */
export function createTier3({ getBackendUrl, classify, grayZoneOnly, grayZone, waitMs, now = Date.now }) {
  let activeBackend;
  /** @type {{cache: Map<string, {at:number, promise:Promise<any>}>, pausedUntil: number}} */
  let state = { cache: new Map(), pausedUntil: 0 };

  /** Should this verdict be sent to the model at all? */
  function eligible(verdict) {
    if (verdict.source !== 'heuristics' || !verdict.domain) return false;
    if (!grayZoneOnly) return true;
    return verdict.risk >= grayZone.min && verdict.risk < grayZone.max;
  }

  function lookup(key, { cache }) {
    const hit = cache.get(key);
    if (!hit) return null;
    if (now() - hit.at > CACHE_TTL_MS) {
      cache.delete(key);
      return null;
    }
    cache.delete(key); // refresh LRU position
    cache.set(key, hit);
    return hit.promise;
  }

  function start(key, summary, backendUrl, endpointState) {
    const { cache } = endpointState;
    const promise = classify(summary, backendUrl).catch((err) => {
      cache.delete(key);
      endpointState.pausedUntil = now() + (err instanceof ModelDisabledError ? DISABLED_BACKOFF_MS : ERROR_BACKOFF_MS);
      console.warn('granny_protect: Tier 3 unavailable', err?.message || err);
      return null;
    });
    cache.set(key, { at: now(), promise });
    while (cache.size > CACHE_SIZE) cache.delete(cache.keys().next().value);
    return promise;
  }

  /**
   * Ask the model about a page. Resolves to its result, or null if Tier 3 is
   * off, not needed, failing, or slower than `waitMs` (the request keeps
   * running and is cached for the next check of the same page).
   * @param {string} url
   * @param {import('./pageHeuristics.js').PageFeatures} page
   * @param {import('./fusion.js').Verdict} verdict
   */
  async function ask(url, page, verdict) {
    if (!page || !eligible(verdict)) return null;
    const backendUrl = await getBackendUrl();
    if (backendUrl !== activeBackend) {
      activeBackend = backendUrl;
      state = { cache: new Map(), pausedUntil: 0 };
    }
    if (!backendUrl || now() < state.pausedUntil) return null;

    let summary;
    try {
      summary = buildSummary(url, page, verdict);
    } catch {
      return null;
    }
    const key = JSON.stringify(summary);
    const promise = lookup(key, state) ?? start(key, summary, backendUrl, state);
    let timer;
    const timeout = new Promise((resolve) => { timer = setTimeout(() => resolve(null), waitMs); });
    try {
      return await Promise.race([promise, timeout]);
    } finally {
      clearTimeout(timer);
    }
  }

  return { ask, eligible };
}
