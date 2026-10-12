// HTTP handler for the backend, written against the standard Fetch API
// Request/Response so it runs unchanged on Node (server.js) and Cloudflare
// Workers (worker.js).
//
//   POST /classify   { summary: PageSummary }  ->  ModelResult
//   GET  /health

import { sanitizeSummary } from '../../extension/lib/summary.js';

const MAX_BODY_BYTES = 32 * 1024;
const INSTALL_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Fixed-window rate limit per key. In-memory, so per process / isolate. */
export function createRateLimiter({ limit, windowMs, now = Date.now }) {
  const windows = new Map();
  return (key) => {
    const t = now();
    let w = windows.get(key);
    if (!w || t - w.start >= windowMs) {
      if (windows.size > 10000) {
        for (const [k, v] of windows) if (t - v.start >= windowMs) windows.delete(k);
      }
      w = { start: t, count: 0 };
      windows.set(key, w);
    }
    w.count++;
    return w.count <= limit;
  };
}

function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });
}

/**
 * @param {Object} opts
 * @param {import('./decisionModel.js').DecisionModel|null} opts.model  null = Tier 3 off
 * @param {boolean} [opts.disabled]      kill switch: answer 503 {disabled:true}
 * @param {number} [opts.ratePerMinute]  per install
 * @param {(entry:object) => void} [opts.log]  decision log for evaluation (§7)
 * @param {() => number} [opts.now]
 */
export function createHandler({ model, disabled = false, ratePerMinute = 60, log = () => {}, now = Date.now }) {
  const allow = createRateLimiter({ limit: ratePerMinute, windowMs: 60_000, now });
  const off = disabled || !model;

  return async function handle(request) {
    const { pathname } = new URL(request.url);

    if (pathname === '/health' && request.method === 'GET') {
      return json(200, { ok: true, tier3: !off, model: model?.name ?? null });
    }
    if (pathname !== '/classify') return json(404, { error: 'not_found' });
    if (request.method !== 'POST') return json(405, { error: 'method_not_allowed' });
    if (off) return json(503, { error: 'tier3_disabled', disabled: true });

    const installId = request.headers.get('x-install-id') || '';
    if (!INSTALL_ID_RE.test(installId)) return json(400, { error: 'bad_install_id' });
    if (!allow(installId.toLowerCase())) return json(429, { error: 'rate_limited' });

    const declared = Number(request.headers.get('content-length') || 0);
    if (declared > MAX_BODY_BYTES) return json(413, { error: 'too_large' });
    const raw = await request.text();
    if (raw.length > MAX_BODY_BYTES) return json(413, { error: 'too_large' });

    let summary;
    try {
      // Re-apply the redaction and limits: never trust the client to have done it.
      summary = sanitizeSummary(JSON.parse(raw)?.summary);
    } catch {
      return json(400, { error: 'bad_summary' });
    }

    const started = now();
    let result;
    try {
      result = await model.classify(summary);
    } catch (err) {
      log({ ts: new Date(started).toISOString(), error: String(err?.message || err), summary });
      return json(502, { error: 'model_unavailable' });
    }
    const { usage, ...answer } = result;
    log({ ts: new Date(started).toISOString(), ms: now() - started, summary, result: answer, usage });
    return json(200, answer);
  };
}
