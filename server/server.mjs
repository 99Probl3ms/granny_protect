// Review service: the only place that talks to Jev and holds its API key.
// The extension posts sanitized review requests here (see
// extension/lib/sanitize.js); later this address points at the on-prem
// deployment instead.
//
//   TYPESAFE_API_KEY=... node server/server.mjs      # listens on 127.0.0.1:8787
//
// POST /review   body: review request   ->  200 {decision, confidence, category, model}
//                                            400 invalid request
//                                            503 model unavailable / not configured
//                                            504 model timed out
// GET  /health   ->  200 {ok, model, configured}

import http from 'node:http';
import { redactPath, redactText, LIMITS } from '../extension/lib/sanitize.js';
import { CATEGORIES, DECISIONS, validateReview } from '../extension/lib/reviewClient.js';
import { createJevModel } from './models/jev.mjs';

const MAX_BODY = 32 * 1024;
const HOST_RE = /^[a-z0-9.-]{1,253}$/;

/**
 * Re-check and re-sanitize a request; never trust the client. Returns the
 * clean request or null.
 */
export function cleanRequest(body) {
  const d = body?.destination;
  if (!d || !['http', 'https'].includes(d.scheme) || !HOST_RE.test(String(d.host))) return null;
  const local = body.local || {};
  const clean = {
    destination: {
      scheme: d.scheme,
      host: d.host,
      hostUnicode: redactText(d.hostUnicode || d.host, 253),
      registrableDomain: HOST_RE.test(String(d.registrableDomain)) ? d.registrableDomain : d.host,
      path: redactPath(String(d.path || '/')),
    },
    local: {
      decision: DECISIONS.includes(local.decision) ? local.decision : 'needs_review',
      risk: typeof local.risk === 'number' ? Math.min(Math.max(local.risk, 0), 1) : 0,
      signals: Array.isArray(local.signals) ? local.signals.filter((s) => /^[a-z_]{1,64}$/.test(s)).slice(0, 20) : [],
      brand: typeof local.brand === 'string' ? local.brand.slice(0, 64) : null,
    },
  };
  if (body.page) {
    const p = body.page;
    const f = p.fields || {};
    clean.page = {
      title: redactText(p.title, LIMITS.title),
      siteName: redactText(p.siteName, LIMITS.title),
      identity: (Array.isArray(p.identity) ? p.identity : []).slice(0, LIMITS.identity).map((t) => redactText(t, LIMITS.title)),
      text: redactText(p.text, LIMITS.text),
      fields: Object.fromEntries(['password', 'card', 'ssn', 'giftCard', 'otp'].map((k) => [k, Number(f[k]) || 0])),
      formTargets: (Array.isArray(p.formTargets) ? p.formTargets : []).filter((h) => HOST_RE.test(String(h))).slice(0, 10),
    };
  }
  return clean;
}

/**
 * @param {{model: {name: string, classify: (req) => Promise<object>, configured?: boolean}, modelTimeoutMs?: number}} opts
 */
export function createReviewServer({ model, modelTimeoutMs = 1200 }) {
  const send = (res, status, body) => {
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify(body));
  };

  return http.createServer(async (req, res) => {
    if (req.method === 'GET' && req.url === '/health') {
      send(res, 200, { ok: true, model: model.name, configured: Boolean(model.configured) });
      return;
    }
    if (req.method !== 'POST' || req.url !== '/review') {
      send(res, 404, { error: 'not_found' });
      return;
    }

    let size = 0;
    const chunks = [];
    for await (const chunk of req) {
      size += chunk.length;
      if (size > MAX_BODY) {
        send(res, 413, { error: 'too_large' });
        return;
      }
      chunks.push(chunk);
    }
    let body;
    try {
      body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      send(res, 400, { error: 'invalid_json' });
      return;
    }
    const request = cleanRequest(body);
    if (!request) {
      send(res, 400, { error: 'invalid_request' });
      return;
    }

    let timer;
    try {
      const raw = await Promise.race([
        model.classify(request),
        new Promise((_, reject) => { timer = setTimeout(() => reject(Object.assign(new Error('timeout'), { code: 'timeout' })), modelTimeoutMs); }),
      ]);
      const review = validateReview({ ...raw, model: raw?.model || model.name });
      if (!review) {
        send(res, 503, { error: 'invalid_model_output' });
        return;
      }
      send(res, 200, { decision: review.decision, confidence: review.confidence, category: review.category, model: review.model });
    } catch (err) {
      if (err?.code === 'timeout') send(res, 504, { error: 'model_timeout' });
      else send(res, 503, { error: 'model_unavailable', detail: String(err?.message || err).slice(0, 200) });
    } finally {
      clearTimeout(timer);
    }
  });
}

// Run directly: node server/server.mjs
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT || 8787);
  const server = createReviewServer({ model: createJevModel() });
  server.listen(port, '127.0.0.1', () => {
    console.log(`granny_protect review service on http://127.0.0.1:${port}/review`);
  });
}

export { CATEGORIES };
