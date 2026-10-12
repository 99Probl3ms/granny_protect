// Remote review plumbing: sanitization, the client (validation, timeout,
// cache, de-duplication) and the review service. The models here are test
// doubles standing in for Jev; they say nothing about Jev's real behaviour.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { buildReviewRequest, redactPath, redactText, reviewKey } from '../extension/lib/sanitize.js';
import { applyReview, createReviewer, validateReview } from '../extension/lib/reviewClient.js';
import { decideUrl } from '../extension/lib/fusion.js';
import { cleanRequest, createReviewServer } from '../server/server.mjs';
import { createJevModel } from '../server/models/jev.mjs';

const REVIEW_URL = 'https://paypal-account-verify.top/signin/reset/9f8a7b6c5d4e3f2a1b0c?email=jane.doe@example.com&token=abc#frag';

// --- sanitization ------------------------------------------------------------

test('review requests carry no query, fragment, credentials or identifiers', () => {
  const url = 'https://jane:secret@paypal-account-verify.top/u/jane.doe@example.com/reset/9f8a7b6c5d4e3f2a1b0c?token=abc#frag';
  const req = buildReviewRequest(url, decideUrl(url));
  const json = JSON.stringify(req);
  for (const leak of ['token=abc', 'frag', 'secret', 'jane:', 'jane.doe@example.com', '9f8a7b6c5d4e3f2a1b0c']) {
    assert.ok(!json.includes(leak), `leaked ${leak}: ${json}`);
  }
  assert.equal(req.destination.host, 'paypal-account-verify.top');
  assert.equal(req.destination.path, '/u/[email]/reset/[id]');
  assert.equal(req.local.decision, 'needs_review');
  assert.ok(req.local.signals.includes('brand_in_unrelated_domain'));
  assert.equal(req.page, undefined);
});

test('page summaries are redacted and capped, typed values never included', () => {
  const url = 'https://account-review-center.com/login';
  const page = {
    title: 'PayPal: Log in',
    siteName: '',
    identityTexts: ['PayPal'],
    text: `Call +1 (888) 555-0199 or write to help@scam.example. Case 123456789. ${'x'.repeat(5000)}`,
    fields: { password: 1, card: 0, ssn: 0, giftCard: 0, otp: 0 },
    forms: [{ actionHost: 'collector.example', actionProtocol: 'https:', hasPassword: true, value: 'hunter2' }],
  };
  const req = buildReviewRequest(url, decideUrl(url), page);
  const json = JSON.stringify(req);
  for (const leak of ['555-0199', 'help@scam.example', '123456789', 'hunter2']) assert.ok(!json.includes(leak), leak);
  assert.ok(req.page.text.length <= 1501);
  assert.deepEqual(req.page.formTargets, ['collector.example']);
  assert.ok(reviewKey(req).startsWith('page:'));
});

test('redaction keeps ordinary words', () => {
  assert.equal(redactPath('/products/blue-quilt'), '/products/blue-quilt');
  assert.equal(redactText('Your account has been limited', 100), 'Your account has been limited');
});

// --- client --------------------------------------------------------------------

const request = buildReviewRequest(REVIEW_URL, decideUrl(REVIEW_URL));

function fakeFetch(handler) {
  const calls = [];
  const fn = async (url, init) => {
    calls.push(JSON.parse(init.body));
    return handler(init);
  };
  fn.calls = calls;
  return fn;
}
const json = (status, body) => ({ ok: status < 400, status, json: async () => body });

test('valid reviews are returned, cached, and shared while in flight', async () => {
  const f = fakeFetch(async () => { await new Promise((r) => setTimeout(r, 20)); return json(200, { decision: 'block', confidence: 0.93, category: 'credential_phish', model: 'stand-in' }); });
  const r = createReviewer({ endpoint: 'http://review.test/review', fetch: f });
  const [a, b] = await Promise.all([r.review(request), r.review(request)]);
  assert.equal(f.calls.length, 1, 'duplicate requests in flight share one call');
  assert.equal(a.decision, 'block');
  assert.deepEqual(a, b);
  const c = await r.review(request);
  assert.equal(c.cached, true);
  assert.equal(f.calls.length, 1);
  assert.equal(r.peek(request).decision, 'block');
});

test('timeouts, errors and invalid responses are "unavailable" and not cached', async () => {
  const cases = [
    [fakeFetch(async (init) => new Promise((_, reject) => init.signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' }))))), 'timeout'],
    [fakeFetch(async () => { throw new TypeError('Failed to fetch'); }), 'network_error'],
    [fakeFetch(async () => json(503, { error: 'model_unavailable' })), 'http_503'],
    [fakeFetch(async () => json(200, { decision: 'safe', confidence: 2 })), 'invalid_response'],
    [fakeFetch(async () => json(200, { decision: 'allow', confidence: 0.9, category: 'made_up' })), 'invalid_response'],
  ];
  for (const [f, reason] of cases) {
    const r = createReviewer({ endpoint: 'http://review.test/review', fetch: f, timeoutMs: 50 });
    const out = await r.review(request);
    assert.deepEqual(out, { status: 'unavailable', reason });
    assert.equal(r.peek(request), null);
  }
});

test('validateReview accepts only the contract', () => {
  assert.ok(validateReview({ decision: 'allow', confidence: 0.5 }));
  assert.equal(validateReview({ decision: 'allow', confidence: NaN }), null);
  assert.equal(validateReview({ decision: 'maybe', confidence: 0.5 }), null);
  assert.equal(validateReview(null), null);
});

// --- applying a review ----------------------------------------------------------

test('only a confident, valid review changes a needs_review decision', () => {
  const local = decideUrl(REVIEW_URL);
  assert.equal(local.action, 'needs_review');
  assert.equal(applyReview(local, { status: 'ok', decision: 'allow', confidence: 0.95 }).action, 'allow');
  const blocked = applyReview(local, { status: 'ok', decision: 'block', confidence: 0.9, category: 'credential_phish' });
  assert.equal(blocked.action, 'block');
  assert.equal(blocked.source, 'review');
  assert.equal(blocked.reasons[0].code, 'remote_review_block');
  assert.equal(applyReview(local, { status: 'ok', decision: 'allow', confidence: 0.6 }).action, 'needs_review');
  assert.equal(applyReview(local, { status: 'unavailable', reason: 'timeout' }).action, 'needs_review');
});

test('reviews never change allow, block or policy decisions', () => {
  const allow = decideUrl('https://grandmas-recipes.com/');
  assert.equal(applyReview(allow, { status: 'ok', decision: 'block', confidence: 1 }).action, 'allow');
  const policy = { action: 'block', policy: true, reasons: [] };
  assert.equal(applyReview(policy, { status: 'ok', decision: 'allow', confidence: 1 }), policy);
});

// --- review service --------------------------------------------------------------

test('the service re-sanitizes requests and rejects malformed ones', () => {
  const dirty = { ...request, destination: { ...request.destination, path: '/reset/9f8a7b6c5d4e3f2a1b0c' }, extra: 'dropped' };
  const clean = cleanRequest(dirty);
  assert.equal(clean.destination.path, '/reset/[id]');
  assert.equal(clean.extra, undefined);
  assert.equal(cleanRequest({ destination: { scheme: 'javascript', host: 'x' } }), null);
  assert.equal(cleanRequest({ destination: { scheme: 'https', host: 'bad host!' } }), null);
});

async function withServer(model, fn, opts = {}) {
  const server = createReviewServer({ model, ...opts });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}`;
  try {
    await fn(url);
  } finally {
    server.close();
  }
}

const post = (url, body) => fetch(`${url}/review`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

test('service: valid model output is returned; bad output, errors and slowness are not', async () => {
  const standIn = (impl) => ({ name: 'stand-in', configured: true, classify: impl });
  await withServer(standIn(async () => ({ decision: 'allow', confidence: 0.9, category: null })), async (url) => {
    const res = await post(url, request);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { decision: 'allow', confidence: 0.9, category: null, model: 'stand-in' });
    assert.equal((await post(url, { nope: true })).status, 400);
  });
  await withServer(standIn(async () => ({ decision: 'yes' })), async (url) => {
    assert.equal((await post(url, request)).status, 503);
  });
  await withServer(standIn(async () => { throw new Error('upstream down'); }), async (url) => {
    assert.equal((await post(url, request)).status, 503);
  });
  await withServer(standIn(() => new Promise(() => {})), async (url) => {
    assert.equal((await post(url, request)).status, 504);
  }, { modelTimeoutMs: 50 });
});

test('service: the Jev adapter refuses to run until it is implemented', async () => {
  await withServer(createJevModel({ apiKey: undefined }), async (url) => {
    const res = await post(url, request);
    assert.equal(res.status, 503);
    assert.match((await res.json()).detail, /TYPESAFE_API_KEY/);
  });
});
