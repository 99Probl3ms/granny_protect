// Remote review plumbing: sanitization, the client (validation, timeout,
// cache, de-duplication), the review service and the Jev adapter. The models
// and Jev responses here are test doubles; they say nothing about Jev's real
// judgements.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { buildReviewRequest, redactPath, redactText, reviewKey } from '../extension/lib/sanitize.js';
import { applyReview, createReviewer, validateReview } from '../extension/lib/reviewClient.js';
import { decideUrl } from '../extension/lib/fusion.js';
import { cleanRequest, createReviewServer } from '../server/server.mjs';
import { buildJevRequest, createJevModel, DEFAULT_ENDPOINT, QUESTIONS, toReview } from '../server/models/jev.mjs';

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
  assert.notEqual(reviewKey(req), reviewKey(buildReviewRequest(url, decideUrl(url))));
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

test('service: the Jev adapter refuses to run without a key', async () => {
  await withServer(createJevModel({ apiKey: '' }), async (url) => {
    const res = await post(url, request);
    assert.equal(res.status, 503);
    assert.match((await res.json()).detail, /TYPESAFE_API_KEY/);
  });
});

// --- Jev adapter -------------------------------------------------------------

const jevAnswer = (noul, choice = 'none') => ({
  model: 'jev-1.13.0',
  answers: {
    phish: { type: 'noul', noul },
    category: { type: 'choice', choice, probabilities: { [choice]: 0.9 }, confidence: 0.9 },
  },
  usage: { input_tokens: 900, output_tokens: 60 },
});

test('Jev request: the sanitized request is the state, with a Noul and a Choice question', () => {
  const body = buildJevRequest(request);
  assert.equal(body.model, 'jev-1.13.0');
  assert.equal(body.state, request);
  assert.equal(QUESTIONS.phish.type, 'noul');
  assert.equal(QUESTIONS.category.type, 'choice');
  assert.ok('none' in QUESTIONS.category.criteria);
});

test('Jev answers map to reviews the client accepts', () => {
  assert.deepEqual(toReview(jevAnswer(0.98, 'credential_phish')),
    { decision: 'block', confidence: 0.96, category: 'credential_phish', model: 'jev-1.13.0' });
  assert.deepEqual(toReview(jevAnswer(0.03, 'credential_phish')),
    { decision: 'allow', confidence: 0.94, category: null, model: 'jev-1.13.0' });
  assert.equal(toReview(jevAnswer(0.5)).decision, 'needs_review');
  assert.equal(toReview(jevAnswer(0.9, 'none')).category, null);
  for (const p of [0, 0.1, 0.15, 0.5, 0.85, 0.9, 1]) {
    for (const choice of Object.keys(QUESTIONS.category.criteria)) {
      assert.ok(validateReview(toReview(jevAnswer(p, choice))), `p=${p} ${choice}`);
    }
  }
  assert.throws(() => toReview({ answers: {} }));
  assert.throws(() => toReview({ answers: { phish: { noul: 1.5 } } }));
});

test('Jev adapter sends the key as a bearer token to TypeSafe and reports HTTP errors', async () => {
  let seen;
  const model = createJevModel({
    apiKey: 'test-key',
    endpoint: DEFAULT_ENDPOINT,
    fetch: async (url, init) => {
      seen = { url, init };
      return new Response(JSON.stringify(jevAnswer(0.99, 'tech_support_scam')), { status: 200 });
    },
  });
  assert.equal(model.configured, true);
  const review = await model.classify(request);
  assert.equal(seen.url, 'https://api.typesafe.ai/v1/systemone');
  assert.equal(seen.init.headers.authorization, 'Bearer test-key');
  assert.deepEqual(JSON.parse(seen.init.body).state, request);
  assert.equal(review.decision, 'block');
  assert.equal(review.category, 'tech_support_scam');

  const failing = createJevModel({ apiKey: 'k', fetch: async () => new Response('bad key', { status: 401 }) });
  await assert.rejects(failing.classify(request), /401/);
});

test('service: Jev reviews pass through the service end to end', async () => {
  const model = createJevModel({
    apiKey: 'k',
    fetch: async () => new Response(JSON.stringify(jevAnswer(0.97, 'credential_phish')), { status: 200 }),
  });
  await withServer(model, async (url) => {
    const res = await post(url, request);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(),
      { decision: 'block', confidence: 0.94, category: 'credential_phish', model: 'jev-1.13.0' });
  });
});


test('changed page evidence and local signals require a fresh review', async () => {
  const f = fakeFetch(async () => json(200, { decision: 'allow', confidence: 0.95 }));
  const r = createReviewer({ endpoint: 'http://review.test/review', fetch: f });
  const page = { title: 'Discussion', text: 'Community news', fields: { password: 0 } };
  const local = decideUrl(REVIEW_URL);
  await r.review(buildReviewRequest(REVIEW_URL, local, page));
  await r.review(buildReviewRequest(REVIEW_URL, local, { ...page, fields: { password: 1 } }));
  await r.review(buildReviewRequest(REVIEW_URL, local, { ...page, text: 'Tell our operator your account passphrase' }));
  await r.review(buildReviewRequest(REVIEW_URL, { ...local, risk: 0.8 }, page));
  assert.equal(f.calls.length, 4);
  const hit = await r.review(buildReviewRequest(REVIEW_URL, local, page));
  assert.equal(hit.cached, true, 'identical evidence still reuses the review');
});

test('different private destination identities do not share redacted cache entries', async () => {
  const f = fakeFetch(async () => json(200, { decision: 'allow', confidence: 0.95 }));
  const r = createReviewer({ endpoint: 'http://review.test/review', fetch: f });
  const urls = [
    'https://paypal-account-verify.top/reset/123456?token=one#first',
    'https://paypal-account-verify.top/reset/654321?token=one#first',
    'https://paypal-account-verify.top/reset/123456?token=two#first',
    'https://paypal-account-verify.top/reset/123456?token=one#second',
    'https://paypal-account-verify.top:8443/reset/123456?token=one#first',
  ];
  const local = decideUrl(urls[0]);
  for (const url of urls) await r.review(buildReviewRequest(url, local));
  assert.equal(f.calls.length, urls.length);
  assert.ok(f.calls.every((req) => JSON.stringify(req) === JSON.stringify(f.calls[0])), 'private identity stays out of the network payload');
});

test('malformed review fields return 400 and leave the server usable', async () => {
  const malformed = [
    { destination: { scheme: 'https', host: { toString: null } } },
    { ...request, destination: { ...request.destination, path: { toString: null } } },
    { ...request, local: { signals: [{ toString: null }] } },
    { ...request, page: { title: { toString: null } } },
    { ...request, page: { identity: [{ toString: null }] } },
    { ...request, page: { fields: { password: {} } } },
    { ...request, page: [] },
    { ...request, local: [] },
    { ...request, page: { formTargets: [{}] } },
    null,
  ];
  await withServer({ name: 'stand-in', classify: async () => ({ decision: 'allow', confidence: 0.9 }) }, async (url) => {
    for (const body of malformed) {
      assert.equal((await post(url, body)).status, 400, JSON.stringify(body));
      assert.equal((await post(url, request)).status, 200, 'valid requests still work after rejection');
    }
  });
});
