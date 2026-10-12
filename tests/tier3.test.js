import { test } from 'node:test';
import assert from 'node:assert/strict';

import { buildSummary, redactText, sanitizeSummary } from '../extension/lib/summary.js';
import { applyModel, decide, THRESHOLDS } from '../extension/lib/fusion.js';
import { describe } from '../extension/lib/messages.js';
import { classifyRemote, ModelDisabledError } from '../extension/lib/apiClient.js';
import { createTier3 } from '../extension/lib/tier3.js';
import { buildRequest, createJevModel, jevConfigFromEnv, parseResponse, QUESTIONS } from '../backend/src/jev.js';
import { createHandler, createRateLimiter } from '../backend/src/handler.js';

const INSTALL_ID = '0b9f6c1e-7a3d-4c1b-9e2f-5d8a6b4c3e21';

function page(overrides = {}) {
  return {
    url: 'https://example-site.com/',
    title: '',
    siteName: '',
    identityTexts: [],
    text: '',
    fields: { password: 0, card: 0, ssn: 0, giftCard: 0, otp: 0 },
    forms: [],
    phoneNumbers: 0,
    fullscreen: false,
    ...overrides,
  };
}

function heuristicVerdict(risk, overrides = {}) {
  return {
    action: risk >= THRESHOLDS.block ? 'block' : risk >= THRESHOLDS.warn ? 'warn' : 'allow',
    risk, source: 'heuristics', category: null, brand: undefined, reasons: [], domain: 'example-site.com',
    ...overrides,
  };
}

const modelResult = (p_phish, category = 'benign', category_confidence = 0.9) =>
  ({ p_phish, category, category_confidence, pressure: 0, model: 'typesafe/jev-1.13-test' });

// --- summary / redaction ----------------------------------------------------

test('redaction removes emails, phone numbers, long digit runs and URL queries', () => {
  const out = redactText('Mail jane.doe@example.com or call (888) 555-0199. Card 4111 1111 1111 1111, '
    + 'SSN 123-45-6789. See https://x.example/a?token=abc#frag now.');
  assert.doesNotMatch(out, /jane|555|4111|6789|token|frag/);
  assert.match(out, /\[email\]/);
  assert.match(out, /\[phone\]/);
  assert.match(out, /\[number\]/);
  assert.match(out, /https:\/\/x\.example\/a now/);
});

test('summary strips query strings, truncates text and keeps only field kinds', () => {
  const url = 'https://secure-paypa1-verify.top/signin/8f3a9c2e7b1d4f6a8c0e2b4d?email=me@x.com#step2';
  const p = page({
    url,
    title: 'PayPal - Confirm your identity',
    text: 'Your account has been limited. '.repeat(200),
    fields: { password: 1, card: 0, ssn: 0, giftCard: 0, otp: 2 },
    forms: [{ actionHost: 'collect.x9k2.ru', hasPassword: true }],
  });
  const v = decide({ url, page: p });
  const s = buildSummary(url, p, v);
  assert.equal(s.url_host, 'secure-paypa1-verify.top');
  assert.equal(s.url_path, '/signin/*');
  assert.doesNotMatch(JSON.stringify(s), /me@x\.com|step2/);
  assert.ok(s.visible_text_excerpt.length <= 1500);
  assert.deepEqual(s.sensitive_fields, ['password', 'otp']);
  assert.deepEqual(s.forms, [{ action_domain: 'x9k2.ru', has_password: true }]);
  assert.ok(s.heuristic_reasons.includes('password_form_posts_elsewhere'));
});

test('sanitizeSummary rejects garbage and drops unknown fields', () => {
  assert.throws(() => sanitizeSummary(null));
  assert.throws(() => sanitizeSummary({ url_host: '' }));
  assert.throws(() => sanitizeSummary({ url_host: 'bad host/with/slash' }));
  const s = sanitizeSummary({
    url_host: 'Example.COM', cookies: 'session=1', sensitive_fields: ['password', 'typedValue'],
    heuristic_reasons: ['ok_code', 'Bad Code!'], heuristic_risk: 7, visible_text_excerpt: 42,
  });
  assert.equal(s.url_host, 'example.com');
  assert.equal(s.cookies, undefined);
  assert.deepEqual(s.sensitive_fields, ['password']);
  assert.deepEqual(s.heuristic_reasons, ['ok_code']);
  assert.equal(s.heuristic_risk, 1);
  assert.equal(s.visible_text_excerpt, '');
});

// --- fusion -------------------------------------------------------------------

test('model alone can warn but not block', () => {
  const v = applyModel(heuristicVerdict(0), modelResult(0.99, 'fake_shop'));
  assert.equal(v.action, 'warn');
  assert.equal(v.source, 'model');
  assert.equal(v.category, 'fake_shop');
  assert.ok(v.reasons.some((r) => r.code === 'model_flagged'));
  assert.equal(v.heuristicRisk, 0);
});

test('heuristics and model agreeing blocks', () => {
  const v = applyModel(heuristicVerdict(0.88), modelResult(0.95, 'credential_phish'));
  assert.equal(v.action, 'block');
  assert.equal(v.category, 'credential_phish');
});

test('a confident benign answer clears a gray-zone warning', () => {
  const v = applyModel(heuristicVerdict(0.65), modelResult(0.05));
  assert.equal(v.action, 'allow');
  assert.equal(v.category, null);
});

test('model cannot fully clear a page the heuristics would block', () => {
  const v = applyModel(heuristicVerdict(0.9), modelResult(0));
  assert.equal(v.action, 'warn');
});

test('model never changes hard-rule verdicts', () => {
  const trusted = decide({ url: 'https://www.paypal.com/signin' });
  assert.equal(applyModel(trusted, modelResult(1, 'credential_phish')), trusted);
  const blocked = decide({ url: 'http://bad.example/x', blocklist: { urls: new Set(['bad.example/x']), hosts: new Set() } });
  assert.equal(applyModel(blocked, modelResult(0)), blocked);
  const h = heuristicVerdict(0.2);
  assert.equal(applyModel(h, null), h);
});

test('low-confidence model category falls back to heuristic categories', () => {
  const v = applyModel(
    heuristicVerdict(0.7, { reasons: [{ code: 'tech_support_scam_language', weight: 0.55 }] }),
    modelResult(0.9, 'fake_shop', 0.3),
  );
  assert.equal(v.category, 'tech_support_scam');
});

test('model categories have plain-language warnings', () => {
  for (const cat of ['credential_phish', 'tech_support_scam', 'gift_card_or_payment_scam', 'fake_shop', 'impersonation_other']) {
    const text = describe(applyModel(heuristicVerdict(0.5), modelResult(0.95, cat)));
    assert.ok(text.headline && text.advice, cat);
    assert.ok(text.reasons.some((r) => /scam checker/.test(r)), cat);
  }
});

// --- extension API client ---------------------------------------------------

test('classifyRemote posts the summary with the install id', async () => {
  let seen;
  const fakeFetch = async (url, init) => {
    seen = { url: String(url), init };
    return Response.json(modelResult(0.8, 'credential_phish'));
  };
  const r = await classifyRemote({ url_host: 'a.com' }, { backendUrl: 'https://api.example/gp', installId: INSTALL_ID, fetch: fakeFetch });
  assert.equal(seen.url, 'https://api.example/gp/classify');
  assert.equal(seen.init.headers['x-install-id'], INSTALL_ID);
  assert.deepEqual(JSON.parse(seen.init.body), { summary: { url_host: 'a.com' } });
  assert.equal(r.p_phish, 0.8);
});

test('classifyRemote reports the kill switch distinctly', async () => {
  const fakeFetch = async () => Response.json({ disabled: true }, { status: 503 });
  await assert.rejects(classifyRemote({}, { backendUrl: 'https://x/', installId: INSTALL_ID, fetch: fakeFetch }), ModelDisabledError);
});

// --- Tier 3 orchestration ---------------------------------------------------

function tier3With(classify, overrides = {}) {
  let t = 1000;
  const t3 = createTier3({
    getBackendUrl: async () => 'https://backend.example',
    classify,
    grayZoneOnly: false,
    grayZone: { min: 0.3, max: 0.85 },
    waitMs: 50,
    now: () => t,
    ...overrides,
  });
  return { t3, advance: (ms) => { t += ms; } };
}

test('tier3 skips hard-rule verdicts and caches results', async () => {
  let calls = 0;
  const { t3 } = tier3With(async () => { calls++; return modelResult(0.7); });
  const p = page({ url: 'https://shop-deals.example/' });
  assert.equal(await t3.ask(p.url, p, { ...heuristicVerdict(0), source: 'trusted' }), null);
  assert.equal((await t3.ask(p.url, p, heuristicVerdict(0, { domain: 'shop-deals.example' }))).p_phish, 0.7);
  await t3.ask(p.url, p, heuristicVerdict(0, { domain: 'shop-deals.example' }));
  assert.equal(calls, 1);
});

test('tier3 gives up waiting but keeps the result for next time', async () => {
  let calls = 0;
  const { t3 } = tier3With(() => { calls++; return new Promise((r) => setTimeout(() => r(modelResult(0.9)), 120)); });
  const p = page({ url: 'https://slow.example/' });
  const v = heuristicVerdict(0, { domain: 'slow.example' });
  assert.equal(await t3.ask(p.url, p, v), null);
  await new Promise((r) => setTimeout(r, 150));
  assert.equal((await t3.ask(p.url, p, v)).p_phish, 0.9);
  assert.equal(calls, 1);
});

test('tier3 backs off after errors, and is off without a backend URL', async () => {
  let calls = 0;
  const { t3, advance } = tier3With(async () => { calls++; throw new ModelDisabledError('off'); });
  const p = page({ url: 'https://x.example/' });
  const v = heuristicVerdict(0, { domain: 'x.example' });
  assert.equal(await t3.ask(p.url, p, v), null);
  assert.equal(await t3.ask(p.url, p, v), null);
  assert.equal(calls, 1);
  advance(11 * 60 * 1000);
  await t3.ask(p.url, p, v);
  assert.equal(calls, 2);

  const { t3: none } = tier3With(async () => { throw new Error('should not be called'); }, { getBackendUrl: async () => '' });
  assert.equal(await none.ask(p.url, p, v), null);
});

test('tier3 gray-zone mode only asks about uncertain pages', () => {
  const { t3 } = tier3With(async () => modelResult(0), { grayZoneOnly: true });
  assert.equal(t3.eligible(heuristicVerdict(0.1)), false);
  assert.equal(t3.eligible(heuristicVerdict(0.5)), true);
  assert.equal(t3.eligible(heuristicVerdict(0.9)), false);
});

// --- Jev adapter --------------------------------------------------------------

const JEV_RESPONSE = {
  model: 'jev-1.13.0',
  answers: {
    phish: { type: 'noul', noul: 0.97 },
    category: { type: 'choice', choice: 'credential_phish', probabilities: { credential_phish: 0.9 }, confidence: 0.85 },
    pressure: { type: 'score', score: 2.4, probabilities: {}, confidence: 0.6 },
  },
  usage: { input_tokens: 500, output_tokens: 30, cost: 0.00002 },
};

test('Jev request uses noul, choice and score questions over the summary', () => {
  const summary = sanitizeSummary({ url_host: 'a.example' });
  const req = buildRequest(summary);
  assert.equal(req.model, 'jev-1.13.0');
  assert.deepEqual(req.state, { page: summary });
  assert.equal(QUESTIONS.phish.type, 'noul');
  assert.equal(QUESTIONS.category.type, 'choice');
  assert.ok('benign' in QUESTIONS.category.criteria);
  assert.equal(QUESTIONS.pressure.type, 'score');
  assert.ok(QUESTIONS.pressure.criteria.length <= 10);
});

test('Jev response parsing', () => {
  assert.deepEqual(parseResponse(JEV_RESPONSE), {
    p_phish: 0.97, category: 'credential_phish', category_confidence: 0.85, pressure: 2.4,
    model: 'jev-1.13.0',
  });
  assert.equal(parseResponse({ answers: { phish: { noul: 0.1 }, category: { choice: 'made_up' } } }).category, 'benign');
  assert.throws(() => parseResponse({ answers: {} }));
});

test('Jev adapter sends the key as a bearer token', async () => {
  let seen;
  const model = createJevModel({
    apiKey: 'test-key',
    fetch: async (url, init) => { seen = { url, init }; return Response.json(JEV_RESPONSE); },
  });
  const r = await model.classify(sanitizeSummary({ url_host: 'a.example' }));
  assert.equal(seen.url, 'https://api.typesafe.ai/v1/systemone');
  assert.equal(seen.init.headers.authorization, 'Bearer test-key');
  assert.equal(r.p_phish, 0.97);
  assert.equal(r.usage.input_tokens, 500);

  const failing = createJevModel({ apiKey: 'k', fetch: async () => new Response('nope', { status: 401 }) });
  await assert.rejects(failing.classify({}), /401/);
});

test('Jev provider comes from the environment, TypeSafe direct first', () => {
  assert.equal(jevConfigFromEnv({}), null);
  assert.deepEqual(jevConfigFromEnv({ TYPESAFE_API_KEY: 'ts', OPENROUTER_API_KEY: 'or' }), {
    provider: 'typesafe', apiKey: 'ts', url: 'https://api.typesafe.ai/v1/systemone', model: 'jev-1.13.0',
  });
  assert.deepEqual(jevConfigFromEnv({ OPENROUTER_API_KEY: 'or' }), {
    provider: 'openrouter', apiKey: 'or', url: 'https://openrouter.ai/api/alpha/decisions', model: 'typesafe/jev-1.13',
  });
  assert.equal(jevConfigFromEnv({ TYPESAFE_API_KEY: 'ts', JEV_MODEL: 'jev-latest' }).model, 'jev-latest');
});

// --- backend handler ----------------------------------------------------------

function classifyRequest(body, headers = { 'x-install-id': INSTALL_ID }) {
  return new Request('http://backend.test/classify', {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
}

test('backend classifies a sanitized summary and logs the decision', async () => {
  const logs = [];
  let received;
  const handle = createHandler({
    model: { name: 'fake', classify: async (s) => { received = s; return { ...modelResult(0.9, 'credential_phish'), usage: { cost: 1 } }; } },
    log: (e) => logs.push(e),
  });
  const res = await handle(classifyRequest({ summary: { url_host: 'evil.example', visible_text_excerpt: 'call 888-555-0199', extra: 'x' } }));
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.p_phish, 0.9);
  assert.equal(body.usage, undefined);
  assert.equal(received.extra, undefined);
  assert.doesNotMatch(received.visible_text_excerpt, /555/);
  assert.equal(logs.length, 1);
  assert.equal(logs[0].result.category, 'credential_phish');
  assert.equal(logs[0].usage.cost, 1);
});

test('backend validates input and enforces the kill switch and rate limit', async () => {
  const model = { name: 'fake', classify: async () => modelResult(0.1) };
  const handle = createHandler({ model, ratePerMinute: 3 }); // invalid requests count too
  assert.equal((await handle(classifyRequest({ summary: { url_host: 'a.com' } }, {}))).status, 400);
  assert.equal((await handle(classifyRequest('not json'))).status, 400);
  assert.equal((await handle(classifyRequest({ summary: {} }))).status, 400);
  assert.equal((await handle(classifyRequest({ summary: { url_host: 'a.com' } }))).status, 200);
  assert.equal((await handle(classifyRequest({ summary: { url_host: 'a.com' } }))).status, 429);
  assert.equal((await handle(new Request('http://backend.test/classify'))).status, 405);
  assert.equal((await handle(new Request('http://backend.test/nope'))).status, 404);

  const off = createHandler({ model, disabled: true });
  const res = await off(classifyRequest({ summary: { url_host: 'a.com' } }));
  assert.equal(res.status, 503);
  assert.equal((await res.json()).disabled, true);
  assert.deepEqual(await (await off(new Request('http://backend.test/health'))).json(), { ok: true, tier3: false, model: 'fake' });

  const broken = createHandler({ model: { name: 'x', classify: async () => { throw new Error('down'); } } });
  assert.equal((await broken(classifyRequest({ summary: { url_host: 'a.com' } }))).status, 502);
});

test('rate limiter resets each window', () => {
  let t = 0;
  const allow = createRateLimiter({ limit: 1, windowMs: 1000, now: () => t });
  assert.equal(allow('a'), true);
  assert.equal(allow('a'), false);
  assert.equal(allow('b'), true);
  t = 1000;
  assert.equal(allow('a'), true);
});

test('encoded path personal data is redacted on both sides, including malformed encodings', () => {
  for (const segment of ['jane%40example.com', '%31%32%33%34%35%36', 'jane%2540example.com', 'jane%ZZ@example.com']) {
    const url = `https://example-site.com/account/${segment}`;
    const summary = buildSummary(url, page(), heuristicVerdict(0));
    for (const s of [summary, sanitizeSummary({ url_host: 'example-site.com', url_path: `/account/${segment}` }), sanitizeSummary(summary)]) {
      assert.doesNotMatch(s.url_path, /jane|example\.com|123456|%/);
    }
  }
  assert.equal(sanitizeSummary({ url_host: 'a.com', url_path: '/verify%2Daccount/signin' }).url_path, '/verify-account/signin');
});

test('backend changes invalidate verdicts and backoff', async () => {
  let endpoint = 'https://old.example';
  const calls = [];
  const { t3 } = tier3With(async (_, backend) => {
    calls.push(backend);
    if (backend === 'https://disabled.example') throw new ModelDisabledError('off');
    return modelResult(backend === 'https://old.example' ? 0 : 1);
  }, { getBackendUrl: async () => endpoint });
  const p = page(), v = heuristicVerdict(0);
  assert.equal((await t3.ask(p.url, p, v)).p_phish, 0);
  endpoint = 'https://new.example';
  assert.equal((await t3.ask(p.url, p, v)).p_phish, 1);
  endpoint = 'https://disabled.example';
  assert.equal(await t3.ask(p.url, p, v), null);
  endpoint = 'https://new.example';
  assert.equal((await t3.ask(p.url, p, v)).p_phish, 1);
  await t3.ask(p.url, p, v);
  assert.equal(calls.length, 4);
});

test('an old in-flight failure cannot erase or pause a new backend verdict', async () => {
  let endpoint = 'https://old.example', rejectOld;
  let calls = 0;
  const { t3 } = tier3With((_, backend) => {
    calls++;
    return backend === 'https://old.example'
      ? new Promise((_, reject) => { rejectOld = reject; })
      : Promise.resolve(modelResult(1));
  }, { getBackendUrl: async () => endpoint });
  const p = page(), v = heuristicVerdict(0);
  const old = t3.ask(p.url, p, v);
  await new Promise((r) => setImmediate(r));
  endpoint = 'https://new.example';
  assert.equal((await t3.ask(p.url, p, v)).p_phish, 1);
  rejectOld(new Error('old backend down'));
  assert.equal(await old, null);
  assert.equal((await t3.ask(p.url, p, v)).p_phish, 1);
  assert.equal(calls, 2);
});

test('backend limits streamed bytes and cancels before reading the entire body', async () => {
  let pulled = 0, cancelled = false;
  const handle = createHandler({ model: { classify: async () => assert.fail('oversized request classified') } });
  const stream = new ReadableStream({
    pull(controller) { pulled++; controller.enqueue(new Uint8Array(8192)); },
    cancel() { cancelled = true; },
  }, { highWaterMark: 0 });
  const response = await handle(new Request('http://backend.test/classify', {
    method: 'POST', headers: { 'x-install-id': INSTALL_ID }, body: stream, duplex: 'half',
  }));
  assert.equal(response.status, 413);
  assert.equal(pulled, 5);
  assert.equal(cancelled, true);
  const multiByte = JSON.stringify({ summary: { url_host: 'a.com', visible_text_excerpt: 'é'.repeat(20000) } });
  assert.ok(multiByte.length < 32768);
  assert.equal((await handle(classifyRequest(multiByte))).status, 413);
});
