import { test } from 'node:test';
import assert from 'node:assert/strict';

import { decideUrl } from '../extension/lib/fusion.js';
import { buildBlocklist } from '../extension/lib/lists.js';
import {
  DOMAINS_PER_RULE, MAX_URL_RULES, allowRule, buildBlockRules, coveredByRules, supportedBlockRules,
} from '../extension/lib/dnrRules.js';

const BLOCK_PAGE = 'chrome-extension://abc/interstitial/blocked.html';

/** Would this rule redirect `url`? (requestDomains matches subdomains too.) */
function ruleMatches(rule, url) {
  const { regexFilter, requestDomains, excludedRequestDomains, isUrlFilterCaseSensitive } = rule.condition;
  const host = new URL(url).hostname;
  if (excludedRequestDomains?.some((d) => host === d || host.endsWith('.' + d))) return false;
  if (requestDomains) {
    const host = new URL(url).hostname;
    if (!requestDomains.some((d) => host === d || host.endsWith('.' + d))) return false;
  }
  return new RegExp(regexFilter, isUrlFilterCaseSensitive ? '' : 'i').test(url);
}

const anyRuleMatches = (rules, url) => rules.some((r) => ruleMatches(r, url));

test('listed hosts become one requestDomains redirect rule', () => {
  const bl = buildBlocklist(['http://evil-login.xyz/paypal/', 'https://scam-shop.top/']);
  const rules = buildBlockRules(bl, BLOCK_PAGE);
  assert.equal(rules.length, 1);
  const [rule] = rules;
  assert.deepEqual(rule.condition.requestDomains.sort(), ['evil-login.xyz', 'scam-shop.top']);
  assert.deepEqual(rule.condition.resourceTypes, ['main_frame']);
  assert.equal(rule.action.type, 'redirect');
  assert.equal(rule.action.redirect.regexSubstitution, `${BLOCK_PAGE}#\\0`);

  assert.ok(anyRuleMatches(rules, 'https://evil-login.xyz/anything?x=1'));
  assert.ok(anyRuleMatches(rules, 'http://cdn.evil-login.xyz/'));
  assert.ok(!anyRuleMatches(rules, 'https://example.com/'));
});

test('exact-URL entries on shared hosts get their own rule', () => {
  const bl = buildBlocklist(['https://docs.google.com/forms/d/e/abc123/viewform']);
  const rules = buildBlockRules(bl, BLOCK_PAGE);
  assert.equal(rules.length, 1);
  assert.equal(rules[0].condition.requestDomains, undefined);
  assert.ok(anyRuleMatches(rules, 'https://docs.google.com/forms/d/e/abc123/viewform'));
  assert.ok(anyRuleMatches(rules, 'https://docs.google.com/forms/d/e/abc123/viewform?usp=sf_link'));
  assert.ok(anyRuleMatches(rules, 'http://www.docs.google.com/forms/d/e/abc123/viewform/'));
  assert.ok(!anyRuleMatches(rules, 'https://docs.google.com/forms/d/e/abc123/viewform2'));
  assert.ok(!anyRuleMatches(rules, 'https://docs.google.com/forms/d/e/legit/viewform'));
});

test('URLs already covered by a listed host get no extra rule', () => {
  const bl = buildBlocklist(['https://evil.top/a', 'https://evil.top/b', 'https://sub.evil.top/c']);
  const rules = buildBlockRules(bl, BLOCK_PAGE);
  assert.equal(rules.length, 1);
});

test('regex special characters in paths are escaped', () => {
  const bl = buildBlocklist(['https://sites.google.com/view/a+b(c)']);
  const rules = buildBlockRules(bl, BLOCK_PAGE);
  assert.ok(anyRuleMatches(rules, 'https://sites.google.com/view/a+b(c)'));
  assert.ok(!anyRuleMatches(rules, 'https://sites.google.com/view/aab(c)'));
});

test('sites the user trusts are left out', () => {
  const bl = buildBlocklist(['https://my-small-bank.com/login', 'https://evil.top/']);
  const rules = buildBlockRules(bl, BLOCK_PAGE, ['my-small-bank.com']);
  assert.deepEqual(rules[0].condition.requestDomains, ['evil.top']);
  assert.ok(!coveredByRules('https://my-small-bank.com/login', bl, ['my-small-bank.com']));
});

test('large lists are chunked and URL rules are capped', () => {
  const hosts = Array.from({ length: DOMAINS_PER_RULE * 2 + 5 }, (_, i) => `https://bad${i}.top/`);
  const urls = Array.from({ length: MAX_URL_RULES + 50 }, (_, i) => `https://sites.google.com/view/bad${i}`);
  const bl = buildBlocklist([...hosts, ...urls]);
  const rules = buildBlockRules(bl, BLOCK_PAGE);
  const hostRules = rules.filter((r) => r.condition.requestDomains);
  assert.equal(hostRules.length, 3);
  assert.equal(rules.length - hostRules.length, MAX_URL_RULES);
  assert.ok(rules.length < 1000, 'stays under Chrome\'s regex rule limit');
  assert.equal(new Set(rules.map((r) => r.id)).size, rules.length, 'unique ids');

  // Coverage agrees with the cap, so the fallback handles the rest.
  assert.ok(coveredByRules('https://sites.google.com/view/bad0', bl));
  assert.ok(!coveredByRules(`https://sites.google.com/view/bad${MAX_URL_RULES + 10}`, bl));
});

test('coveredByRules mirrors the rules', () => {
  const bl = buildBlocklist(['http://evil-login.xyz/paypal/', 'https://docs.google.com/forms/d/e/abc123/viewform']);
  assert.ok(coveredByRules('https://evil-login.xyz/', bl));
  assert.ok(coveredByRules('https://www.evil-login.xyz/x', bl));
  assert.ok(coveredByRules('https://docs.google.com/forms/d/e/abc123/viewform?x', bl));
  assert.ok(!coveredByRules('https://docs.google.com/forms/d/e/other/viewform', bl));
});

test('allow rules outrank block rules', () => {
  const rule = allowRule(3, 'evil.top');
  assert.equal(rule.action.type, 'allow');
  assert.ok(rule.priority > buildBlockRules(buildBlocklist(['https://evil.top/']), BLOCK_PAGE)[0].priority);
});


test('DNR and local decisions agree on trusted hosts, descendants, and exact paths', () => {
  const feed = [
    'https://www.paypal.com/example', 'http://intranet/login',
    'https://bad.example-company.net/a', 'https://example-vendor.net/a',
    'https://docs.google.com/forms/AbC',
  ];
  const userTrusted = ['safe.example-vendor.net', 'docs.google.com'];
  const bl = buildBlocklist(feed);
  const rules = buildBlockRules(bl, BLOCK_PAGE, userTrusted);
  const cases = [
    ['https://www.paypal.com/example', false],
    ['http://intranet/login', false],
    ['https://child.bad.example-company.net/', true],
    ['https://safe.example-vendor.net/a', false],
    ['https://child.safe.example-vendor.net/a', false],
    ['https://other.example-vendor.net/a', true],
    ['https://docs.google.com/forms/AbC', true],
    ['https://docs.google.com/forms/abc', false],
  ];
  for (const [url, blocked] of cases) {
    assert.equal(anyRuleMatches(rules, url), blocked, `DNR: ${url}`);
    assert.equal(coveredByRules(url, bl, userTrusted), blocked, `coverage: ${url}`);
    assert.equal(decideUrl(url, { blocklist: bl, userTrusted }).action === 'block', blocked, `local: ${url}`);
  }
});

test('compiler-rejected URL rules do not discard other blocks or suppress their fallback', async () => {
  const badUrl = `https://docs.google.com/forms/${'a'.repeat(1200)}`;
  const goodUrl = 'https://docs.google.com/forms/good';
  const bl = buildBlocklist(['https://evil-login.xyz/', badUrl, goodUrl]);
  const rules = buildBlockRules(bl, BLOCK_PAGE);
  const checks = [];
  const { addRules, skippedRuleIds } = await supportedBlockRules(rules, async (options) => {
    checks.push(options);
    return { isSupported: !options.regex.includes('a'.repeat(1200)), reason: 'memoryLimitExceeded' };
  });
  assert.deepEqual(addRules.map((r) => r.id), [1, 3]);
  assert.deepEqual(skippedRuleIds, [2]);
  assert.ok(checks.every((c) => c.requireCapturing), 'validate redirect capture support');
  assert.equal(checks[1].isCaseSensitive, true);
  assert.ok(coveredByRules('https://evil-login.xyz/path', bl, [], skippedRuleIds));
  assert.ok(coveredByRules(goodUrl, bl, [], skippedRuleIds));
  assert.equal(coveredByRules(badUrl, bl, [], skippedRuleIds), false, 'use navigation fallback');
  assert.equal(decideUrl(badUrl, { blocklist: bl }).action, 'block', 'local block remains');
});

test('regex support is checked by Chrome rather than inferred from string length', async () => {
  const bl = buildBlocklist(['https://docs.google.com/forms/short']);
  const rules = buildBlockRules(bl, BLOCK_PAGE);
  const { addRules, skippedRuleIds } = await supportedBlockRules(rules, async () => ({ isSupported: false }));
  assert.deepEqual(addRules, []);
  assert.equal(coveredByRules('https://docs.google.com/forms/short', bl, [], skippedRuleIds), false);
});

test('identical host regexes are validated once, and rejected host rules use fallback', async () => {
  const bl = buildBlocklist(Array.from({ length: DOMAINS_PER_RULE + 1 }, (_, i) => `https://bad${i}.top/`));
  const rules = buildBlockRules(bl, BLOCK_PAGE);
  let checks = 0;
  const { addRules, skippedRuleIds } = await supportedBlockRules(rules, async () => { checks++; return { isSupported: false }; });
  assert.equal(checks, 1);
  assert.deepEqual(addRules, []);
  assert.deepEqual(skippedRuleIds, [1, 2]);
  assert.equal(coveredByRules('https://bad0.top/', bl, [], skippedRuleIds), false);
  assert.equal(coveredByRules(`https://bad${DOMAINS_PER_RULE}.top/`, bl, [], skippedRuleIds), false);
});
