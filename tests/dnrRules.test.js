import { test } from 'node:test';
import assert from 'node:assert/strict';

import { buildBlocklist } from '../extension/lib/lists.js';
import {
  DOMAINS_PER_RULE, MAX_URL_RULES, allowRule, buildBlockRules, coveredByRules,
} from '../extension/lib/dnrRules.js';

const BLOCK_PAGE = 'chrome-extension://abc/interstitial/blocked.html';

/** Would this rule redirect `url`? (requestDomains matches subdomains too.) */
function ruleMatches(rule, url) {
  const { regexFilter, requestDomains } = rule.condition;
  if (requestDomains) {
    const host = new URL(url).hostname;
    if (!requestDomains.some((d) => host === d || host.endsWith('.' + d))) return false;
  }
  return new RegExp(regexFilter, 'i').test(url);
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
