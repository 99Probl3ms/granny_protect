import { test } from 'node:test';
import assert from 'node:assert/strict';

import { registrableDomain, subdomainLabels, toUnicodeHost } from '../extension/lib/domain.js';
import { buildBlocklist, isBlocklisted, isTrusted } from '../extension/lib/lists.js';
import { analyzeUrl, skeleton } from '../extension/lib/urlHeuristics.js';
import { analyzePage, claimedBrand } from '../extension/lib/pageHeuristics.js';
import { decide } from '../extension/lib/fusion.js';
import { describe } from '../extension/lib/messages.js';

const codes = (r) => r.reasons.map((x) => x.code);

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

// --- domain helpers --------------------------------------------------------

test('registrable domain handles multi-part suffixes', () => {
  assert.equal(registrableDomain('login.paypal.com'), 'paypal.com');
  assert.equal(registrableDomain('www.bbc.co.uk'), 'bbc.co.uk');
  assert.equal(registrableDomain('a.b.amazon.com.au'), 'amazon.com.au');
  assert.deepEqual(subdomainLabels('paypal.com.secure-login.xyz'), ['paypal', 'com']);
});

test('punycode hosts decode to unicode', () => {
  assert.equal(toUnicodeHost('xn--pypal-4ve.com'), 'pаypal.com'); // Cyrillic а
  assert.equal(toUnicodeHost('xn--mnchen-3ya.de'), 'münchen.de');
  assert.equal(skeleton('pаypa1'), 'paypal');
});

// --- lists ----------------------------------------------------------------

test('trusted list covers brands and subdomains but not user-content hosts', () => {
  assert.ok(isTrusted('www.paypal.com'));
  assert.ok(isTrusted('secure.chase.com'));
  assert.ok(!isTrusted('paypal.com.evil.xyz'));
  assert.ok(!isTrusted('docs.google.com'), 'Google Docs/Forms can host phishing');
  assert.ok(!isTrusted('evil.sharepoint.com'));
  assert.ok(isTrusted('mybank-example.com', ['mybank-example.com']), 'user-trusted domains');
});

test('blocklist matches exact URLs everywhere, whole hosts only when not shared', () => {
  const bl = buildBlocklist([
    'http://evil-login.xyz/paypal/',
    'https://docs.google.com/forms/d/e/abc123/viewform',
  ]);
  assert.ok(isBlocklisted('https://evil-login.xyz/other-page', bl));
  assert.ok(isBlocklisted('https://cdn.evil-login.xyz/', bl));
  assert.ok(isBlocklisted('https://docs.google.com/forms/d/e/abc123/viewform?usp=sf_link', bl));
  assert.ok(!isBlocklisted('https://docs.google.com/forms/d/e/legit/viewform', bl));
});

// --- URL heuristics -------------------------------------------------------

test('look-alike and misspelled brand domains score high', () => {
  const homoglyph = analyzeUrl('https://xn--pypal-4ve.com/signin');
  assert.ok(codes(homoglyph).includes('lookalike_brand_domain'), JSON.stringify(homoglyph));
  assert.ok(homoglyph.risk >= 0.75);

  const digits = analyzeUrl('https://paypa1.com/');
  assert.ok(codes(digits).includes('lookalike_brand_domain'));

  const typo = analyzeUrl('https://amazom.com/');
  assert.ok(codes(typo).includes('typosquat_brand_domain'), JSON.stringify(typo));
});

test('brand name inside an unrelated domain is flagged', () => {
  const r = analyzeUrl('https://paypal.com.secure-login.xyz/webscr');
  assert.ok(codes(r).includes('brand_in_unrelated_domain'));
  assert.ok(codes(r).includes('domain_in_subdomain'));
  assert.ok(codes(r).includes('risky_tld'));
  // The URL alone is enough to warn; blocking also needs page evidence.
  assert.ok(r.risk >= 0.6, `risk ${r.risk}`);
});

test('ordinary-word brands are not matched as substrings', () => {
  // "chase" inside "purchase", "apple" inside "pineapple"
  assert.ok(!codes(analyzeUrl('https://purchase-orders.com/')).includes('brand_in_unrelated_domain'));
  assert.ok(!codes(analyzeUrl('https://pineapplefarm.com/')).includes('brand_in_unrelated_domain'));
  assert.equal(analyzeUrl('https://pineapplefarm.com/').risk, 0);
});

test('plain unknown sites have little or no URL risk', () => {
  for (const url of ['https://grandmas-recipes.com/', 'https://localbakery.net/menu', 'https://example.org/']) {
    assert.ok(analyzeUrl(url).risk < 0.2, url);
  }
});

test('IP-address hosts and URL credentials are flagged', () => {
  assert.ok(codes(analyzeUrl('http://192.168.4.20/login')).includes('ip_address_host'));
  assert.ok(codes(analyzeUrl('https://paypal.com@evil.example/')).includes('credentials_in_url'));
});

// --- page heuristics ------------------------------------------------------

test('brand claims require distinctive names or phrases', () => {
  assert.equal(claimedBrand(['PayPal: Log in to your account'])?.name, 'PayPal');
  assert.equal(claimedBrand(['Sign in with your Apple ID'])?.name, 'Apple');
  assert.equal(claimedBrand(['Apple pie recipes - sign in']), null);
  assert.equal(claimedBrand(['Discover great hikes']), null);
  assert.equal(claimedBrand(['UPS: Track your package'])?.name, 'UPS');
  assert.equal(claimedBrand(['Ups and downs of gardening']), null);
});

test('impersonating login page on a foreign domain is flagged', () => {
  const r = analyzePage(page({
    url: 'https://account-review-center.com/login',
    title: 'PayPal: Log in to your account',
    fields: { password: 1, card: 0, ssn: 0, giftCard: 0, otp: 0 },
    forms: [{ actionHost: 'collector.ru', hasPassword: true }],
    text: 'We noticed unusual activity. Your account has been limited. Verify your identity within 24 hours.',
  }));
  assert.ok(codes(r).includes('impersonates_brand_asks_secrets'));
  assert.ok(codes(r).includes('password_form_posts_elsewhere'));
  assert.ok(codes(r).includes('urgent_threatening_language'));
  assert.ok(r.risk >= 0.85, `risk ${r.risk}`);
});

test('tech support scam page is flagged', () => {
  const r = analyzePage(page({
    url: 'https://win-alert-9921.online/',
    title: 'Windows Defender Security Center',
    text: 'WARNING! Your computer is infected with a virus. Do not close this page. Call Microsoft Support toll-free at +1 (888) 555-0199. Error code #DW6VB36.',
    phoneNumbers: 1,
    fullscreen: true,
  }));
  assert.ok(codes(r).includes('tech_support_scam_language'), JSON.stringify(r));
  assert.ok(r.risk >= 0.6);
});

test('ordinary login page on an unknown site is allowed', () => {
  const r = decide({
    url: 'https://grandmas-recipes.com/login',
    page: page({
      url: 'https://grandmas-recipes.com/login',
      title: "Grandma's Recipes - Sign in",
      fields: { password: 1, card: 0, ssn: 0, giftCard: 0, otp: 0 },
      forms: [{ actionHost: 'grandmas-recipes.com', hasPassword: true }],
      text: 'Welcome back! Sign in to save your favourite recipes.',
    }),
  });
  assert.equal(r.action, 'allow', JSON.stringify(r));
});

test('online shop checkout on an unknown site is allowed', () => {
  const r = decide({
    url: 'https://handmade-quilts.com/checkout',
    page: page({
      url: 'https://handmade-quilts.com/checkout',
      title: 'Checkout - Handmade Quilts',
      fields: { password: 0, card: 1, ssn: 0, giftCard: 0, otp: 0 },
      text: 'Order summary. Shipping address. Pay with card or gift card.',
    }),
  });
  assert.equal(r.action, 'allow', JSON.stringify(r));
});

// --- fusion ---------------------------------------------------------------

test('trusted sites are always allowed, even with scary words', () => {
  const r = decide({
    url: 'https://www.paypal.com/signin',
    page: page({
      url: 'https://www.paypal.com/signin',
      title: 'PayPal: Log in',
      fields: { password: 1, card: 0, ssn: 0, giftCard: 0, otp: 0 },
      text: 'Your account has been limited. Verify your identity immediately.',
    }),
  });
  assert.equal(r.action, 'allow');
  assert.equal(r.source, 'trusted');
});

test('blocklisted sites are blocked', () => {
  const blocklist = buildBlocklist(['https://nice-looking-site.com/x']);
  const r = decide({ url: 'https://nice-looking-site.com/', blocklist });
  assert.equal(r.action, 'block');
  assert.equal(r.source, 'blocklist');
});

test('a full phishing page is blocked with a credential category and brand', () => {
  const url = 'https://paypal-account-verify.top/signin';
  const r = decide({
    url,
    page: page({
      url,
      title: 'PayPal: Log in to your account',
      fields: { password: 1, card: 0, ssn: 0, giftCard: 0, otp: 0 },
      text: 'Your account has been suspended. Confirm your identity within 24 hours.',
    }),
  });
  assert.equal(r.action, 'block');
  assert.equal(r.category, 'credential_phish');
  assert.equal(r.brand, 'PayPal');
  const text = describe(r);
  assert.match(text.headline, /pretending to be PayPal/);
  assert.ok(text.reasons.length >= 1 && text.reasons.length <= 3);
});

test('gift card scam is categorized as payment scam', () => {
  const url = 'https://irs-refund-desk.com/claim';
  const r = decide({
    url,
    page: page({
      url,
      title: 'Tax refund pending',
      fields: { password: 0, card: 0, ssn: 0, giftCard: 1, otp: 0 },
      text: 'Your tax refund is pending. To claim, pay the processing fee immediately with Google Play gift cards and enter the claim code below.',
    }),
  });
  assert.notEqual(r.action, 'allow', JSON.stringify(r));
  assert.equal(r.category, 'payment_scam');
});
