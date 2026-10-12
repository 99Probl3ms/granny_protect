// Tier 2: signals from the page content. Runs in the background on a feature
// summary sent by the content script (see content/content.js `extractFeatures`).

import { BRANDS } from './brands.js';
import { normalizeHost, registrableDomain } from './domain.js';
import { isTrusted, isUserContentHost } from './lists.js';
import { noisyOr } from './score.js';
import { isBrandHost } from './urlHeuristics.js';

/**
 * @typedef {Object} PageFeatures
 * @property {string} url
 * @property {string} title
 * @property {string} siteName       og:site_name / application-name
 * @property {string[]} identityTexts logo alt/title text, top headings, header text
 * @property {string} text           visible text excerpt (first few thousand chars)
 * @property {{password:number, card:number, ssn:number, giftCard:number, otp:number}} fields
 * @property {{actionHost:string, hasPassword:boolean}[]} forms
 * @property {number} phoneNumbers   phone-number-looking strings in visible text
 * @property {boolean} fullscreen    page went fullscreen without the user asking
 */

const URGENCY_PATTERNS = [
  /\b(account|card|access)\b.{0,40}\b(suspended|locked|limited|disabled|restricted|on hold|frozen|compromised)\b/i,
  /\b(suspended|locked|limited|disabled|restricted|frozen)\b.{0,40}\b(account|card|access)\b/i,
  /\bwithin\s+(24|48|72)\s+hours\b/i,
  /\b(immediately|urgent(ly)?|right away|act now|final (notice|warning)|last (chance|warning))\b/i,
  /\b(unusual|suspicious|unauthori[sz]ed)\s+(activity|sign[- ]?in|login|transaction|purchase|charge)s?\b/i,
  /\b(verify|confirm|update|validate)\s+your\s+(identity|account|information|details|payment|billing)\b/i,
  /\b(package|parcel|shipment|delivery)\b.{0,60}\b(on hold|failed|could not be delivered|unpaid|redelivery|customs fee)\b/i,
  /\b(refund|tax return|stimulus|prize|winner|won|lottery|sweepstakes|inheritance)\b.{0,60}\b(claim|pending|approved|eligible)\b/i,
  /\b(will be|has been)\s+(closed|terminated|deleted|deactivated|cancel+ed)\b/i,
];

const TECH_SUPPORT_PATTERNS = [
  /\b(your|this)\s+(computer|pc|device|system|mac|iphone|windows)\b.{0,60}\b(infected|virus(es)?|hacked|compromised|blocked|locked|at risk|damaged)\b/i,
  /\b(virus|trojan|spyware|malware|pornographic spyware|zeus)\b.{0,60}\b(detected|found|alert|warning)\b/i,
  /\b(call|contact|dial)\b.{0,40}\b(microsoft|windows|apple|norton|mcafee|geek squad|amazon|paypal)?\s*(support|technician|help ?desk|security team|customer service)\b/i,
  /\b(do not|don't)\s+(close|shut down|restart|turn off|ignore)\b.{0,40}\b(this (page|window)|your (computer|pc|device))\b/i,
  /\b(toll[- ]?free|helpline)\b/i,
  /\berror\s*(code)?\s*[#:]?\s*(0x[0-9a-f]+|dw\d+|#?\d{3,})\b/i,
  /\b(windows|apple|microsoft)\s+(defender|security|firewall)\s+(alert|warning|center)\b/i,
];

const PAYMENT_RAIL_PATTERNS = [
  /\bgift\s*cards?\b/i,
  /\b(google play|apple|itunes|amazon|steam|target|walmart|ebay)\s+(gift\s*)?cards?\b/i,
  /\b(bitcoin|btc|crypto(currency)?|usdt|tether|ethereum)\b.{0,40}\b(atm|wallet|address|send|pay|deposit)\b/i,
  /\b(wire transfer|western union|moneygram|zelle)\b/i,
  /\b(scratch|claim|redemption)\s+code\b/i,
];

const LOGIN_TITLE = /\b(sign[- ]?in|log[- ]?in|log on|verify|verification|account|password|secure|security|update|billing|confirm)\b/i;

function countMatches(patterns, text) {
  return patterns.filter((p) => p.test(text)).length;
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Brand names that are ordinary English words. In page text these brands are
// recognised only through their `phrases` ("Apple ID", "Chase Bank").
const AMBIGUOUS_IN_TEXT = new Set([
  'apple', 'chase', 'discover', 'spectrum', 'meta', 'windows', 'outlook', 'citi',
]);

/** Which brand (if any) does this text present itself as? */
export function claimedBrand(texts) {
  const joined = texts.filter(Boolean).join(' \u2022 ');
  if (!joined) return null;
  const has = (n, flags) => new RegExp(`(^|[^A-Za-z0-9])${escapeRe(n)}([^A-Za-z0-9]|$)`, flags).test(joined);
  for (const brand of BRANDS) {
    const names = [
      ...brand.name.split(' / ').filter((n) => n.length >= 4 && !AMBIGUOUS_IN_TEXT.has(n.toLowerCase())),
      ...brand.keywords.filter((k) => k.length >= 4 && !AMBIGUOUS_IN_TEXT.has(k)),
      ...(brand.phrases || []),
    ];
    if (names.some((n) => has(n, 'i'))) return brand;
    // Short acronyms ("UPS", "IRS", "AOL") only in capitals.
    if (brand.keywords.some((k) => k.length <= 3 && has(k.toUpperCase(), ''))) return brand;
  }
  return null;
}

/**
 * @param {PageFeatures} f
 * @param {{userTrusted?: string[]}} [opts]
 */
export function analyzePage(f, opts = {}) {
  const reasons = [];
  const add = (code, weight, detail) => reasons.push({ code, weight, detail });

  let u;
  try {
    u = new URL(f.url);
  } catch {
    return { risk: 0, reasons };
  }
  const host = normalizeHost(u.hostname);
  const fields = { password: 0, card: 0, ssn: 0, giftCard: 0, otp: 0, ...(f.fields || {}) };
  const asksSecrets = fields.password + fields.card + fields.ssn + fields.giftCard + fields.otp > 0;
  const text = f.text || '';

  // Brand impersonation: the page's identity (title, site name, logo, header)
  // names a brand whose domains this isn't.
  const brand = claimedBrand([f.title, f.siteName, ...(f.identityTexts || [])]);
  let brandName;
  if (brand && !isBrandHost(brand, host)) {
    brandName = brand.name;
    if (asksSecrets) add('impersonates_brand_asks_secrets', 0.65, brand.name);
    else if (LOGIN_TITLE.test(f.title || '')) add('impersonates_brand_login_page', 0.3, brand.name);
  }

  // Sensitive inputs on a site we don't already trust.
  if (fields.password) add('password_field', 0.1);
  if (fields.card) add('card_field', 0.15);
  if (fields.ssn) add('ssn_field', 0.35);
  if (fields.giftCard) add('gift_card_code_field', 0.45);
  if (fields.otp) add('one_time_code_field', 0.1);

  if (u.protocol === 'http:' && asksSecrets && !['localhost', '127.0.0.1'].includes(host)) {
    add('secrets_over_http', 0.45);
  }
  if (asksSecrets && isUserContentHost(host)) add('secrets_on_free_hosting', 0.35);

  const pageReg = registrableDomain(host);
  const foreign = (f.forms || []).filter((form) =>
    form.hasPassword && form.actionHost &&
    registrableDomain(form.actionHost) !== pageReg &&
    !isTrusted(form.actionHost, opts.userTrusted));
  if (foreign.length) add('password_form_posts_elsewhere', 0.4, foreign[0].actionHost);

  // Social-engineering language.
  const urgency = countMatches(URGENCY_PATTERNS, `${f.title || ''}\n${text}`);
  if (urgency >= 2) add('urgent_threatening_language', 0.3, String(urgency));
  else if (urgency === 1) add('urgent_language', 0.1);

  const tech = countMatches(TECH_SUPPORT_PATTERNS, `${f.title || ''}\n${text}`);
  if (tech >= 2 || (tech >= 1 && f.phoneNumbers > 0)) add('tech_support_scam_language', 0.55, String(tech));
  else if (tech === 1) add('tech_support_language', 0.15);

  const pay = countMatches(PAYMENT_RAIL_PATTERNS, text);
  if (pay && (urgency || tech)) add('unusual_payment_request', 0.35);
  else if (pay >= 2) add('unusual_payment_mentions', 0.1);

  if (f.fullscreen) add('forced_fullscreen', tech ? 0.35 : 0.15);

  return { risk: noisyOr(reasons.map((r) => r.weight)), reasons, brand: brandName };
}
