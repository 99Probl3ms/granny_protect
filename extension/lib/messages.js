// Plain-language text for warnings. Written for someone who isn't technical:
// short sentences, no jargon, tell them what to do.

const HEADLINES = {
  insecure_password: () => "This page isn't safe for passwords.",
  credential_phish: (brand) => brand
    ? `This page is pretending to be ${brand}.`
    : 'This page may be trying to steal your password.',
  tech_support_scam: () => 'This is a fake warning. Your computer is fine.',
  payment_scam: () => 'This page looks like a scam asking for money.',
  suspicious_site: () => 'This website looks dangerous.',
};

const ADVICE = {
  insecure_password: () =>
    "Your organization doesn't allow typing passwords into pages that aren't encrypted. The password boxes on this page are locked. If you need this site for work, contact IT.",
  credential_phish: (brand) => brand
    ? `Don't type your password or card number here. If you're worried about your ${brand} account, close this page and go to ${brand} the way you normally do.`
    : "Don't type your password, card number or any personal details here.",
  tech_support_scam: () =>
    "Don't call any phone number on this page and don't let anyone connect to your computer. Real companies like Microsoft and Apple never show warnings like this. Just close the page.",
  payment_scam: () =>
    'No real company or government office asks to be paid in gift cards, Bitcoin or wire transfers. Don\'t send money or read out any codes.',
  suspicious_site: () => "Don't type any personal information here. If you're not sure, ask someone you trust.",
};

const REASONS = {
  known_phishing_site: 'This site is on a list of known scam websites.',
  lookalike_brand_domain: (d) => `The web address is made to look like ${d}'s, using look-alike letters.`,
  typosquat_brand_domain: (d) => `The web address is a misspelling of ${d}'s.`,
  brand_in_unrelated_domain: (d) => `The web address uses the name ${d}, but it isn't ${d}'s website.`,
  domain_in_subdomain: 'The web address hides another company\'s address inside it.',
  impersonates_brand_asks_secrets: (d) => `The page shows ${d}'s name but isn't on ${d}'s website, and it asks for private details.`,
  impersonates_brand_login_page: (d) => `The page uses ${d}'s name but isn't on ${d}'s website.`,
  ip_address_host: 'The web address is a string of numbers instead of a name.',
  credentials_in_url: 'The web address is built to disguise where it really goes.',
  non_ascii_domain: 'The web address uses unusual letters that can look like normal ones.',
  not_https: 'The connection to this site isn\'t secure.',
  secrets_over_http: 'It asks for private details over an insecure connection.',
  secrets_on_free_hosting: 'It asks for private details on a free website that anyone can create.',
  password_form_posts_elsewhere: 'What you type here would be sent to a different website.',
  gift_card_code_field: 'It asks for gift card codes.',
  ssn_field: 'It asks for your Social Security number.',
  urgent_threatening_language: 'It tries to scare or rush you.',
  tech_support_scam_language: 'It claims your computer has a problem and tells you to call someone.',
  unusual_payment_request: 'It asks for payment in gift cards, crypto or wire transfer.',
  forced_fullscreen: 'It took over your whole screen.',
  risky_tld: 'The web address ending is often used by scam sites.',
  free_hosting: 'It\'s on a free website service that scammers often use.',
  password_on_http_page: 'This page isn\'t encrypted (http), so a password typed here could be read by others.',
  password_sent_over_http: 'This page would send your password without encryption (http).',
  brand_in_path: (d) => `The link mentions ${d}, but it doesn't go to ${d}'s website.`,
  brand_in_userinfo: (d) => `The web address starts with ${d}'s name to hide where it really goes.`,
  suspicious_words_in_domain: 'The web address uses words like "login" or "verify" to look official.',
};

// For destinations we couldn't confirm either way ("needs_review"). Softer:
// there are warning signs, not proof.
const REVIEW_HEADLINES = {
  credential_phish: (brand) => brand
    ? `This website might be pretending to be ${brand}.`
    : "We couldn't confirm this website is safe.",
  tech_support_scam: () => 'This page may be a fake computer warning.',
  payment_scam: () => 'This page may be a scam asking for money.',
  suspicious_site: () => "We couldn't confirm this website is safe.",
};

const REVIEW_ADVICE = {
  credential_phish: (brand) => brand
    ? `If you meant to visit ${brand}, it's safer to go there the way you normally do. Don't type your password here unless you're sure.`
    : "If you weren't expecting this website, go back. Don't type passwords or card numbers here unless you're sure.",
  tech_support_scam: ADVICE.tech_support_scam,
  payment_scam: ADVICE.payment_scam,
  suspicious_site: () => "It has some warning signs. If you weren't expecting to visit it, go back.",
};

/** Build user-facing text from a verdict. */
export function describe(verdict) {
  const cat = verdict.category || 'suspicious_site';
  const review = verdict.action === 'needs_review';
  const reasons = [];
  for (const r of verdict.reasons || []) {
    const t = REASONS[r.code];
    if (!t) continue;
    const line = typeof t === 'function' ? t(r.detail || 'a company') : t;
    if (!reasons.includes(line)) reasons.push(line);
    if (reasons.length >= 3) break;
  }
  return {
    headline: (review ? REVIEW_HEADLINES : HEADLINES)[cat](verdict.brand),
    advice: (review ? REVIEW_ADVICE : ADVICE)[cat](verdict.brand),
    reasons,
  };
}
