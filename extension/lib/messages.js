// Plain-language text for warnings. Written for someone who isn't technical:
// short sentences, no jargon, tell them what to do.

const HEADLINES = {
  credential_phish: (brand) => brand
    ? `This page is pretending to be ${brand}.`
    : 'This page may be trying to steal your password.',
  tech_support_scam: () => 'This is a fake warning. Your computer is fine.',
  payment_scam: () => 'This page looks like a scam asking for money.',
  suspicious_site: () => 'This website looks dangerous.',
};

const ADVICE = {
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
};

/** Build user-facing text from a verdict. */
export function describe(verdict) {
  const cat = verdict.category || 'suspicious_site';
  const reasons = [];
  for (const r of verdict.reasons || []) {
    const t = REASONS[r.code];
    if (!t) continue;
    const line = typeof t === 'function' ? t(r.detail || 'a company') : t;
    if (!reasons.includes(line)) reasons.push(line);
    if (reasons.length >= 3) break;
  }
  return {
    headline: HEADLINES[cat](verdict.brand),
    advice: ADVICE[cat](verdict.brand),
    reasons,
  };
}
