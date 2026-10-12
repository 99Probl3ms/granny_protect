// Representative destinations for evaluating local (URL-level) decisions.
//
// label     what the destination really is: malicious | benign | internal
// expect    the decision local screening should make today:
//           allow | needs_review | block
// miss      set on malicious entries that local checks can't catch (expect
//           is then 'allow'); these are what Jev / page screening are for.
//
// Malicious URLs are modelled on real phishing patterns (brand in subdomain,
// look-alike letters, free hosting, misspellings, credential tricks). Hosts
// listed in BLOCKLIST_FEED stand in for a downloaded OpenPhish feed.

export const BLOCKLIST_FEED = [
  'http://secure-account-update-center.com/',
  'https://chase-verify-session.net/login.php',
  'https://sites.google.com/view/wellsfargo-secure-portal',
  'https://docs.google.com/forms/d/e/1FAIpQLSf-phish-example/viewform',
  'http://203.0.113.45/apple/id/',
];

export const DESTINATIONS = [
  // --- malicious: on the blocklist -----------------------------------------
  { label: 'malicious', expect: 'block', url: 'http://secure-account-update-center.com/paypal/signin', note: 'listed host, any path' },
  { label: 'malicious', expect: 'block', url: 'https://chase-verify-session.net/', note: 'listed host, other page' },
  { label: 'malicious', expect: 'block', url: 'https://sites.google.com/view/wellsfargo-secure-portal', note: 'listed page on shared host' },
  { label: 'malicious', expect: 'block', url: 'https://docs.google.com/forms/d/e/1FAIpQLSf-phish-example/viewform?usp=sf_link', note: 'listed Google Form, with query' },
  { label: 'malicious', expect: 'block', url: 'http://203.0.113.45/apple/id/', note: 'listed IP address' },

  // --- malicious: look-alike and misspelled domains -------------------------
  { label: 'malicious', expect: 'needs_review', url: 'https://xn--pypal-4ve.com/signin', note: 'Cyrillic а in paypal' },
  { label: 'malicious', expect: 'needs_review', url: 'https://paypa1.com/', note: 'digit 1 for l' },
  { label: 'malicious', expect: 'needs_review', url: 'https://amaz0n.com/gp/signin', note: 'digit 0 for o' },
  { label: 'malicious', expect: 'needs_review', url: 'https://amazom.com/', note: 'one-letter typo' },
  { label: 'malicious', expect: 'needs_review', url: 'https://netf1ix.com/login', note: 'digit 1 for l' },
  { label: 'malicious', expect: 'needs_review', url: 'https://rnicrosoft.com/', note: 'rn for m' },
  { label: 'malicious', expect: 'needs_review', url: 'https://xn--80ak6aa92e.com/', note: 'all-Cyrillic apple look-alike' },
  { label: 'malicious', expect: 'needs_review', url: 'https://wellsfarqo.com/', note: 'q for g' },
  { label: 'malicious', expect: 'needs_review', url: 'https://coinbsae.com/', note: 'swapped letters' },

  // --- malicious: brand name in someone else's domain -----------------------
  { label: 'malicious', expect: 'needs_review', url: 'https://paypal.com.secure-login.xyz/webscr', note: 'brand domain in subdomain' },
  { label: 'malicious', expect: 'needs_review', url: 'https://www.paypal.com.account-check.io/', note: 'brand domain in subdomain' },
  { label: 'malicious', expect: 'needs_review', url: 'https://appleid.apple.com.verify-account.info/', note: 'brand login host in subdomain' },
  { label: 'malicious', expect: 'needs_review', url: 'https://paypal-account-verify.top/signin', note: 'brand + verify words + risky TLD' },
  { label: 'malicious', expect: 'needs_review', url: 'https://amazon-billing-update.net/', note: 'brand + billing/update words' },
  { label: 'malicious', expect: 'needs_review', url: 'https://appleid-verify-account.com/', note: 'apple keyword + verify/account' },
  { label: 'malicious', expect: 'needs_review', url: 'https://login-microsoftonline-secure.xyz/', note: 'brand + login/secure + risky TLD' },
  { label: 'malicious', expect: 'needs_review', url: 'https://chase-online-banking-alert.com/', note: 'chase token + many hyphens' },
  { label: 'malicious', expect: 'needs_review', url: 'https://wellsfargo-secure-login.co/', note: 'brand + secure/login' },
  { label: 'malicious', expect: 'needs_review', url: 'https://bankofamerica-alert.support/', note: 'brand + risky TLD' },
  { label: 'malicious', expect: 'needs_review', url: 'https://usps-redelivery-fee.top/', note: 'parcel scam' },
  { label: 'malicious', expect: 'needs_review', url: 'https://ups-parcel-hold.icu/', note: 'parcel scam' },
  { label: 'malicious', expect: 'needs_review', url: 'https://fedex-delivery-confirm.shop/', note: 'parcel scam' },
  { label: 'malicious', expect: 'needs_review', url: 'https://irs-tax-refund-claim.online/', note: 'tax refund scam' },
  { label: 'malicious', expect: 'needs_review', url: 'https://medicare-card-renewal.site/', note: 'benefits scam' },
  { label: 'malicious', expect: 'needs_review', url: 'https://netflix-billing-update.xyz/', note: 'subscription scam' },
  { label: 'malicious', expect: 'needs_review', url: 'https://geeksquad-renewal-invoice.live/', note: 'fake invoice / refund scam' },
  { label: 'malicious', expect: 'needs_review', url: 'https://norton-subscription-refund.click/', note: 'fake invoice / refund scam' },
  { label: 'malicious', expect: 'needs_review', url: 'https://secure.chase.com.auth-session.cfd/', note: 'brand login host in subdomain' },

  // --- malicious: free hosting and credential tricks ------------------------
  { label: 'malicious', expect: 'needs_review', url: 'https://microsoft-office365-login.web.app/', note: 'brand on free hosting' },
  { label: 'malicious', expect: 'needs_review', url: 'https://outlook-webmail-verify.weebly.com/', note: 'brand on free site builder' },
  { label: 'malicious', expect: 'needs_review', url: 'https://sites.google.com/view/paypal-secure-login', note: 'brand in path on shared host' },
  { label: 'malicious', expect: 'needs_review', url: 'https://storage.googleapis.com/bucket-8812/amazon/login.html', note: 'brand in path on cloud storage' },
  { label: 'malicious', expect: 'needs_review', url: 'https://www.paypal.com@evil-example.ru/', note: 'brand before @' },
  { label: 'malicious', expect: 'needs_review', url: 'http://198.51.100.23/paypal/webscr/login.php', note: 'public IP + brand path' },

  // --- malicious: not catchable from the address alone ----------------------
  { label: 'malicious', expect: 'allow', miss: 'unknown brand (crypto wallet)', url: 'https://metamask-restore-wallet.com/' },
  { label: 'malicious', expect: 'allow', miss: 'neutral domain, scam is in the page', url: 'https://account-review-center.com/login' },
  { label: 'malicious', expect: 'allow', miss: 'neutral domain, tech-support page content', url: 'https://win-alert-9921.online/' },
  { label: 'malicious', expect: 'allow', miss: 'shortener hides destination (redirect screening catches it)', url: 'https://bit.ly/3xPhish' },
  { label: 'malicious', expect: 'allow', miss: 'neutral domain, fake shop', url: 'https://best-deals-outlet-store.com/' },

  // --- benign: well-known sites and real login pages -------------------------
  { label: 'benign', expect: 'allow', url: 'https://www.paypal.com/signin' },
  { label: 'benign', expect: 'allow', url: 'https://www.paypal-community.com/', note: 'PayPal-owned, brand in name' },
  { label: 'benign', expect: 'allow', url: 'https://accounts.google.com/ServiceLogin' },
  { label: 'benign', expect: 'allow', url: 'https://login.microsoftonline.com/common/oauth2/authorize' },
  { label: 'benign', expect: 'allow', url: 'https://appleid.apple.com/sign-in' },
  { label: 'benign', expect: 'allow', url: 'https://secure.chase.com/web/auth/' },
  { label: 'benign', expect: 'allow', url: 'https://connect.secure.wellsfargo.com/auth/login/present' },
  { label: 'benign', expect: 'allow', url: 'https://www.amazon.co.uk/ap/signin' },
  { label: 'benign', expect: 'allow', url: 'https://tools.usps.com/go/TrackConfirmAction' },
  { label: 'benign', expect: 'allow', url: 'https://www.irs.gov/refunds' },
  { label: 'benign', expect: 'allow', url: 'https://my.ssa.gov/' },
  { label: 'benign', expect: 'allow', url: 'https://www.medicare.gov/account/login' },
  { label: 'benign', expect: 'allow', url: 'https://www.nytimes.com/2026/10/01/business/paypal-earnings.html' },
  { label: 'benign', expect: 'allow', url: 'https://en.wikipedia.org/wiki/Phishing' },
  { label: 'benign', expect: 'allow', url: 'https://www.aboutamazon.com/news', note: 'Amazon-owned, brand in name' },
  { label: 'benign', expect: 'allow', url: 'https://www.theupsstore.com/', note: 'UPS-owned' },
  { label: 'benign', expect: 'allow', url: 'https://www.discovercard.com/', note: 'Discover-owned' },

  // --- benign: long tail that shares words with brands or scams --------------
  { label: 'benign', expect: 'allow', url: 'https://www.applebees.com/en/menu', note: 'contains "apple"' },
  { label: 'benign', expect: 'allow', url: 'https://pineapplefarm.com/', note: 'contains "apple"' },
  { label: 'benign', expect: 'allow', url: 'https://purchase-orders.com/', note: 'contains "chase"' },
  { label: 'benign', expect: 'allow', url: 'https://discoverlosangeles.com/', note: 'contains "discover"' },
  { label: 'benign', expect: 'allow', url: 'https://grandmas-recipes.com/login' },
  { label: 'benign', expect: 'allow', url: 'https://handmade-quilts.com/checkout' },
  { label: 'benign', expect: 'allow', url: 'https://joesplumbing-austin.com/contact' },
  { label: 'benign', expect: 'allow', url: 'https://www.fnbo.com/', note: 'small bank, not in lists' },
  { label: 'benign', expect: 'allow', url: 'https://login.salesforce.com/', note: 'login word, unknown to lists' },
  { label: 'benign', expect: 'allow', url: 'https://secure-booking-hotels.com/', note: 'secure word' },
  { label: 'benign', expect: 'allow', url: 'https://auth0.com/docs', note: 'auth word' },
  { label: 'benign', expect: 'allow', url: 'https://myblog.example/review-of-paypal-fees', note: 'brand in path of a blog' },
  { label: 'benign', expect: 'allow', url: 'https://someone.github.io/portfolio/', note: 'free hosting, no brand' },
  { label: 'benign', expect: 'allow', url: 'https://docs.google.com/document/d/1abc/edit', note: 'shared host, no brand' },
  { label: 'benign', expect: 'allow', url: 'https://xn--mnchen-3ya.de/', note: 'münchen.de, legit IDN' },
  { label: 'benign', expect: 'allow', url: 'https://xn--bcher-kva.de/', note: 'bücher.de, legit IDN' },
  { label: 'benign', expect: 'allow', url: 'http://old-family-site.net/', note: 'plain http' },
  { label: 'benign', expect: 'allow', url: 'https://bit.ly/3xRecipe', note: 'shortener' },
  { label: 'benign', expect: 'allow', url: 'https://shop.example-store.xyz/', note: 'risky TLD alone' },
  { label: 'benign', expect: 'allow', url: 'https://www.costcotravel.com/', note: 'Costco-owned travel site' },
  { label: 'benign', expect: 'allow', url: 'https://www.mychart.org/', note: 'patient portal' },

  // --- internal destinations --------------------------------------------------
  { label: 'internal', expect: 'allow', url: 'http://localhost:3000/login' },
  { label: 'internal', expect: 'allow', url: 'http://127.0.0.1:8080/admin' },
  { label: 'internal', expect: 'allow', url: 'http://192.168.1.1/', note: 'home router' },
  { label: 'internal', expect: 'allow', url: 'http://10.0.0.5/login.php' },
  { label: 'internal', expect: 'allow', url: 'http://172.16.4.2/' },
  { label: 'internal', expect: 'allow', url: 'http://intranet/' },
  { label: 'internal', expect: 'allow', url: 'http://wiki.corp/' },
  { label: 'internal', expect: 'allow', url: 'http://nas.local:5000/' },
  { label: 'internal', expect: 'allow', url: 'http://printer.lan/' },
  { label: 'internal', expect: 'allow', url: 'https://jira.internal/browse/IT-12' },
  { label: 'internal', expect: 'allow', url: 'http://router.home.arpa/' },
  { label: 'internal', expect: 'allow', url: 'http://[::1]:8080/' },
  { label: 'internal', expect: 'allow', url: 'http://[fd00::1]/' },
  { label: 'internal', expect: 'allow', url: 'http://my-pc:8080/' },
];
