# Granny Protect

A Chrome extension that warns people, especially less technical users, before
they type a password, card number or gift-card code into a scam website.

> **Status: proof of concept.** All checking runs on the device. The fast
> decision model (TypeSafe's Jev) and the backend described in
> [ARCHITECTURE.md](ARCHITECTURE.md) are not connected yet.

## What it does

- **Blocks known scam sites before they load.** Uses the public
  [OpenPhish](https://openphish.com/) feed, refreshed every 12 hours. Chrome
  redirects listed sites to a block page before any request is sent, so the
  scam site never hears from the user's browser.
- **Spots fake web addresses:** look-alike letters (`pаypal.com` with a
  Cyrillic "а"), misspelled brands (`paypa1.com`, `amazom.com`), and brand names
  inside someone else's address (`paypal.com.secure-login.xyz`).
- **Reads the page:** a page using a bank's or company's name when it isn't on
  that company's site, password forms that send what you type to another site,
  pressure language ("your account will be closed within 24 hours"), fake virus
  warnings with a phone number, and requests for gift cards or crypto.
- **Locks sensitive fields** (password, card, Social Security number, gift-card
  code) on risky pages until the user deliberately chooses to continue.
- **Explains in plain words**, with one big **Take me to safety** button.
  Continuing anyway takes two confirmations.

Well-known sites (banks, big shops, email providers, news) are never flagged.
Ordinary login and checkout pages on unknown sites aren't flagged either.

## Install (for testing)

1. Download or clone this repository.
2. In Chrome (or Edge), open `chrome://extensions` (`edge://extensions` in Edge).
3. Turn on **Developer mode** (top right).
4. Click **Load unpacked** and choose the `extension/` folder.
5. A welcome page opens. Pin the green shield to the toolbar so it's easy to find.

No build step and no dependencies. After editing a file, click the reload icon
on the extension's card in `chrome://extensions`.

Requires Chrome 116 or later.

## Using it

- **Warnings appear on their own.** Nothing to do until a page looks risky.
- **Click the shield** in the toolbar to see whether the current site looks
  safe and why.
- **"I trust this website"** in the shield popup stops checks on a site you
  know is fine, such as a small local bank. **"Stop trusting this website"**
  undoes it.
- **"I understand the risk"** on a warning lets you continue to that site for
  the rest of the browser session.

## Privacy

All checks happen in the browser. No page content, address or browsing history
leaves the device. The only network request the extension makes itself is a
download of the public OpenPhish list of scam addresses.

## Development

```
extension/
├── manifest.json          Manifest V3
├── background.js          service worker: lists, verdicts, messages, block redirect
├── content/content.js     page feature extraction, input lock, warning overlay
├── interstitial/          full-page block screen
├── popup/                 toolbar popup
├── onboarding/            welcome page shown on install
├── ui/common.css          shared styles for extension pages
└── lib/                   detection logic (plain ES modules, unit-tested in Node)
    ├── domain.js          registrable domain, punycode decoding
    ├── brands.js          impersonated brands and their real domains
    ├── trustedDomains.js  popular sites that are never flagged
    ├── lists.js           trusted / user-content / blocklist matching
    ├── dnrRules.js        blocklist → Chrome declarativeNetRequest redirect rules
    ├── urlHeuristics.js   web address checks
    ├── pageHeuristics.js  page content checks
    ├── fusion.js          combines checks into allow / warn / block
    ├── score.js           score combination helper
    └── messages.js        plain-language warning text
tests/                     unit tests (node:test)
e2e/                       Playwright smoke test and test pages
```

### How a verdict is made

1. **Trusted?** A built-in popular or brand domain, or one the user trusts:
   allow. Hosts where anyone can publish (Google Forms, SharePoint,
   `*.web.app`, ...) are never trusted.
2. **Blocklisted?** Block. Listed sites are turned into Chrome
   `declarativeNetRequest` redirect rules (`lib/dnrRules.js`), so the browser
   goes straight to the block page without contacting the site. Listed domains
   share a few rules. A single bad page on a shared host, such as one Google
   Form, gets its own rule, up to 900 of them. Anything over that limit is
   caught by a navigation check instead.
3. **Otherwise** each check adds a weighted signal. Signals are combined as
   `1 − Π(1 − weight)`. A score of **0.6** or more warns, **0.85** or more
   blocks. The web address alone is checked before the page loads, and page
   content is added once it has loaded.

To tune detection, adjust the weights in `lib/urlHeuristics.js` and
`lib/pageHeuristics.js` or the thresholds in `lib/fusion.js`, then run the
tests.

### Tests

Node 20 or later.

```sh
npm test            # unit tests for the detection logic
npm run test:e2e    # loads the extension in Chromium and checks real behaviour
```

The end-to-end test needs Playwright and a Chromium build. If Playwright isn't
installed in this project, point to an existing install:

```sh
PLAYWRIGHT_PATH=/path/to/node_modules/playwright/index.mjs npm run test:e2e
```

It serves local test pages under fake hostnames (such as
`paypal-account-verify.top`), so it needs no network access.

## Known limitations

- Brand coverage is a hand-picked list of about 45 companies that scammers
  commonly impersonate. Fakes of other companies are caught only by the
  general checks.
- The domain-suffix handling covers common multi-part endings (`.co.uk`,
  `.com.au`, ...), not the full Public Suffix List.
- No domain-age check yet, which would need a backend.
- A determined page can still hide the warning overlay. Sensitive fields stay
  locked anyway.
- The block page has to be reachable from websites so Chrome can redirect to
  it, which lets a site detect that the extension is installed.
- Chrome and Edge only for now.

## Roadmap

See [ARCHITECTURE.md](ARCHITECTURE.md). Next up:

1. A small backend and Jev for pages the local checks can't decide.
2. An optional alert to a family member.
3. Checking links in webmail.
