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
- **Holds risky links before they load.** Clicking a link to a suspicious
  site, opening it in a new tab, Ctrl/middle-clicking it or pressing Enter on
  it shows a check page first, and the site isn't contacted until the user
  decides. Typed addresses, pop-ups and redirects are checked too.
- **Locks sensitive fields** (password, card, Social Security number, gift-card
  code) on risky pages until the user deliberately chooses to continue.
- **Explains in plain words**, with one big **Take me to safety** button.
  Every site gets one of three decisions: **allow**, **needs review** (warning
  signs: one click continues) or **block** (known or near-certain scam:
  continuing takes two confirmations).

Well-known sites (banks, big shops, email providers, news) and sites on your
own network (router, printer, `localhost`, intranet) are never flagged.
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
├── background.js          service worker: lists, decisions, navigation gating
├── content/content.js     link gate, load-time check, page screening, input lock, overlay
├── interstitial/          gate page (block and review modes)
├── popup/                 toolbar popup
├── onboarding/            welcome page shown on install
├── ui/common.css          shared styles for extension pages
└── lib/                   detection logic (plain ES modules, unit-tested in Node)
    ├── domain.js          registrable domain, punycode, internal hosts
    ├── brands.js          impersonated brands and their real domains
    ├── trustedDomains.js  popular sites that are never flagged
    ├── lists.js           trusted / user-content / blocklist matching
    ├── dnrRules.js        blocklist → Chrome declarativeNetRequest redirect rules
    ├── urlHeuristics.js   web address checks
    ├── pageHeuristics.js  page content checks
    ├── fusion.js          combines checks into allow / needs_review / block
    ├── score.js           score combination helper
    └── messages.js        plain-language warning text
tests/                     unit tests (node:test) and the destination test set
scripts/eval.mjs           confusion matrix for the destination test set
e2e/                       Playwright tests: smoke test, navigation matrix, test pages
```

### How a decision is made

1. **Internal?** `localhost`, private IP addresses, single-word hostnames and
   `.local` / `.lan` / `.internal` / `.corp` / `home.arpa`: allow.
2. **Trusted?** A built-in popular or brand domain, or one the user trusts:
   allow. Hosts where anyone can publish (Google Forms, SharePoint,
   `*.web.app`, ...) are never trusted.
3. **Blocklisted?** Block. Listed sites are turned into Chrome
   `declarativeNetRequest` redirect rules (`lib/dnrRules.js`), so the browser
   goes straight to the block page without contacting the site. Listed domains
   share a few rules. A single bad page on a shared host, such as one Google
   Form, gets its own rule, up to 900 of them. Anything over that limit is
   caught by a navigation check instead.
4. **Otherwise** each check adds a weighted signal. Signals are combined as
   `1 − Π(1 − weight)`. A score of **0.5** or more needs review, **0.85** or
   more blocks. The web address alone is checked before the page loads, and
   page content is added once it has loaded.

### Where navigations are gated

| Gate | Catches | Site contacted? |
|---|---|---|
| Blocklist redirect rules | Listed sites, from any source | No |
| Link gate (content script) | Link clicks, new tabs, Ctrl/middle click, keyboard Enter | No |
| Navigation and redirect checks | Typed addresses, `window.open`, script and meta redirects, server redirects | May be, but the page isn't shown |
| Load-time check | Any page that slips past the above | Yes; page hidden as it starts |
| Page screening | Risky page content | Yes; overlay and locked fields |

Links are screened in the background as the page loads (and when links are
added or change), so clicks on links already known to be safe aren't touched.
Links the page handles itself, such as in single-page apps, are left alone.

To tune detection, adjust the weights in `lib/urlHeuristics.js` and
`lib/pageHeuristics.js` or the thresholds in `lib/fusion.js`, then run the
tests.

### Tests

Node 20 or later.

```sh
npm test            # unit tests, including every entry in the destination test set
npm run eval        # confusion matrix for the destination test set
npm run test:e2e    # loads the extension in Chromium: smoke test + navigation matrix
```

The destination test set (`tests/fixtures/destinations.js`) holds malicious,
benign and internal addresses with the decision each should get. Malicious
ones that address checks can't catch are marked as known misses.

The end-to-end test needs Playwright and a Chromium build. If Playwright isn't
installed in this project, point to an existing install:

```sh
PLAYWRIGHT_PATH=/path/to/node_modules/playwright/index.mjs npm run test:e2e
```

It serves local test pages under fake hostnames (such as
`paypal-account-verify.top`), so it needs no network access. The navigation
matrix tries 11 ways of navigating (link click, new tab, Ctrl/middle click,
keyboard, typed address, `window.open`, server/script/meta redirects) against a
blocked, a needs-review and a safe destination, and checks whether the site's
server was contacted.

## Known limitations

- Brand coverage is a hand-picked list of about 45 companies that scammers
  commonly impersonate. Fakes of other companies are caught only by the
  general checks.
- The domain-suffix handling covers common multi-part endings (`.co.uk`,
  `.com.au`, ...), not the full Public Suffix List.
- No domain-age check yet, which would need a backend.
- A determined page can still hide the warning overlay. Sensitive fields stay
  locked anyway.
- Sites that need review, reached by a typed address, `window.open` or a
  redirect, receive the request before the tab moves to the check page. The
  page itself is never shown.
- "Open link in new tab" from the right-click menu, form submissions and
  embedded frames aren't checked before loading; the destination is checked
  when it arrives.
- The block page has to be reachable from websites so Chrome can redirect to
  it, which lets a site detect that the extension is installed.
- Chrome and Edge only for now.

## Roadmap

See [ARCHITECTURE.md](ARCHITECTURE.md). Next up:

1. A small backend and Jev for pages the local checks can't decide.
2. An optional alert to a family member.
3. Checking links in webmail.
