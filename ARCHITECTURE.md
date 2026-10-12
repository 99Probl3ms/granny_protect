# granny_protect — Architecture

A browser extension that protects less technical users (think: grandparents) from
phishing and scam pages. It layers cheap, deterministic checks with a fast
decision model (TypeSafe's **Jev**) used only where the cheap checks are unsure.

> Status: design draft. Nothing here is implemented yet. Jev API details below are
> illustrative; confirm request/response shapes against TypeSafe's docs before
> building the client.

---

## 1. Goals and non-goals

**Goals**
- Stop the user from typing credentials, card numbers or gift-card codes into a
  fraudulent page, and from following "tech support" / "your account is locked"
  scams.
- Warnings a non-technical person understands: one big, calm message and one
  obvious safe action ("Take me back").
- Low false-positive rate. A warning on their real bank trains the user to click
  through every warning.
- Private by default: no browsing history leaves the device unless a page is
  already suspicious.

**Non-goals (v1)**
- Malware / download scanning (leave to the browser and OS).
- Full email-client integration (planned for v2, see §9).
- Ad blocking.

---

## 2. High-level design

```
 ┌─────────────────────── Browser (Manifest V3) ────────────────────────┐
 │                                                                      │
 │  Content script (every page)        Service worker (background)      │
 │  ─────────────────────────          ───────────────────────────      │
 │  • DOM feature extraction   ──msg──▶ • Tier 0: allow/deny lists       │
 │  • Guard password/card inputs        • Tier 1: URL heuristics         │
 │  • Render warning overlay   ◀─verdict• Tier 2: page heuristics        │
 │                                      • Score fusion + verdict cache   │
 │  Popup / options page                • Calls backend for Tier 3       │
 │  • "Is this site safe?"                       │                      │
 │  • Trusted-contact settings                   │                      │
 └───────────────────────────────────────────────┼──────────────────────┘
                                                 │ HTTPS (only gray-zone pages)
                                ┌────────────────▼─────────────────┐
                                │  granny_protect backend (thin)   │
                                │  • Holds Jev API key             │
                                │  • Rate limiting, auth per install│
                                │  • Domain-age / WHOIS / CT lookup │
                                │  • Jev call (Tier 3)              │
                                │  • Feedback + eval logging        │
                                └────────────────┬─────────────────┘
                                                 │
                                         TypeSafe Jev API
```

Why a backend: the Jev key must never ship inside the extension (anyone can unpack
it), and some signals (domain age, certificate-transparency history, shared
verdict cache) need a server anyway. Keep it stateless and small, e.g. a single
serverless function.

---

## 3. Detection pipeline (tiered, cheapest first)

Each tier returns a `risk` in [0, 1] plus human-readable `reasons`. Stop as soon as
a verdict is confident.

### Tier 0 — Lists (≈0 ms, local)
- **Allowlist**: top-N popular domains (e.g. Tranco top 10k) plus sites the family
  marks as trusted (their bank, pharmacy, email). Allowlisted → done, `safe`.
- **Blocklist**: Google Safe Browsing (Update API, local hash-prefix DB), plus
  OpenPhish / PhishTank feeds synced daily into `chrome.storage`. Hit → `block`.
- **Verdict cache**: per-eTLD+1 results with a TTL (e.g. 24 h for safe, 7 d for
  block).

### Tier 1 — URL heuristics (<5 ms, local)
| Signal | Example |
|---|---|
| Punycode / mixed-script homoglyphs | `xn--pypal-4ve.com`, `pаypal.com` (Cyrillic а) |
| Edit distance to an allowlisted brand | `paypa1.com`, `amaz0n-support.com` |
| Brand name outside the registrable domain | `paypal.com.secure-login.xyz` |
| Raw IP host, `@` in URL, very long URL, many subdomains | |
| Risky TLD / free hosting / URL shortener | `.top`, `*.web.app`, `bit.ly` |
| Non-HTTPS | |

### Tier 2 — Page heuristics (<30 ms, content script)
| Signal | Why |
|---|---|
| Password / card / SSN-like inputs on a non-allowlisted domain | Credential harvest |
| Form `action` posts to a different domain | Classic phish kit |
| Page title, logo alt text, or favicon hash matches a known brand, but domain doesn't | Brand impersonation |
| Urgency / fear language ("account suspended", "call Microsoft now", "within 24 hours") | Social engineering |
| Phone numbers + "support" + fullscreen request, `beforeunload` traps, audio autoplay, keyboard lock | Tech-support scam |
| Gift-card / crypto / wire-transfer payment requests | Scam payment rails |
| Domain age < 30 days (from backend) | Most phish domains are new |

### Tier 3 — Jev (≈70–500 ms per vendor claims, backend)
Called **only** when Tiers 0–2 land in the gray zone (e.g. `0.3 ≤ risk < 0.8`), or
when the user focuses a sensitive input on an unverified site. This keeps cost and
latency down and keeps most browsing private.

Jev's three primitives map neatly onto this problem:

- **Noul** (yes/no probability): "Is this page attempting to trick the user into
  giving credentials, money or remote access?" → `p_phish`.
- **Choice** (pick from options): category, used to tailor the warning text:
  `credential_phish | tech_support_scam | fake_shop | gift_card_or_payment_scam |
  impersonation_other | benign`.
- **Score** (ordered scale), optional: urgency/pressure level of the page copy.

Input to Jev is a compact, privacy-stripped summary, not the raw page:

```json
{
  "url_domain": "secure-paypa1-verify.top",
  "claimed_brand": "PayPal",
  "title": "PayPal - Confirm your identity",
  "visible_text_excerpt": "Your account has been limited... (first ~1.5k chars)",
  "forms": [{"fields": ["email", "password"], "action_domain": "x9k2.ru"}],
  "heuristic_reasons": ["brand_domain_mismatch", "cross_domain_form", "domain_age_3d"]
}
```

Never send typed form values, cookies, full query strings, or text from pages
already allowlisted.

### Score fusion
Start simple and explainable, then tune on the eval set (§7):

```
risk = max(blocklist_hit ? 1 : 0,
           w1 * heuristic_risk + w2 * p_phish)

risk ≥ 0.85            → BLOCK  (full-page interstitial)
0.6 ≤ risk < 0.85      → WARN   (overlay; sensitive inputs locked until user confirms)
risk < 0.6             → ALLOW
```

Hard rules override the model in both directions: allowlist always wins;
blocklist hit is always blocked. Jev alone should not be able to block an
allowlisted site.

Put the model behind an interface (`DecisionModel.classify(summary)`) so Jev can
be swapped for a local classifier later. Commentators point out that for a narrow
task a purpose-trained classifier can match a general decision model; logged,
labeled Jev decisions (§7) are the training data for that.

---

## 4. Latency strategy

A remote call can't run before every page paints without making browsing feel
broken. Instead:

1. Tiers 0–1 run on `webNavigation.onBeforeNavigate`. Blocklist hits redirect to
   the extension's interstitial page before the phish loads.
2. The page loads normally. Tier 2 runs at `DOMContentLoaded`.
3. **Input guard**: on a non-allowlisted site, the content script intercepts the
   first `focus`/`keydown` on a password, card or gift-card field and the form
   `submit`. If a verdict is still pending, show a "Checking this site…" shimmer
   (up to ~800 ms) before allowing typing. This is the moment that matters, and
   Jev is fast enough for it.
4. Speculatively start the Jev call as soon as Tier 2 flags a gray-zone page, so
   the result is usually ready before the user reaches the input.

---

## 5. User experience (designed for older users)

- Large type, high contrast, one sentence of explanation, no jargon:
  *"This page is pretending to be PayPal. Don't enter your password here."*
- One big primary button: **"Take me to safety"** (back / new tab). Proceeding
  anyway is a small text link, behind a second confirmation.
- Category-specific advice from Jev's Choice output, e.g. tech-support scam:
  *"Microsoft will never ask you to call them. Close this page. Your computer is
  fine."*
- **Trusted contact (optional)**: when a BLOCK is overridden or a tech-support
  scam is detected, notify a family member (email/SMS via the backend), with
  explicit consent at setup.
- Options page managed by the family member: trusted sites, contact, sensitivity.

---

## 6. Privacy and security

- Default local-only: Tiers 0–2 run on device. Only gray-zone summaries go to the
  backend; say so plainly in onboarding and the store listing.
- Strip query strings and fragments, redact emails/phone numbers/long digit runs
  in text excerpts before sending.
- Per-install random ID for rate limiting; no accounts required.
- Minimal permissions: `storage`, `webNavigation`, `scripting`, `alarms`, host
  access `<all_urls>` (needed for content scripts; justify in the store review).
- Content-script → background messages are validated; page JavaScript must not be
  able to forge a "safe" verdict (use an isolated world, never trust
  `window.postMessage`).
- Treat page text sent to Jev as untrusted. Since Jev only returns from
  developer-defined options, prompt injection can at most skew a score, which is
  another reason hard rules stay outside the model.

---

## 7. Evaluation and feedback loop

- **Eval set**: recent phish URLs (OpenPhish/PhishTank, snapshotted, since phish
  pages die in hours) + benign pages including look-alike legitimate ones (small
  banks, login pages, tech-support pages of real vendors).
- Track precision/recall per tier and end to end; tune fusion weights and
  thresholds for very low false positives on the benign set.
- In-product feedback: "This site is safe" / "Report this site" buttons → backend.
- Log (redacted) feature summaries + Jev outputs + final labels to train a cheaper
  local model later and to catch Jev drift after vendor updates.
- Kill switch: backend flag to disable Tier 3 (cost spike, outage) and fall back
  to heuristics-only.

---

## 8. Proposed repository layout

```
granny_protect/
├── extension/
│   ├── manifest.json            # MV3
│   ├── src/
│   │   ├── background/
│   │   │   ├── index.ts         # service worker entry, navigation hooks
│   │   │   ├── lists.ts         # Tier 0: allow/block lists, Safe Browsing
│   │   │   ├── urlHeuristics.ts # Tier 1
│   │   │   ├── fusion.ts        # score fusion + thresholds
│   │   │   ├── cache.ts
│   │   │   └── apiClient.ts     # talks to backend
│   │   ├── content/
│   │   │   ├── extract.ts       # DOM feature extraction (Tier 2 inputs)
│   │   │   ├── pageHeuristics.ts
│   │   │   ├── inputGuard.ts    # intercept sensitive fields / submit
│   │   │   └── overlay.ts       # warning UI (shadow DOM)
│   │   ├── interstitial/        # full-page block screen
│   │   ├── popup/
│   │   ├── options/
│   │   └── shared/types.ts      # Verdict, Signal, PageSummary
│   └── data/                    # bundled brand list, top-domains snapshot
├── backend/
│   ├── src/
│   │   ├── classify.ts          # POST /classify → domain intel + Jev
│   │   ├── models/DecisionModel.ts
│   │   ├── models/jev.ts        # Jev adapter
│   │   ├── domainIntel.ts       # WHOIS/RDAP age, CT logs
│   │   └── feedback.ts
│   └── ...
├── eval/                        # datasets, runner, metrics
└── ARCHITECTURE.md
```

Stack suggestion: TypeScript everywhere, Vite + `@crxjs/vite-plugin` (or WXT) for
the extension so one codebase builds for Chrome, Edge and Firefox; backend as a
Cloudflare Worker or Vercel function.

---

## 9. Roadmap

1. **MVP**: Tiers 0–2 + input guard + simple overlay. Fully local, no backend.
   Measure false positives on real browsing.
2. **Jev**: backend, Tier 3 for gray zone, category-specific warnings.
3. **Family features**: trusted contact alerts, managed options.
4. **Webmail**: content scripts for Gmail/Outlook web that scan links and sender
   mismatches in open messages, reusing the same pipeline.
5. **Local model**: distill logged decisions into an on-device classifier
   (e.g. ONNX/WebGPU) to cut cost and send less data off-device.

---

## 10. Open questions

- Which browsers are in scope for v1? (Chrome + Edge share MV3; Firefox needs
  small manifest tweaks; Safari needs an Xcode wrapper.)
- Who installs and configures it: the user, or a family member remotely?
- Budget per user per month for Jev and domain-intel lookups?
- Store-review risk around `<all_urls>`; prepare a clear justification.
