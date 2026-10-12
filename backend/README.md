# granny_protect backend (Tier 3)

A small, stateless service that holds the Jev API key and answers one question
for the extension: is this page trying to trick the user?

```
extension ──POST /classify {summary}──▶ backend ──POST decisions──▶ Jev (typesafe/jev-1.13 via OpenRouter)
          ◀── {p_phish, category, category_confidence, pressure, model} ──
```

No dependencies. Node 20+ or Cloudflare Workers.

## Run locally

```sh
JEV_API_KEY=sk-or-... npm run backend          # http://localhost:8787
```

Then point the extension at it: open `chrome://extensions`, click the
extension's "service worker" link and run

```js
chrome.storage.local.set({ backendUrl: 'http://localhost:8787' })
```

For a build that ships with a backend, set `DEFAULT_BACKEND_URL` in
`extension/lib/config.js`. An empty backend URL turns Tier 3 off and the
extension runs on Tiers 0-2 only.

| Variable | Default | |
|---|---|---|
| `JEV_API_KEY` | (none) | OpenRouter key with access to `typesafe/jev`. Without it `/classify` answers 503. |
| `JEV_API_URL` | `https://openrouter.ai/api/alpha/decisions` | |
| `JEV_MODEL` | `typesafe/jev-1.13` | Pinned; the fusion weights are tuned against it. |
| `TIER3_DISABLED` | | `1` = kill switch. Extensions back off for 10 minutes and use heuristics only. |
| `RATE_PER_MINUTE` | `60` | Per install ID (in memory). |
| `DECISION_LOG` | stdout | File to append JSON-lines decision logs to. |
| `PORT` | `8787` | |

On Cloudflare, deploy `worker.js` and set `JEV_API_KEY` with
`wrangler secret put JEV_API_KEY`.

## API

`POST /classify` with header `x-install-id: <uuid>` and body
`{ "summary": PageSummary }` (see `extension/lib/summary.js`). The summary is
re-sanitized here (redaction, length limits, unknown fields dropped), so the
key holder never forwards more than the documented fields.

Responses: `200` result, `400` bad input, `413` too large, `429` rate
limited, `502` Jev failed, `503 {"disabled": true}` kill switch.

`GET /health` → `{ ok, tier3, model }`.

## What is asked of Jev

One request per page with three questions over the summary (`src/jev.js`):

- `phish` (Noul): is the page trying to trick the visitor into giving away
  credentials, money, codes or remote access? → `p_phish`
- `category` (Choice): `credential_phish | tech_support_scam | fake_shop |
  gift_card_or_payment_scam | impersonation_other | benign`, used for the
  warning text.
- `pressure` (Score, 4 levels): how hard the page pushes the visitor. Logged
  for evaluation; not used in the verdict yet.

## Decision log

Every call logs one JSON line: the sanitized summary, the result, latency and
token usage. These are the labeled examples for evaluation and for training a
local model later (ARCHITECTURE.md §7).
