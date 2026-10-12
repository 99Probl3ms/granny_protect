# Jev question comparison

The revised questions shorten repeated context, describe local heuristic outputs as fallible hints, and distinguish deceptive solicitation from legitimate login/checkout/support and content discussing scams. The Noul now has explicit yes/no criteria. The existing question IDs, categories, pinned `jev-1.13.0` model, redaction, routing and thresholds are unchanged.

## Live development results

Measured October 12, 2026 against TypeSafe with synthetic requests only. Twenty-two cases were run twice for each prompt, alternating prompt order. All prompts received identical sanitized evidence. Results below compare the saved original prompt with the final candidate.

| Measure | Original | Revised |
| --- | ---: | ---: |
| Expected effective browser decisions | 30/44 | 34/44 |
| Unexpected allows on malicious or uncertain cases | 0 | 0 |
| Blocks on benign cases | 0 | 0 |
| Input tokens across 44 calls | 42,390 | 36,582 |
| Output tokens across 44 calls | 3,532 | 3,532 |
| Median API latency | 142 ms | 131 ms |
| P95 API latency | 169 ms | 168 ms |

The per-call measurements are in [jev-prompt-results.csv](jev-prompt-results.csv). Input token use fell 13.7%. This small latency sample does not establish a reliable speed improvement. Model answers varied slightly between runs.

The revised prompt cleared gift-card retail and official support examples, and blocked an OTP phishing example the original left held. It still held ordinary login, checkout, brand-discussion and SSO examples. The fake-shop example changed from block to held for review, and a URL-only typo domain changed from block to held; neither was allowed. Categories were recorded but not scored independently.

Both prompts retain the same two layers of decision policy: the adapter labels p ≤ 0.15 as allow and p ≥ 0.85 as block, but the browser also requires confidence ≥ 0.8. With confidence defined as 2·|p − 0.5|, effective allow needs p ≤ 0.10 and effective block needs p ≥ 0.90 (subject to the existing confidence rounding). The evaluator reports these effective decisions rather than treating an adapter answer as permission to navigate.

These synthetic cases were used while developing the prompt. The scores measure fit to this development set, not accuracy on employee traffic or a held-out population. Sparse evidence labels express the intended policy: an unverified short link or ambiguous login stays held. Some site legitimacy cannot be established from the sanitized evidence alone. Validate on separately labeled examples before changing thresholds or expanding automatic allows.

The existing live browser suite also passed: link/typed PayPal lookalikes were blocked, an ambiguous address stayed held, a fake support warning was blocked using page evidence, and private link parameters were absent from outgoing requests.

## Reproduce

Inject `TYPESAFE_API_KEY` through the environment, then run:

```sh
npm run eval:jev -- --baseline tests/fixtures/jev-prompt-baseline.json --repeats 2 --output /tmp/jev-results.json
```

This makes 88 live API calls. `tests/fixtures/jev-reviews.js` contains the synthetic evidence and expected effective decisions. The optional output contains probabilities, categories, model version, usage and timings for every call, plus the question variants. No API key is written to output. The tool reports misses for investigation; it is not a deterministic CI test.
