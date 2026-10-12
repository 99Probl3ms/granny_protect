# URL-only Jev threat datasets

Two separate local corpora were generated on October 12, 2026. Each has 250 threat URLs and 250 curated official homepage controls. Each corpus contains 400 development examples (200 per class) and 100 test examples (50 per class).

| Corpus | Positive label | Source |
| --- | --- | --- |
| URLhaus | `malware_download` | Authenticated recent CSV export; 33,816 records, 17,233 reported online at collection |
| Phishing.Database | `phishing` | Public MIT-licensed `phishing-links-ACTIVE.txt` at commit `12a20bf8dd2b7e78d9d38fc12b3e5c970f79d1a7`, committed October 2, 2026 |

The URLhaus download succeeded using `URLHAUS_AUTH_KEY`. Offline and unknown-status entries are excluded. The source CSV, report dates, tags, status, checksums and collection time are retained locally. No authentication key is saved. The phishing source's activity status is an upstream claim from its snapshot, not a live check made by this project.

The current Jev question targets deceptive solicitation of information, money or device access. URLhaus instead lists malware payload downloads. Its evaluation is a broader malware/generalization test, not a measurement of phishing accuracy; report the two corpora separately.

## Files and sampling

Generated outputs live under ignored `data/` directories:

- `urlhaus-2026-10-12/`
- `phishing-database-2026-10-12/`

Each contains `all.jsonl`, `development.jsonl`, `test.jsonl`, `manifest.json` and the exact Public Suffix List used for grouping. URLhaus also includes its input CSV; Phishing.Database includes its MIT license notice. Generated intelligence is not published in the code PR.

Each selected example has a distinct registrable-domain group, including PRIVATE public suffixes for shared-host tenants. Public IPv4 addresses are grouped by /24; IPv6 uses the exact address. One representative URL is selected per group, and groups are sampled deterministically using a recorded seed. Groups do not overlap between development and test within a corpus. These splits are reproducible within a snapshot; they are not chronological or campaign-independent, and future snapshots require a new cross-snapshot leakage check.

Controls are real homepage addresses from the project's curated trusted-domain list. They are labeled `benign_reference`, not independently verified benign ground truth. Groups appearing in both a threat source and the curated control list are excluded from both pools. This provides a convenient initial false-positive check, but it is an easy control set: it lacks representative employee traffic and difficult benign login/document/payment URLs. A balanced convenience sample cannot establish production precision.

No listed threat URL is contacted, resolved or opened by the builder. It reads strings from the provider's dataset only. Do not use these lists as a browser navigation test.

## Evaluate

The evaluator accepts a generated JSONL file, re-sanitizes requests, and reports separate allow/hold/block counts per label. Labels, source names, status, tags and known blocklist matches stay outside Jev's request. Every case receives the same neutral local hints, so this measures URL-only semantic judgments rather than reputation lookup or the complete extension pipeline. No page evidence is fabricated.

Inspect the call budget without making requests:

```sh
npm run eval:jev -- --dataset data/urlhaus-2026-10-12/test.jsonl --dry-run
npm run eval:jev -- --dataset data/phishing-database-2026-10-12/test.jsonl --dry-run
```

Each test command plans 100 calls: 50 threat cases and 50 controls. To evaluate development data first, inject `TYPESAFE_API_KEY` and run:

```sh
npm run eval:jev -- --dataset data/urlhaus-2026-10-12/development.jsonl --output /tmp/jev-urlhaus-development.json
npm run eval:jev -- --dataset data/phishing-database-2026-10-12/development.jsonl --output /tmp/jev-phishing-development.json
```

In this cloud workspace, prefix Node commands with `NODE_USE_ENV_PROXY=1` to use its outbound proxy (Node 24). These make 400 API calls each. `--limit N` can run a smaller sample. `--baseline tests/fixtures/jev-prompt-baseline.json` compares prompts and doubles the call count. Preserve the test files while tuning on development data. Neither corpus has been submitted to Jev as part of dataset construction.

## Rebuild URLhaus

Provide `URLHAUS_AUTH_KEY` through environment settings; never put it in a command or file. Fetch the public suffix list once, then:

```sh
curl -fsSL https://publicsuffix.org/list/public_suffix_list.dat -o /tmp/public-suffix-list.dat
npm run dataset:urlhaus -- --psl /tmp/public-suffix-list.dat --output data/urlhaus-new --per-class 250
```

The builder uses the officially documented `recent.csv` export. It does not log the authenticated download URI or upstream error bodies. `--csv /path/to/export.csv` uses a previously downloaded export without an API key. Never fetch an export more often than URLhaus's documented five-minute refresh interval. A source with fewer independent online groups produces a smaller balanced corpus; the manifest reports the actual count rather than duplicating examples.

## Rebuild Phishing.Database

Fetch a specific source commit and its license, not a moving branch:

```sh
curl -fsSL https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/12a20bf8dd2b7e78d9d38fc12b3e5c970f79d1a7/phishing-links-ACTIVE.txt -o /tmp/phishing-source.txt
curl -fsSL https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/12a20bf8dd2b7e78d9d38fc12b3e5c970f79d1a7/LICENSE -o /tmp/phishing-source-license.txt
npm run dataset:phishing -- --feed /tmp/phishing-source.txt --psl /tmp/public-suffix-list.dat --license /tmp/phishing-source-license.txt --source-commit 12a20bf8dd2b7e78d9d38fc12b3e5c970f79d1a7 --source-date 2026-10-02T15:30:28Z --output data/phishing-new --per-class 250
```

All builders refuse to overwrite an existing output directory, preserving prior snapshots and evaluation results.
