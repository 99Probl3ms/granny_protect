// Evaluate Jev on a labelled URL set (default eval/urlhaus-jev.json, built by
// scripts/build-urlhaus-dataset.mjs). Each URL goes through the same path as
// in the extension: local decision -> sanitized review request -> the review
// service's re-sanitization -> the real Jev adapter. Address only, no page
// content, and every URL is sent (in the extension only "needs review" ones are).
//
//   TYPESAFE_API_KEY=... npm run eval:jev                        all entries
//   TYPESAFE_API_KEY=... npm run eval:jev -- --limit 20          a stratified 20
//   options: --dataset <file>  --concurrency <n> (default 4)  --out <results.jsonl>
//
// The report adds a histogram of Jev's raw probability and what other block
// and allow cutoffs would have done, for tuning THRESHOLDS in jev.mjs.
//
// Costs one Jev call per entry. Nothing is fetched from the URLs themselves.

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { parseArgs } from 'node:util';
import { buildBlocklist } from '../extension/lib/lists.js';
import { decideUrl } from '../extension/lib/fusion.js';
import { buildReviewRequest } from '../extension/lib/sanitize.js';
import { cleanRequest } from '../server/server.mjs';
import { createJevModel } from '../server/models/jev.mjs';

const { values: args } = parseArgs({
  options: {
    dataset: { type: 'string', default: 'eval/urlhaus-jev.json' },
    limit: { type: 'string' },
    concurrency: { type: 'string', default: '4' },
    out: { type: 'string', default: 'eval/results/jev-latest.jsonl' },
  },
});

if (!process.env.TYPESAFE_API_KEY) {
  console.error('TYPESAFE_API_KEY is not set');
  process.exit(2);
}

// Object.groupBy needs Node 21; the project supports Node 20.
const groupBy = (items, key) => items.reduce((m, x) => ((m[key(x)] ??= []).push(x), m), {});

const { entries } = JSON.parse(readFileSync(args.dataset, 'utf8'));
let todo = entries;
if (args.limit) {
  // Round-robin over strata so a small run still covers every kind of URL.
  const byStratum = Object.values(groupBy(entries, (e) => e.stratum));
  todo = [];
  for (let i = 0; todo.length < Number(args.limit) && byStratum.some((s) => s[i]); i++) {
    for (const s of byStratum) if (s[i] && todo.length < Number(args.limit)) todo.push(s[i]);
  }
}

const jev = createJevModel({ timeoutMs: 15000 });
const blocklist = buildBlocklist([]);
const results = [];
let done = 0;

async function run(entry) {
  const local = decideUrl(entry.url, { blocklist });
  const request = cleanRequest(buildReviewRequest(entry.url, local));
  const started = Date.now();
  let review = null;
  let error = null;
  for (let attempt = 0; attempt < 2 && !review; attempt++) {
    try {
      review = await jev.classify(request);
      error = null;
    } catch (err) {
      error = String(err?.message || err).slice(0, 200);
    }
  }
  results.push({
    id: entry.id, url: entry.url, label: entry.label, stratum: entry.stratum,
    local: local.action, sent: request.destination, ...(review || {}), error, ms: Date.now() - started,
  });
  process.stderr.write(`\r${++done}/${todo.length}`);
}

const queue = [...todo];
await Promise.all(Array.from({ length: Number(args.concurrency) }, async () => {
  while (queue.length) await run(queue.shift());
}));
process.stderr.write('\n');
results.sort((a, b) => a.id - b.id);

mkdirSync(dirname(args.out), { recursive: true });
writeFileSync(args.out, results.map((r) => JSON.stringify(r)).join('\n') + '\n');

// --- report ----------------------------------------------------------------------

const DECISIONS = ['allow', 'needs_review', 'block', 'error'];
const pad = (s, n) => String(s).padEnd(n);
const pct = (n, d) => (d ? `${((100 * n) / d).toFixed(1)}%` : '-');
const decisionOf = (r) => (r.error ? 'error' : r.decision);

function table(title, groups) {
  console.log(`\n${pad(title, 44)}${DECISIONS.map((d) => pad(d, 14)).join('')}n`);
  for (const [name, rows] of groups) {
    const c = Object.fromEntries(DECISIONS.map((d) => [d, rows.filter((r) => decisionOf(r) === d).length]));
    console.log(`${pad(name, 44)}${DECISIONS.map((d) => pad(c[d], 14)).join('')}${rows.length}`);
  }
}

table('label', Object.entries(groupBy(results, (r) => r.label)));
table('stratum', Object.entries(groupBy(results, (r) => `${r.label}/${r.stratum}`)));

const mal = results.filter((r) => r.label === 'malicious' && !r.error);
const ben = results.filter((r) => r.label === 'benign' && !r.error);
const count = (rows, ...ds) => rows.filter((r) => ds.includes(r.decision)).length;
console.log(`
malicious blocked:                 ${count(mal, 'block')}/${mal.length} (${pct(count(mal, 'block'), mal.length)})
malicious blocked or held:         ${count(mal, 'block', 'needs_review')}/${mal.length} (${pct(count(mal, 'block', 'needs_review'), mal.length)})
benign blocked (false block):      ${count(ben, 'block')}/${ben.length} (${pct(count(ben, 'block'), ben.length)})
benign held or blocked:            ${count(ben, 'block', 'needs_review')}/${ben.length} (${pct(count(ben, 'block', 'needs_review'), ben.length)})
errors:                            ${results.filter((r) => r.error).length}`);

// Where Jev's probabilities land, and what other cutoffs would have done.
// The current ones are THRESHOLDS in server/models/jev.mjs.
const BUCKETS = 10;
const bucketOf = (p) => Math.min(Math.floor(p * BUCKETS), BUCKETS - 1);
console.log(`\n${pad('probability', 14)}${pad('malicious', 12)}benign`);
for (let b = 0; b < BUCKETS; b++) {
  const inBucket = (rows) => rows.filter((r) => bucketOf(r.probability) === b).length;
  console.log(`${pad(`${(b / BUCKETS).toFixed(1)}-${((b + 1) / BUCKETS).toFixed(1)}`, 14)}${pad(inBucket(mal), 12)}${inBucket(ben)}`);
}
console.log(`\n${pad('block if p >=', 16)}${pad('malicious blocked', 22)}benign blocked`);
for (const cut of [0.5, 0.6, 0.7, 0.75, 0.8, 0.85, 0.9]) {
  const blocked = (rows) => rows.filter((r) => r.probability >= cut).length;
  console.log(`${pad(cut, 16)}${pad(`${blocked(mal)} (${pct(blocked(mal), mal.length)})`, 22)}${blocked(ben)} (${pct(blocked(ben), ben.length)})`);
}
console.log(`\n${pad('allow if p <=', 16)}${pad('malicious allowed', 22)}benign allowed`);
for (const cut of [0.1, 0.15, 0.2, 0.3, 0.4, 0.5]) {
  const allowed = (rows) => rows.filter((r) => r.probability <= cut).length;
  console.log(`${pad(cut, 16)}${pad(`${allowed(mal)} (${pct(allowed(mal), mal.length)})`, 22)}${allowed(ben)} (${pct(allowed(ben), ben.length)})`);
}

const categories = Object.entries(groupBy(mal.filter((r) => r.category), (r) => r.category))
  .map(([c, rows]) => `${c} ${rows.length}`);
if (categories.length) console.log(`malicious categories:              ${categories.join(', ')}`);
const models = [...new Set(results.map((r) => r.model).filter(Boolean))];
console.log(`model: ${models.join(', ') || '-'}    results: ${args.out}`);

const errors = results.filter((r) => r.error);
if (errors.length) console.log(`\nfirst error: ${errors[0].error}`);
