// Evaluate Jev's accuracy on a labelled list of addresses.
//
//   TYPESAFE_API_KEY=... npm run eval:jev -- dataset.csv [options]
//
// The dataset has one address per line, "url,label". The label is
// malicious (also: phish, phishing, scam, bad, 1) or benign (also: legit,
// legitimate, safe, good, 0). A header line, blank lines and lines starting
// with # are skipped. Tab or comma separated.
//
// Each address is sent to Jev exactly as the extension would send it: the
// local URL checks run first (no blocklist, so OpenPhish plays no part) and
// the request is sanitized by the same code. Only the address is judged;
// pages are not loaded.
//
// Options:
//   --only-review     send only addresses the local checks hold for review
//                     (what Jev sees in production); default sends every one
//   --limit N         first N addresses only
//   --concurrency N   parallel Jev calls (default 4)
//   --out FILE        write per-address results as CSV (default: none)
//
// Each address costs one Jev call (two questions).

import fs from 'node:fs';
import { decideUrl } from '../extension/lib/fusion.js';
import { buildReviewRequest } from '../extension/lib/sanitize.js';
import { cleanRequest } from '../server/server.mjs';
import { createJevModel, THRESHOLDS } from '../server/models/jev.mjs';

const args = process.argv.slice(2);
const opt = (name, fallback) => {
  const i = args.indexOf(name);
  return i === -1 ? fallback : args.splice(i, 2)[1];
};
const flag = (name) => {
  const i = args.indexOf(name);
  return i !== -1 && args.splice(i, 1).length > 0;
};
const onlyReview = flag('--only-review');
const limit = Number(opt('--limit', Infinity));
const concurrency = Math.max(1, Number(opt('--concurrency', 4)));
const outFile = opt('--out', null);
const datasetPath = args[0];

if (!datasetPath) {
  console.error('usage: npm run eval:jev -- dataset.csv [--only-review] [--limit N] [--concurrency N] [--out results.csv]');
  process.exit(2);
}
if (!process.env.TYPESAFE_API_KEY) {
  console.error('TYPESAFE_API_KEY is not set');
  process.exit(2);
}

const MALICIOUS = new Set(['malicious', 'phish', 'phishing', 'scam', 'bad', '1', 'true']);
const BENIGN = new Set(['benign', 'legit', 'legitimate', 'safe', 'good', '0', 'false']);

const rows = [];
const skipped = [];
for (const [i, raw] of fs.readFileSync(datasetPath, 'utf8').split(/\r?\n/).entries()) {
  const line = raw.trim();
  if (!line || line.startsWith('#')) continue;
  const cut = line.search(/[\t,](?=[^\t,]*$)/);
  const url = (cut === -1 ? line : line.slice(0, cut)).trim().replace(/^"|"$/g, '');
  const label = (cut === -1 ? '' : line.slice(cut + 1)).trim().replace(/^"|"$/g, '').toLowerCase();
  const malicious = MALICIOUS.has(label) ? true : BENIGN.has(label) ? false : null;
  let href;
  try {
    href = new URL(/^[a-z][a-z0-9+.-]*:/i.test(url) ? url : `http://${url}`).href;
  } catch {
    href = null;
  }
  if (malicious === null || !href) {
    if (i > 0 || !/url/i.test(line)) skipped.push(`line ${i + 1}: ${line.slice(0, 80)}`);
    continue;
  }
  rows.push({ url: href, malicious });
  if (rows.length >= limit) break;
}

async function classify(row) {
  const verdict = decideUrl(row.url);
  row.local = verdict.action;
  if (onlyReview && verdict.action !== 'needs_review') return;
  const request = cleanRequest(JSON.parse(JSON.stringify(buildReviewRequest(row.url, verdict))));
  // Keep Jev's raw probability as well as the mapped decision.
  let body;
  const jev = createJevModel({
    timeoutMs: 15000,
    fetch: async (endpoint, init) => {
      const res = await fetch(endpoint, init);
      if (res.ok) body = await res.clone().json().catch(() => null);
      return res;
    },
  });
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      const review = await jev.classify(request);
      row.p = body?.answers?.phish?.noul;
      row.decision = review.decision;
      row.confidence = review.confidence;
      row.category = review.category;
      row.model = review.model;
      delete row.error;
      return;
    } catch (err) {
      row.error = String(err?.message || err).slice(0, 120);
    }
  }
}

let next = 0;
let done = 0;
await Promise.all(Array.from({ length: concurrency }, async () => {
  while (next < rows.length) {
    const row = rows[next++];
    await classify(row);
    done++;
    if (process.stderr.isTTY) process.stderr.write(`\r${done}/${rows.length}`);
  }
}));
if (process.stderr.isTTY) process.stderr.write('\r');

// --- report ------------------------------------------------------------------

const judged = rows.filter((r) => r.decision);
const errors = rows.filter((r) => r.error);
const pct = (n, d) => (d ? `${((100 * n) / d).toFixed(1)}%` : '-');
const pad = (s, n) => String(s).padEnd(n);
const DECISIONS = ['allow', 'needs_review', 'block'];

console.log(`\nJev evaluation on ${datasetPath}`);
console.log(`addresses: ${rows.length}, judged by Jev: ${judged.length}, errors: ${errors.length}` +
  (onlyReview ? `, not sent (local decision not needs_review): ${rows.length - judged.length - errors.length}` : ''));
const models = [...new Set(judged.map((r) => r.model).filter(Boolean))];
if (models.length) console.log(`model: ${models.join(', ')}`);

console.log(`\n${pad('label', 11)}${DECISIONS.map((d) => pad(d, 14)).join('')}total`);
for (const [name, mal] of [['malicious', true], ['benign', false]]) {
  const group = judged.filter((r) => r.malicious === mal);
  const counts = DECISIONS.map((d) => group.filter((r) => r.decision === d).length);
  console.log(`${pad(name, 11)}${counts.map((c) => pad(c, 14)).join('')}${group.length}`);
}

function metrics(name, isPositive) {
  const tp = judged.filter((r) => r.malicious && isPositive(r)).length;
  const fn = judged.filter((r) => r.malicious && !isPositive(r)).length;
  const fp = judged.filter((r) => !r.malicious && isPositive(r)).length;
  const tn = judged.filter((r) => !r.malicious && !isPositive(r)).length;
  console.log(`  ${pad(name, 34)} accuracy ${pad(pct(tp + tn, judged.length), 7)} precision ${pad(pct(tp, tp + fp), 7)}` +
    ` recall ${pad(pct(tp, tp + fn), 7)} false-positive rate ${pct(fp, fp + tn)}`);
}
console.log('\nCounting as "flagged as malicious":');
metrics('block only', (r) => r.decision === 'block');
metrics('block or needs_review', (r) => r.decision !== 'allow');
metrics('p >= 0.5', (r) => r.p >= 0.5);

const scored = judged.filter((r) => typeof r.p === 'number');
const pos = scored.filter((r) => r.malicious).map((r) => r.p);
const neg = scored.filter((r) => !r.malicious).map((r) => r.p);
if (pos.length && neg.length) {
  let wins = 0;
  for (const a of pos) for (const b of neg) wins += a > b ? 1 : a === b ? 0.5 : 0;
  console.log(`\nROC AUC of p: ${(wins / (pos.length * neg.length)).toFixed(3)}` +
    ` (thresholds in use: block p >= ${THRESHOLDS.block}, allow p <= ${THRESHOLDS.allow})`);
}

const wrong = judged.filter((r) => (r.malicious && r.decision === 'allow') || (!r.malicious && r.decision === 'block'));
if (wrong.length) {
  console.log(`\nClear mistakes (${wrong.length}): malicious allowed or benign blocked`);
  for (const r of wrong) {
    console.log(`  ${pad(r.malicious ? 'malicious' : 'benign', 10)} -> ${pad(r.decision, 6)} p=${r.p?.toFixed(3) ?? '?'}  ${r.url}`);
  }
}
if (errors.length) {
  console.log(`\nErrors (${errors.length}):`);
  for (const r of errors.slice(0, 10)) console.log(`  ${r.url}: ${r.error}`);
}
if (skipped.length) {
  console.log(`\nSkipped ${skipped.length} unreadable line(s):`);
  for (const s of skipped.slice(0, 10)) console.log(`  ${s}`);
}

if (outFile) {
  const esc = (v) => (v == null ? '' : /[",\n]/.test(String(v)) ? `"${String(v).replace(/"/g, '""')}"` : String(v));
  const cols = ['url', 'label', 'local', 'p', 'decision', 'confidence', 'category', 'model', 'error'];
  const lines = rows.map((r) => cols.map((c) => esc(c === 'label' ? (r.malicious ? 'malicious' : 'benign') : r[c])).join(','));
  fs.writeFileSync(outFile, `${cols.join(',')}\n${lines.join('\n')}\n`);
  console.log(`\nper-address results: ${outFile}`);
}
