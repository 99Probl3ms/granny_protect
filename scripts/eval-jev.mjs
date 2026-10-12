// Live prompt evaluation using sanitized cases. No key is printed.
// npm run eval:jev -- --baseline tests/fixtures/jev-prompt-baseline.json --output /tmp/results.json
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { datasetMetrics, loadDataset } from './lib/evaluation-cases.mjs';
import { JEV_REVIEWS } from '../tests/fixtures/jev-reviews.js';
import { buildJevRequest, DEFAULT_ENDPOINT, toReview } from '../server/models/jev.mjs';
import { applyReview, validateReview } from '../extension/lib/reviewClient.js';

const args = process.argv.slice(2);
const value = (flag) => args.includes(flag) ? args[args.indexOf(flag) + 1] : undefined;
const baselinePath = value('--baseline');
const output = value('--output');
const repeats = Number(value('--repeats') || 1);
if (!Number.isInteger(repeats) || repeats < 1 || repeats > 5) throw new Error('--repeats must be 1–5');
const datasetPath = value('--dataset');
const fixtures = datasetPath ? loadDataset(datasetPath) : JEV_REVIEWS;
const limit = Number(value('--limit') || fixtures.length);
if (!Number.isInteger(limit) || limit < 1 || limit > fixtures.length) throw new Error('--limit must be within the dataset size');
const cases = fixtures.slice(0, limit);
if (args.includes('--dry-run')) {
  console.log(JSON.stringify({ cases: cases.length, repeats, variants: baselinePath ? 2 : 1,
    calls: cases.length * repeats * (baselinePath ? 2 : 1),
    labels: Object.fromEntries([...new Set(cases.map((c) => c.label || 'synthetic'))]
      .map((label) => [label, cases.filter((c) => (c.label || 'synthetic') === label).length])) }, null, 2));
  process.exit(0);
}
if (!process.env.TYPESAFE_API_KEY) throw new Error('TYPESAFE_API_KEY is required');
const variants = [{ name: 'candidate', questions: buildJevRequest({}).questions }];
if (baselinePath) {
  const questions = baselinePath.endsWith('.json')
    ? JSON.parse(fs.readFileSync(baselinePath, 'utf8'))
    : (await import(pathToFileURL(path.resolve(baselinePath)))).QUESTIONS;
  variants.unshift({ name: 'baseline', questions });
}
const rows = [];
for (let repeat = 0; repeat < repeats; repeat++) {
  for (const [index, fixture] of cases.entries()) {
    // Alternate order to reduce systematic warm-cache/latency advantage.
    for (const variant of index % 2 ? [...variants].reverse() : variants) {
      const body = { ...buildJevRequest(fixture.request), questions: variant.questions };
      const start = performance.now();
      const response = await fetch(DEFAULT_ENDPOINT, {
        method: 'POST', headers: { authorization: `Bearer ${process.env.TYPESAFE_API_KEY}`, 'content-type': 'application/json' },
        body: JSON.stringify(body), signal: AbortSignal.timeout(10000),
      });
      if (!response.ok) throw new Error(`TypeSafe HTTP ${response.status} (${fixture.id}, ${variant.name}); evaluation stopped`);
      const answer = await response.json();
      const latencyMs = Math.round(performance.now() - start);
      const review = toReview(answer);
      const effective = applyReview({ action: 'needs_review', reasons: [] }, validateReview(review)).action;
      const passed = fixture.expected === 'not_allow' ? effective !== 'allow' : effective === fixture.expected;
      const row = { repeat, id: fixture.id, variant: variant.name, expected: fixture.expected, label: fixture.label, passed,
        p: answer.answers.phish.noul, category: answer.answers.category.choice,
        decision: review.decision, effective, latencyMs, usage: answer.usage, model: answer.model };
      rows.push(row);
      console.log(`${variant.name.padEnd(9)} ${fixture.id.padEnd(23)} p=${row.p.toFixed(3)} ${effective.padEnd(12)} ${passed ? 'ok' : 'MISS'} ${latencyMs}ms`);
    }
  }
}
const summaries = variants.map(({ name }) => {
  const subset = rows.filter((r) => r.variant === name);
  const latencies = subset.map((r) => r.latencyMs).sort((a, b) => a - b);
  return { variant: name, passed: subset.filter((r) => r.passed).length, total: subset.length,
    unexpectedAllows: subset.filter((r) => r.expected !== 'allow' && r.effective === 'allow').length,
    benignBlocks: subset.filter((r) => r.expected === 'allow' && r.effective === 'block').length,
    inputTokens: subset.reduce((n, r) => n + (r.usage?.input_tokens || 0), 0),
    outputTokens: subset.reduce((n, r) => n + (r.usage?.output_tokens || 0), 0),
    ...(datasetPath ? { datasetMetrics: datasetMetrics(subset) } : {}),
    medianMs: latencies[Math.floor(latencies.length / 2)], p95Ms: latencies[Math.ceil(latencies.length * 0.95) - 1] };
});
console.log(JSON.stringify(summaries, null, 2));
if (output) fs.writeFileSync(output, JSON.stringify({ summaries, rows, variants }, null, 2) + '\n');
