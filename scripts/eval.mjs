// Evaluate local URL decisions on the representative test set.
//
//   npm run eval            summary + any entries that don't match
//   npm run eval -- --all   every entry with its score and reasons

import { buildBlocklist } from '../extension/lib/lists.js';
import { decideUrl } from '../extension/lib/fusion.js';
import { BLOCKLIST_FEED, DESTINATIONS } from '../tests/fixtures/destinations.js';

const showAll = process.argv.includes('--all');
const blocklist = buildBlocklist(BLOCKLIST_FEED);
const ACTIONS = ['allow', 'needs_review', 'block'];
const LABELS = ['malicious', 'benign', 'internal'];

const matrix = Object.fromEntries(LABELS.map((l) => [l, Object.fromEntries(ACTIONS.map((a) => [a, 0]))]));
const mismatches = [];
const rows = [];

for (const d of DESTINATIONS) {
  const v = decideUrl(d.url, { blocklist });
  matrix[d.label][v.action]++;
  const row = { ...d, got: v.action, risk: v.risk, reasons: v.reasons.map((r) => r.code).join(', ') || v.source };
  rows.push(row);
  if (v.action !== d.expect) mismatches.push(row);
}

const pad = (s, n) => String(s).padEnd(n);
console.log(`\n${pad('label', 11)}${ACTIONS.map((a) => pad(a, 14)).join('')}total`);
for (const l of LABELS) {
  const counts = ACTIONS.map((a) => matrix[l][a]);
  console.log(`${pad(l, 11)}${counts.map((c) => pad(c, 14)).join('')}${counts.reduce((x, y) => x + y, 0)}`);
}

const mal = matrix.malicious;
const malTotal = mal.allow + mal.needs_review + mal.block;
const caught = mal.needs_review + mal.block;
const okTotal = LABELS.filter((l) => l !== 'malicious').reduce((n, l) => n + ACTIONS.reduce((m, a) => m + matrix[l][a], 0), 0);
const falseAlarms = LABELS.filter((l) => l !== 'malicious').reduce((n, l) => n + matrix[l].needs_review + matrix[l].block, 0);
console.log(`\nmalicious caught (review or block): ${caught}/${malTotal} (${Math.round((100 * caught) / malTotal)}%)`);
console.log(`benign + internal held for review or blocked: ${falseAlarms}/${okTotal}`);
console.log(`known misses: ${DESTINATIONS.filter((d) => d.miss).length}`);

if (showAll) {
  console.log('');
  for (const r of rows) console.log(`${pad(r.got, 13)} ${pad(r.risk.toFixed(2), 5)} ${pad(r.label, 10)} ${r.url}\n${' '.repeat(20)}${r.reasons}`);
}

if (mismatches.length) {
  console.log(`\n${mismatches.length} entr${mismatches.length === 1 ? 'y' : 'ies'} differ from expected:`);
  for (const r of mismatches) {
    console.log(`  expected ${r.expect}, got ${r.got} (${r.risk.toFixed(2)}): ${r.url}\n      ${r.reasons}`);
  }
  process.exitCode = 1;
}
