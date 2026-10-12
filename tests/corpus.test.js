// Local URL decisions on the representative test set
// (tests/fixtures/destinations.js). `npm run eval` prints the same results as
// a confusion matrix.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { buildBlocklist } from '../extension/lib/lists.js';
import { decideUrl } from '../extension/lib/fusion.js';
import { BLOCKLIST_FEED, DESTINATIONS } from './fixtures/destinations.js';

const blocklist = buildBlocklist(BLOCKLIST_FEED);

test('the test set covers every label and decision', () => {
  const labels = new Set(DESTINATIONS.map((d) => d.label));
  const expects = new Set(DESTINATIONS.map((d) => d.expect));
  assert.deepEqual([...labels].sort(), ['benign', 'internal', 'malicious']);
  assert.deepEqual([...expects].sort(), ['allow', 'block', 'needs_review']);
});

for (const d of DESTINATIONS) {
  test(`${d.label}: ${d.expect} ${d.url}`, () => {
    const v = decideUrl(d.url, { blocklist });
    assert.equal(v.action, d.expect,
      `risk ${v.risk}; ${v.reasons.map((r) => r.code).join(', ') || v.source}${d.note ? `; ${d.note}` : ''}`);
  });
}

test('benign and internal destinations are never held or blocked', () => {
  const bad = DESTINATIONS
    .filter((d) => d.label !== 'malicious')
    .filter((d) => decideUrl(d.url, { blocklist }).action !== 'allow');
  assert.deepEqual(bad.map((d) => d.url), []);
});

test('internal destinations are allowed as internal, not by luck', () => {
  for (const d of DESTINATIONS.filter((x) => x.label === 'internal')) {
    assert.equal(decideUrl(d.url, { blocklist }).source, 'internal', d.url);
  }
});

test('only documented misses get through', () => {
  const missed = DESTINATIONS
    .filter((d) => d.label === 'malicious' && !d.miss)
    .filter((d) => decideUrl(d.url, { blocklist }).action === 'allow');
  assert.deepEqual(missed.map((d) => d.url), []);
});
