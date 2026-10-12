import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createSampler, domainGroup, makeRecords, parseSuffixList } from '../scripts/lib/phishing-dataset.mjs';
import { datasetMetrics, loadDataset } from '../scripts/lib/evaluation-cases.mjs';
const psl = parseSuffixList('com\nnet\nco.uk\n*.ck\n!www.ck\n// PRIVATE\ngithub.io\n');

test('grouping respects public/private suffixes, wildcard exceptions and IP networks', () => {
  assert.equal(domainGroup('login.bank.co.uk', psl), 'bank.co.uk');
  assert.equal(domainGroup('a.user.github.io', psl), 'user.github.io');
  assert.notEqual(domainGroup('one.github.io', psl), domainGroup('two.github.io', psl));
  assert.equal(domainGroup('a.b.ck', psl), 'a.b.ck');
  assert.equal(domainGroup('a.www.ck', psl), 'www.ck');
  assert.equal(domainGroup('8.8.8.1', psl), domainGroup('8.8.8.2', psl));
});

test('sampling is independent of feed order and drops invalid/internal URLs', () => {
  const feed = ['https://a.shop.com/login?secret=value', 'https://b.shop.com/other', 'https://a.shop.com/login?secret=value',
    'http://8.8.8.1/malware', 'file:///etc/passwd', 'http://intranet/', 'not a URL'];
  const forward = createSampler(psl, 'seed'), reverse = createSampler(psl, 'seed');
  feed.forEach((url) => forward.add(url)); [...feed].reverse().forEach((url) => reverse.add(url));
  assert.equal(forward.selected.size, 2);
  assert.deepEqual([...forward.selected.values()].sort((a, b) => a.rank.localeCompare(b.rank)),
    [...reverse.selected.values()].sort((a, b) => a.rank.localeCompare(b.rank)));
});

test('splits have disjoint groups, and model inputs exclude labels and query identifiers', () => {
  const positive = createSampler(psl, 'seed'), negative = createSampler(psl, 'seed');
  for (let i = 0; i < 10; i++) {
    positive.add(`https://bad${i}.com/login?token=private`);
    negative.add(`https://good${i}.net/`);
  }
  const rows = makeRecords(positive.selected.values(), negative.selected.values(), { size: 10 });
  const testGroups = new Set(rows.filter((r) => r.split === 'test').map((r) => r.group));
  assert.equal(testGroups.size, 4);
  for (const row of rows) {
    if (row.split === 'development') assert.ok(!testGroups.has(row.group));
    assert.equal(row.request.page, undefined, 'no fabricated page evidence');
    assert.deepEqual(row.request.local, { decision: 'needs_review', risk: 0.5, signals: [], brand: null });
    assert.doesNotMatch(JSON.stringify(row.request), /token=|private|Phishing.Database|benign_reference|upstream/);
  }
});

test('loader validates external cases and resanitizes before model evaluation', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'jev-dataset-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'cases.jsonl');
  const row = { id: '1', label: 'phishing', expected: 'not_allow', url: 'https://evil.com/?secret=x',
    request: { destination: { scheme: 'https', host: 'evil.com', path: '/u/jane%40example.com' }, source: 'feed', label: 'phishing' } };
  fs.writeFileSync(file, JSON.stringify(row));
  const [loaded] = loadDataset(file);
  assert.equal(loaded.request.source, undefined);
  assert.equal(loaded.request.label, undefined);
  assert.equal(loaded.request.destination.path, '/u/[email]');
  fs.writeFileSync(file, JSON.stringify(row) + '\n' + JSON.stringify(row));
  assert.throws(() => loadDataset(file), /duplicate/);
});

test('metrics distinguish held threats from blocks and include held benign controls', () => {
  const result = datasetMetrics([
    { label: 'phishing', effective: 'block' }, { label: 'phishing', effective: 'needs_review' },
    { label: 'phishing', effective: 'allow' }, { label: 'benign_reference', effective: 'block' },
    { label: 'benign_reference', effective: 'needs_review' }, { label: 'benign_reference', effective: 'allow' },
  ]);
  assert.equal(result.phishingCatchRate, 2 / 3);
  assert.equal(result.phishingBlockRecall, 1 / 3);
  assert.equal(result.benignReferenceHoldRate, 2 / 3);
  assert.equal(result.blockPrecisionOnThisSample, 0.5);
});
