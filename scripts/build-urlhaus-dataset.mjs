// URLhaus tracks malware downloads, not phishing. Keep this corpus separate.
import fs from 'node:fs';
import path from 'node:path';
import { BUILTIN_TRUSTED } from '../extension/lib/lists.js';
import { createSampler, digest, makeRecords, parseSuffixList } from './lib/phishing-dataset.mjs';
import { downloadUrlhausExport, parseUrlhausCsv } from './lib/urlhaus.mjs';

const args = process.argv.slice(2);
const value = (flag) => args.includes(flag) ? args[args.indexOf(flag) + 1] : undefined;
const csvFile = value('--csv');
const pslFile = value('--psl');
const output = value('--output') || 'data/urlhaus-evaluation';
const seed = value('--seed') || 'jev-threat-dataset-v1';
const requestedSize = Number(value('--per-class') || 250);
if (!pslFile) throw new Error('--psl FILE is required');
if (!Number.isInteger(requestedSize) || requestedSize < 5 || requestedSize > 10000) throw new Error('--per-class must be 5–10000');
if (fs.existsSync(output)) throw new Error('Output directory already exists; choose a new path to preserve the snapshot');
const pslText = fs.readFileSync(pslFile, 'utf8'), psl = parseSuffixList(pslText);
const text = csvFile ? fs.readFileSync(csvFile, 'utf8') : await downloadUrlhausExport({ apiKey: process.env.URLHAUS_AUTH_KEY });
const records = parseUrlhausCsv(text);
const positive = createSampler(psl, seed), negative = createSampler(psl, seed);
for (const row of records) if (row.evidence.status === 'online') positive.add(row.url, row.evidence);
for (const domain of BUILTIN_TRUSTED) negative.add(`https://${domain}/`);
const conflicts = [...negative.selected.keys()].filter((group) => positive.selected.has(group));
for (const group of conflicts) { negative.selected.delete(group); positive.selected.delete(group); }
// Never pad or duplicate examples to hit a nominal count. A small export may
// have few independent online groups; report the actual balanced size.
const size = Math.min(requestedSize, positive.selected.size, negative.selected.size);
if (size < 5) throw new Error('Fewer than five independent online malware groups available');
const rows = makeRecords(positive.selected.values(), negative.selected.values(), {
  size, seed, positiveLabel: 'malware_download', positiveSource: 'URLhaus',
});
fs.mkdirSync(output, { recursive: true });
fs.writeFileSync(path.join(output, 'source.csv'), text);
fs.writeFileSync(path.join(output, 'public-suffix-list.dat'), pslText);
for (const split of ['development', 'test', 'all']) {
  fs.writeFileSync(path.join(output, `${split}.jsonl`), rows.filter((r) => split === 'all' || r.split === split).map((r) => JSON.stringify(r)).join('\n') + '\n');
}
const counts = Object.fromEntries(['development', 'test'].map((split) => [split,
  Object.fromEntries(['malware_download', 'benign_reference'].map((label) => [label, rows.filter((r) => r.split === split && r.label === label).length]))]));
const manifest = { schemaVersion: 1, createdAt: new Date().toISOString(), seed, requestedPerClass: requestedSize,
  source: { name: 'URLhaus', description: 'Recent CSV export; online malware_download entries only',
    docs: 'https://urlhaus.abuse.ch/api/', sha256: digest(text), input: csvFile ? 'local_csv' : 'authenticated_export',
    records: records.length, onlineRecords: records.filter((r) => r.evidence.status === 'online').length,
    caveat: 'Online status is from the export, not independently rechecked; historical/offline records are excluded' },
  publicSuffixList: { sha256: digest(pslText), includesPrivate: true },
  curatedControls: { source: 'project curated official homepages', seedListSha256: digest(JSON.stringify(BUILTIN_TRUSTED)),
    conflictsExcluded: conflicts.length, caveat: 'Convenience controls, not independently verified benign labels' },
  counts, total: rows.length, grouping: 'one URL per PSL registrable domain/private tenant or IPv4 /24 or exact IPv6',
  evaluation: 'URL-only sanitized evidence, identical neutral local hints; no feed labels, tags or reputation sent to Jev',
  scope: 'Malware-download generalization test. Current Jev question targets deceptive solicitation, so this is not a phishing-accuracy measurement.',
};
fs.writeFileSync(path.join(output, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log(JSON.stringify({ output: path.resolve(output), counts, total: rows.length, requestedPerClass: requestedSize }, null, 2));
