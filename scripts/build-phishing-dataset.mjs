// Build a local dataset from an immutable public feed snapshot. Never fetches
// any address contained in the feed; reads URL strings only.
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { BUILTIN_TRUSTED } from '../extension/lib/lists.js';
import { createSampler, digest, makeRecords, parseSuffixList } from './lib/phishing-dataset.mjs';

const args = process.argv.slice(2);
const value = (flag) => args.includes(flag) ? args[args.indexOf(flag) + 1] : undefined;
const feed = value('--feed'), pslFile = value('--psl'), licenseFile = value('--license');
const commit = value('--source-commit');
const sourceDate = value('--source-date');
const output = value('--output') || 'data/phishing-evaluation';
const size = Number(value('--per-class') || 250);
const seed = value('--seed') || 'jev-threat-dataset-v1';
if (!feed || !pslFile || !licenseFile || !/^[a-f0-9]{40}$/.test(commit || '') || !sourceDate || Number.isNaN(Date.parse(sourceDate))) {
  throw new Error('Required: --feed FILE --psl FILE --license FILE --source-commit SHA --source-date ISO_DATE');
}
if (!Number.isInteger(size) || size < 5 || size > 10000) throw new Error('--per-class must be 5–10000');
if (fs.existsSync(output)) throw new Error('Output directory already exists; choose a new path to preserve the snapshot');
const pslText = fs.readFileSync(pslFile, 'utf8');
const psl = parseSuffixList(pslText);
const sampler = createSampler(psl, seed);
const hashStream = createHash('sha256');
const source = fs.createReadStream(feed);
source.on('data', (chunk) => hashStream.update(chunk));
for await (const line of readline.createInterface({ input: source, crlfDelay: Infinity })) sampler.add(line);
const benign = createSampler(psl, seed);
for (const domain of BUILTIN_TRUSTED) benign.add(`https://${domain}/`);
// A reported phishing URL on a domain invalidates that domain as a benign
// control. Same-group conflicts are excluded from BOTH pools, not relabeled.
const conflicts = [...benign.selected.keys()].filter((group) => sampler.selected.has(group));
for (const group of conflicts) { benign.selected.delete(group); sampler.selected.delete(group); }
const rows = makeRecords(sampler.selected.values(), benign.selected.values(), { size, seed });
if (rows.filter((r) => r.label === 'phishing').length < size || rows.filter((r) => r.label === 'benign_reference').length < size) {
  throw new Error(`Insufficient independent groups: ${sampler.selected.size} phishing, ${benign.selected.size} benign candidates; reduce --per-class`);
}
fs.mkdirSync(output, { recursive: true });
for (const split of ['development', 'test']) {
  fs.writeFileSync(path.join(output, `${split}.jsonl`), rows.filter((r) => r.split === split).map((r) => JSON.stringify(r)).join('\n') + '\n');
}
fs.writeFileSync(path.join(output, 'all.jsonl'), rows.map((r) => JSON.stringify(r)).join('\n') + '\n');
fs.copyFileSync(licenseFile, path.join(output, 'SOURCE-LICENSE.txt'));
fs.copyFileSync(pslFile, path.join(output, 'public-suffix-list.dat'));
const counts = Object.fromEntries(['development', 'test'].map((split) => [split,
  Object.fromEntries(['phishing', 'benign_reference'].map((label) => [label, rows.filter((r) => r.split === split && r.label === label).length]))]));
const manifest = {
  schemaVersion: 1, createdAt: new Date().toISOString(), seed,
  source: { name: 'Phishing.Database', commit, committedAt: sourceDate,
    url: `https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/${commit}/phishing-links-ACTIVE.txt`,
    sha256: hashStream.digest('hex'), license: 'MIT', status: 'upstream_active_at_snapshot_not_rechecked',
    upstreamStats: sampler.stats() },
  publicSuffixList: { url: 'https://publicsuffix.org/list/public_suffix_list.dat', sha256: digest(pslText), includesPrivate: true },
  curatedControls: { source: 'extension/lib/lists.js BUILTIN_TRUSTED official homepages',
    repoCommit: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
    seedListSha256: digest(JSON.stringify(BUILTIN_TRUSTED)), conflictsExcluded: conflicts.length,
    caveat: 'Convenience controls, not independently verified benign labels or representative employee traffic' },
  counts, total: rows.length, grouping: 'one URL per PSL registrable domain (including private suffixes), or IPv4 /24 or exact IPv6',
  evaluation: 'URL-only, sanitized requests with neutral identical local hints; no source labels, reputation or blocklist hits sent to Jev',
};
fs.writeFileSync(path.join(output, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log(JSON.stringify({ output: path.resolve(output), counts, total: rows.length, conflictsExcluded: conflicts.length }, null, 2));
