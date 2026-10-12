import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { buildReviewRequest } from '../../extension/lib/sanitize.js';
import { isInternalHost } from '../../extension/lib/domain.js';

export const digest = (text) => createHash('sha256').update(text).digest('hex');

// Full PSL, including PRIVATE rules: tenants of shared hosting stay distinct.
export function parseSuffixList(text) {
  const rules = new Set(), wildcards = new Set(), exceptions = new Set();
  for (let line of text.split(/\r?\n/)) {
    line = line.trim();
    if (!line || line.startsWith('//')) continue;
    const target = line.startsWith('!') ? exceptions : line.startsWith('*.') ? wildcards : rules;
    const suffix = line.replace(/^!|^\*\./, '');
    target.add(new URL(`https://${suffix}`).hostname.toLowerCase());
  }
  if (!rules.size) throw new Error('Public Suffix List is empty');
  return { rules, wildcards, exceptions };
}

export function domainGroup(host, psl) {
  host = host.toLowerCase().replace(/\.$/, '');
  const ip = host.replace(/^\[|\]$/g, '');
  if (isIP(ip) === 4) return `ipv4:${ip.split('.').slice(0, 3).join('.')}.0/24`;
  // URL canonicalization compresses IPv6 consistently; exact-IP groups suffice.
  if (isIP(ip) === 6) return `ipv6:${ip}`;
  const labels = host.split('.');
  let length = 1;
  for (let i = 0; i < labels.length; i++) {
    const suffix = labels.slice(i).join('.');
    if (psl.exceptions.has(suffix)) return labels.slice(i).join('.');
    if (psl.rules.has(suffix)) length = Math.max(length, labels.length - i);
    if (i > 0 && psl.wildcards.has(suffix)) length = Math.max(length, labels.length - i + 1);
  }
  return labels.slice(-Math.min(labels.length, length + 1)).join('.');
}

export function canonicalUrl(raw) {
  try {
    const u = new URL(raw.trim());
    if (!['http:', 'https:'].includes(u.protocol) || isInternalHost(u.hostname)) return null;
    return u.href;
  } catch { return null; }
}

export function createSampler(psl, seed) {
  const selected = new Map();
  let lines = 0, valid = 0;
  function add(raw, evidence = undefined) {
    lines++;
    const url = canonicalUrl(raw);
    if (!url) return;
    valid++;
    const group = domainGroup(new URL(url).hostname, psl);
    const rank = digest(`${seed}\0${url}`);
    if (!selected.has(group) || rank < selected.get(group).rank) selected.set(group, { url, group, rank, evidence });
  }
  return { add, selected, stats: () => ({ lines, valid, groups: selected.size }) };
}

export function makeRecords(positives, negatives, { size = 250, seed = 'jev-threat-dataset-v1', positiveLabel = 'phishing', positiveSource = 'Phishing.Database' } = {}) {
  const choose = (pool) => [...pool].sort((a, b) =>
    digest(`${seed}\0group\0${a.group}`).localeCompare(digest(`${seed}\0group\0${b.group}`))).slice(0, size);
  // Groups get a reproducible split within this snapshot. Exactly 20% per class is
  // held out, with a disjoint domain/network group for every selected example.
  function records(pool, label, source) {
    const selected = choose(pool);
    const testCount = Math.floor(selected.length * 0.2);
    return selected.map(({ url, group, evidence }, index) => ({
      id: digest(url).slice(0, 20), url, group, label, source,
      labelBasis: label !== 'benign_reference' ? `upstream_reported_${label}` : 'project_curated_official_homepage_not_independently_verified',
      split: index < testCount ? 'test' : 'development',
      expected: label !== 'benign_reference' ? 'not_allow' : 'allow',
      ...(evidence ? { evidence } : {}),
      // Equal hints for both classes. Never give Jev the feed label or a known
      // blocklist hit; this benchmark measures URL-only semantic judgement.
      request: buildReviewRequest(url, { action: 'needs_review', risk: 0.5, reasons: [], brand: null }),
    }));
  }
  return [...records(positives, positiveLabel, positiveSource),
    ...records(negatives, 'benign_reference', 'project_curated_official_homepages')]
    .sort((a, b) => digest(`${seed}\0order\0${a.id}`).localeCompare(digest(`${seed}\0order\0${b.id}`)));
}
