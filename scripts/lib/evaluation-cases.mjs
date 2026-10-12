import fs from 'node:fs';
import { cleanRequest } from '../../server/server.mjs';

export function loadDataset(filename) {
  const rows = fs.readFileSync(filename, 'utf8').split(/\r?\n/).filter((s) => s.trim());
  if (!rows.length) throw new Error('Dataset is empty');
  const ids = new Set();
  return rows.map((line, index) => {
    let row;
    try { row = JSON.parse(line); } catch { throw new Error(`Invalid dataset JSON on line ${index + 1}`); }
    const request = cleanRequest(row.request);
    if (typeof row.id !== 'string' || ids.has(row.id) || !request ||
      !['phishing', 'malware_download', 'benign_reference'].includes(row.label) ||
      row.expected !== (row.label !== 'benign_reference' ? 'not_allow' : 'allow')) {
      throw new Error(`Invalid or duplicate dataset case on line ${index + 1}`);
    }
    ids.add(row.id);
    // Keep labels outside the HTTP state. Also reapply server sanitization.
    return { id: row.id, expected: row.expected, label: row.label, request };
  });
}

export function datasetMetrics(rows) {
  const matrix = Object.fromEntries(['phishing', 'malware_download', 'benign_reference'].map((label) => [label,
    Object.fromEntries(['allow', 'needs_review', 'block'].map((decision) => [decision,
      rows.filter((r) => r.label === label && r.effective === decision).length]))]));
  const positives = Object.values(matrix.phishing).reduce((a, b) => a + b, 0);
  const malware = Object.values(matrix.malware_download).reduce((a, b) => a + b, 0);
  const negatives = Object.values(matrix.benign_reference).reduce((a, b) => a + b, 0);
  const blocks = matrix.phishing.block + matrix.malware_download.block + matrix.benign_reference.block;
  return { matrix,
    phishingCatchRate: positives ? (positives - matrix.phishing.allow) / positives : null,
    phishingBlockRecall: positives ? matrix.phishing.block / positives : null,
    malwareCatchRate: malware ? (malware - matrix.malware_download.allow) / malware : null,
    malwareBlockRecall: malware ? matrix.malware_download.block / malware : null,
    benignReferenceHoldRate: negatives ? (negatives - matrix.benign_reference.allow) / negatives : null,
    blockPrecisionOnThisSample: blocks ? (matrix.phishing.block + matrix.malware_download.block) / blocks : null };
}
