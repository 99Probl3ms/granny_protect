import { test } from 'node:test';
import assert from 'node:assert/strict';
import { downloadUrlhausExport, parseCsv, parseUrlhausCsv } from '../scripts/lib/urlhaus.mjs';
import { createSampler, makeRecords, parseSuffixList } from '../scripts/lib/phishing-dataset.mjs';
import { datasetMetrics } from '../scripts/lib/evaluation-cases.mjs';

const CSV = '# URLhaus export\r\n# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\r\n'
  + '"1","2026-10-12 10:00:00","https://download.example/a,b.exe","online","2026-10-12 10:00:00","malware_download","exe,agent","https://urlhaus.abuse.ch/url/1/","reporter"\r\n'
  + '"2","2026-10-11 10:00:00","https://offline.example/a.exe","offline","","malware_download","exe","https://urlhaus.abuse.ch/url/2/","reporter"\r\n';

test('URLhaus parser handles commented header, quoting and report status without relabeling offline URLs', () => {
  const rows = parseUrlhausCsv(CSV);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].url, 'https://download.example/a,b.exe');
  assert.equal(rows[0].evidence.dateAdded, '2026-10-12T10:00:00.000Z');
  assert.equal(rows[1].evidence.status, 'offline');
  assert.equal(rows[0].evidence.tags, 'exe,agent');
  assert.deepEqual(parseCsv('"a""b","two\nlines"\n'), [['a"b', 'two\nlines']]);
  assert.throws(() => parseUrlhausCsv('unauthorized'), /schema/);
  assert.throws(() => parseUrlhausCsv(CSV.replaceAll('malware_download', 'phishing')), /threat/);
  assert.throws(() => parseCsv('"unterminated'), /Unclosed/);
});

test('export downloader uses official endpoint and never exposes the key on failure', async () => {
  let seen;
  const text = await downloadUrlhausExport({ apiKey: 'test-secret', fetch: async (url, options) => {
    seen = { url, options }; return new Response(CSV);
  } });
  assert.equal(text, CSV);
  assert.equal(seen.url, 'https://urlhaus-api.abuse.ch/v2/files/exports/test-secret/recent.csv');
  assert.equal(seen.options.redirect, 'error');
  await assert.rejects(downloadUrlhausExport({ apiKey: 'test-secret', fetch: async () => { throw new Error('https://secret/test-secret'); } }),
    (err) => !err.message.includes('test-secret') && !err.cause);
  await assert.rejects(downloadUrlhausExport({ apiKey: 'test-secret', fetch: async () => new Response('test-secret', { status: 401 }) }), /HTTP 401/);
  await assert.rejects(downloadUrlhausExport({ apiKey: 'test-secret', fetch: async () => new Response('test-secret') }), /refusing to save/);
});

test('malware reports stay separate and source evidence never enters model state', () => {
  const psl = parseSuffixList('com\n');
  const pool = createSampler(psl, 'seed');
  pool.add('https://download.com/payload.exe', { tags: 'agent', status: 'online', threat: 'malware_download' });
  const [row] = makeRecords(pool.selected.values(), [], { size: 1, positiveLabel: 'malware_download', positiveSource: 'URLhaus' });
  assert.equal(row.label, 'malware_download');
  assert.equal(row.evidence.status, 'online');
  assert.equal(row.expected, 'not_allow');
  assert.doesNotMatch(JSON.stringify(row.request), /URLhaus|malware_download|agent|online/);
  const metrics = datasetMetrics([{ label: 'malware_download', effective: 'allow' }, { label: 'malware_download', effective: 'block' }]);
  assert.equal(metrics.phishingCatchRate, null);
  assert.equal(metrics.malwareCatchRate, 0.5);
});
