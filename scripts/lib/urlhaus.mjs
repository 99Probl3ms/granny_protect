// Parse the URLhaus CSV export without interpreting any listed URL as a fetch.
export function parseCsv(text) {
  const rows = [];
  let row = [], field = '', quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      if (quoted && text[i + 1] === '"') { field += '"'; i++; }
      else if (quoted || !field.length) quoted = !quoted;
      else field += c;
    } else if (!quoted && c === ',') { row.push(field); field = ''; }
    else if (!quoted && (c === '\n' || c === '\r')) {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(field); rows.push(row); row = []; field = '';
    } else field += c;
  }
  if (quoted) throw new Error('Unclosed quote in URLhaus CSV');
  if (field.length || row.length) { row.push(field); rows.push(row); }
  return rows;
}

export function parseUrlhausCsv(text) {
  text = text.replace(/^\uFEFF/, '');
  let columns = ['id', 'dateadded', 'url', 'url_status', 'last_online', 'threat', 'tags', 'urlhaus_link', 'reporter'];
  const records = [];
  for (const fields of parseCsv(text)) {
    const first = fields[0]?.trim() || '';
    const header = fields.map((s, i) => (i ? s : s.replace(/^#\s*/, '')).trim().toLowerCase());
    if (header.includes('url') && header.includes('url_status') && header.includes('threat')) { columns = header; continue; }
    if (!first || first.startsWith('#')) continue;
    const row = Object.fromEntries(columns.map((key, index) => [key, fields[index]]));
    if (!/^\d+$/.test(row.id || '') || !row.url || !['online', 'offline', 'unknown'].includes(row.url_status) ||
        row.threat !== 'malware_download') throw new Error('Unexpected URLhaus CSV schema or threat label');
    const added = row.dateadded || row.date_added;
    const isoDate = added && /Z$|[+-]\d\d:\d\d$/.test(added) ? added : added?.replace(' ', 'T') + 'Z';
    if (!added || Number.isNaN(Date.parse(isoDate))) throw new Error('Invalid URLhaus report timestamp');
    records.push({ url: row.url, evidence: { feedId: row.id, dateAdded: new Date(isoDate).toISOString(),
      status: row.url_status, lastOnline: row.last_online || null, threat: row.threat, tags: row.tags || null } });
  }
  if (!records.length) throw new Error('URLhaus CSV contains no malware-download records');
  return records;
}

export async function downloadUrlhausExport({ apiKey, fetch: doFetch = fetch } = {}) {
  if (!apiKey) throw new Error('URLHAUS_AUTH_KEY is required, or use --csv FILE');
  // Official exports put the key in the path. Never return/log the URI,
  // redirect location, response body or an underlying fetch exception.
  let response;
  try {
    response = await doFetch(`https://urlhaus-api.abuse.ch/v2/files/exports/${encodeURIComponent(apiKey)}/recent.csv`, {
      redirect: 'error', signal: AbortSignal.timeout(60000),
    });
  } catch { throw new Error('URLhaus export download failed (network, redirect or timeout)'); }
  if (!response.ok) throw new Error(`URLhaus export HTTP ${response.status}`);
  const chunks = [];
  let bytes = 0;
  try {
    for await (const chunk of response.body) {
      bytes += chunk.byteLength;
      if (bytes > 128 * 1024 * 1024) throw new Error('too large');
      chunks.push(chunk);
    }
  } catch { throw new Error('URLhaus CSV transfer failed or exceeded the 128 MB limit'); }
  const text = Buffer.concat(chunks).toString('utf8');
  if (text.includes(apiKey)) throw new Error('URLhaus export unexpectedly contains the authentication key; refusing to save it');
  return text;
}
