// Talks to the granny_protect backend. The Jev API key lives there, never in
// the extension.

/** Thrown when the backend has Tier 3 switched off (kill switch). */
export class ModelDisabledError extends Error {}

/**
 * POST a page summary to the backend's /classify endpoint.
 * @param {import('./summary.js').PageSummary} summary
 * @param {{backendUrl:string, installId:string, timeoutMs?:number, fetch?:typeof fetch}} opts
 * @returns {Promise<import('./fusion.js').ModelResult>}
 */
export async function classifyRemote(summary, { backendUrl, installId, timeoutMs = 10000, fetch: doFetch = fetch }) {
  const res = await doFetch(new URL('classify', backendUrl.endsWith('/') ? backendUrl : `${backendUrl}/`), {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-install-id': installId },
    body: JSON.stringify({ summary }),
    credentials: 'omit',
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (res.status === 503) {
    const body = await res.json().catch(() => ({}));
    if (body.disabled) throw new ModelDisabledError('Tier 3 disabled by backend');
  }
  if (!res.ok) throw new Error(`backend HTTP ${res.status}`);
  const data = await res.json();
  if (!Number.isFinite(data?.p_phish)) throw new Error('backend returned no p_phish');
  return {
    p_phish: data.p_phish,
    category: String(data.category ?? ''),
    category_confidence: Number(data.category_confidence) || 0,
    pressure: Number.isFinite(data.pressure) ? data.pressure : null,
    model: String(data.model ?? ''),
  };
}
