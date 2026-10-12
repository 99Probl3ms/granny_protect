// Enterprise policy rules. Unlike the heuristics these aren't scored and can't
// be overridden: not by the trusted list, the internal-network rule, a
// user-trusted site, or "continue anyway".

/**
 * Passwords must never be typed into, or sent from, a page without
 * encryption (http).
 * @param {import('./pageHeuristics.js').PageFeatures} page
 * @returns {{code: string, weight: number} | null}
 */
export function insecurePasswordViolation(page) {
  let protocol;
  try {
    protocol = new URL(page.url).protocol;
  } catch {
    return null;
  }
  const forms = page.forms || [];
  const hasPassword = (page.fields?.password || 0) + (page.passwordInputs || 0) > 0 ||
    forms.some((f) => f.hasPassword);
  if (!hasPassword) return null;
  if (protocol === 'http:') return { code: 'password_on_http_page', weight: 1 };
  if (forms.some((f) => f.hasPassword && f.actionProtocol === 'http:')) {
    return { code: 'password_sent_over_http', weight: 1 };
  }
  return null;
}
