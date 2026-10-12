// Jev adapter: turns a sanitized review request into a review
// ({decision, confidence, category, model}).
//
// NOT IMPLEMENTED YET. The request/response format must come from TypeSafe's
// live docs (https://docs.typesafe.ai/llms.txt, the API or JavaScript SDK
// page, and the Noul / Choice primitive pages), which this environment
// couldn't reach. Until then this adapter refuses to run instead of guessing
// at the API, so the extension keeps destinations gated for review.
//
// Planned questions (to confirm against the docs), asked together on the
// same state so they run in parallel:
//   - Noul: "Is this destination trying to trick the user into giving
//     credentials, money or remote access?" -> probability of phishing
//   - Choice: which kind of scam, with a "none of these" option
//     (credential_phish, tech_support_scam, payment_scam, suspicious_site)
// Mapping (thresholds to be tuned on tests/fixtures/destinations.js):
//   p >= 0.85 -> block, p <= 0.15 -> allow, otherwise needs_review;
//   confidence = how far p is from the undecided middle.

export class JevNotConfigured extends Error {}

export function createJevModel({ apiKey = process.env.TYPESAFE_API_KEY, endpoint = process.env.TYPESAFE_API_URL } = {}) {
  return {
    name: 'jev',
    async classify(/* request */) {
      if (!apiKey) throw new JevNotConfigured('TYPESAFE_API_KEY is not set');
      throw new JevNotConfigured('Jev adapter not implemented yet: pending TypeSafe API docs');
    },
    configured: Boolean(apiKey && endpoint),
  };
}
