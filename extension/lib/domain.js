// Hostname helpers: registrable domain (eTLD+1), punycode decoding, IP checks.
//
// A full Public Suffix List is ~200 KB; for the MVP we ship the multi-part
// suffixes that matter most for the users we target. Anything not listed is
// treated as a single-label suffix (".com", ".xyz", ...).

const MULTI_PART_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'ac.uk', 'gov.uk', 'nhs.uk',
  'com.au', 'net.au', 'org.au', 'gov.au', 'edu.au',
  'co.nz', 'org.nz', 'govt.nz',
  'co.il', 'org.il', 'gov.il', 'ac.il',
  'co.za', 'org.za', 'gov.za',
  'co.in', 'net.in', 'org.in', 'gov.in',
  'co.jp', 'ne.jp', 'or.jp', 'go.jp',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'com.mx', 'org.mx', 'gob.mx',
  'com.ar', 'com.co', 'com.tr', 'com.sg', 'com.hk', 'com.cn', 'com.tw', 'co.kr',
  'ca.us', 'ny.us', 'tx.us',
]);

export function isIpHost(host) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return true;
  if (host.startsWith('[') || host.includes(':')) return true; // IPv6 literal
  // Integer / hex IP tricks such as http://3232235777/ or http://0xC0A80001/
  if (/^(0x[0-9a-f]+|\d+)$/i.test(host)) return true;
  return false;
}

// Hostnames that only resolve inside a home or office network.
const INTERNAL_SUFFIXES = ['localhost', 'local', 'lan', 'internal', 'intranet', 'corp', 'home', 'home.arpa', 'localdomain'];

function isPrivateIPv4(host) {
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127);
}

function isPrivateIPv6(host) {
  const h = host.replace(/^\[|\]$/g, '');
  if (!h.includes(':')) return false;
  return h === '::1' || /^f[cd][0-9a-f]{2}:/.test(h) || /^fe[89ab][0-9a-f]:/.test(h);
}

/**
 * Destinations on the user's own network: localhost, private IP ranges,
 * single-label names ("http://intranet/") and internal-only suffixes.
 * Numeric IPs written in other forms (integer, hex) are not treated as
 * internal, since that's an obfuscation trick.
 */
export function isInternalHost(host) {
  host = String(host || '').toLowerCase().replace(/\.$/, '');
  if (!host) return false;
  if (isPrivateIPv4(host) || isPrivateIPv6(host)) return true;
  if (isIpHost(host)) return false;
  if (!host.includes('.')) return true;
  return INTERNAL_SUFFIXES.some((s) => host === s || host.endsWith('.' + s));
}

/** Registrable domain, e.g. "login.paypal.co.uk" -> "paypal.co.uk". */
export function registrableDomain(host) {
  host = normalizeHost(host);
  if (!host || isIpHost(host)) return host;
  const labels = host.split('.');
  if (labels.length <= 2) return host;
  const lastTwo = labels.slice(-2).join('.');
  if (MULTI_PART_SUFFIXES.has(lastTwo)) return labels.slice(-3).join('.');
  return lastTwo;
}

/** Suffix ("com", "co.uk") for a host. */
export function publicSuffix(host) {
  const reg = registrableDomain(host);
  return reg.split('.').slice(1).join('.');
}

/** The registrable label without suffix: "paypal" for "www.paypal.co.uk". */
export function domainLabel(host) {
  return registrableDomain(host).split('.')[0];
}

/** Labels to the left of the registrable domain: ["login", "secure"] etc. */
export function subdomainLabels(host) {
  host = normalizeHost(host);
  const reg = registrableDomain(host);
  if (host === reg) return [];
  return host.slice(0, -(reg.length + 1)).split('.').filter(Boolean);
}

export function normalizeHost(host) {
  return String(host || '').toLowerCase().replace(/\.$/, '').replace(/^www\./, '');
}

/** True when `host` equals `domain` or is a subdomain of it. */
export function hostMatches(host, domain) {
  host = normalizeHost(host);
  domain = normalizeHost(domain);
  return host === domain || host.endsWith('.' + domain);
}

// ---------------------------------------------------------------------------
// Punycode (RFC 3492) decoder, so "xn--pypal-4ve.com" can be shown and checked
// as "pаypal.com". Browsers give us hostnames in punycode form.

const BASE = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700, INITIAL_BIAS = 72, INITIAL_N = 128;

function adapt(delta, numPoints, firstTime) {
  let k = 0;
  delta = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  delta += Math.floor(delta / numPoints);
  for (; delta > ((BASE - TMIN) * TMAX) >> 1; k += BASE) {
    delta = Math.floor(delta / (BASE - TMIN));
  }
  return Math.floor(k + ((BASE - TMIN + 1) * delta) / (delta + SKEW));
}

function basicToDigit(cp) {
  if (cp >= 0x30 && cp < 0x3a) return cp - 22;
  if (cp >= 0x41 && cp < 0x5b) return cp - 0x41;
  if (cp >= 0x61 && cp < 0x7b) return cp - 0x61;
  return BASE;
}

function decodeLabel(input) {
  const output = [];
  let i = 0, n = INITIAL_N, bias = INITIAL_BIAS;
  let basic = input.lastIndexOf('-');
  if (basic < 0) basic = 0;
  for (let j = 0; j < basic; ++j) output.push(input.charCodeAt(j));
  for (let index = basic > 0 ? basic + 1 : 0; index < input.length;) {
    const oldi = i;
    for (let w = 1, k = BASE; ; k += BASE) {
      if (index >= input.length) throw new Error('punycode: bad input');
      const digit = basicToDigit(input.charCodeAt(index++));
      if (digit >= BASE) throw new Error('punycode: bad input');
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
    }
    const out = output.length + 1;
    bias = adapt(i - oldi, out, oldi === 0);
    n += Math.floor(i / out);
    i %= out;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

/** "xn--pypal-4ve.com" -> "pаypal.com". Labels that fail to decode are kept. */
export function toUnicodeHost(host) {
  return normalizeHost(host)
    .split('.')
    .map((label) => {
      if (!label.startsWith('xn--')) return label;
      try {
        return decodeLabel(label.slice(4));
      } catch {
        return label;
      }
    })
    .join('.');
}
