// Build a labelled URL set for evaluating Jev (eval/urlhaus-jev.json):
// malicious URLs sampled from URLhaus, benign ones from the Tranco top list
// plus real downloads hosted on the same kinds of hosts URLhaus abuses.
//
//   curl -sSLo urlhaus.csv https://urlhaus.abuse.ch/downloads/csv_recent/
//   curl -sSLo tranco.zip https://tranco-list.eu/top-1m.csv.zip && unzip tranco.zip   # top-1m.csv
//   node scripts/build-urlhaus-dataset.mjs --urlhaus urlhaus.csv --tranco top-1m.csv
//
// Options: --out <file> (default eval/urlhaus-jev.json), --seed <n> (default 1).
//
// URLhaus is dominated by a few kinds of URL (raw.githubusercontent.com
// payloads, IoT botnet IP:port droppers), so the malicious side is sampled in
// fixed quotas per stratum, with at most a couple of URLs per host (per repo
// owner on code hosts). The same seed and inputs give the same file.

import { readFileSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

const { values: args } = parseArgs({
  options: {
    urlhaus: { type: 'string' },
    tranco: { type: 'string' },
    out: { type: 'string', default: 'eval/urlhaus-jev.json' },
    seed: { type: 'string', default: '1' },
  },
});
if (!args.urlhaus || !args.tranco) {
  console.error('usage: node scripts/build-urlhaus-dataset.mjs --urlhaus <csv> --tranco <top-1m.csv> [--out file] [--seed n]');
  process.exit(2);
}

// --- strata -------------------------------------------------------------------

const MALICIOUS_QUOTA = { ip_host: 40, code_hosting: 40, file_sharing: 30, free_dynamic_host: 30, dedicated_domain: 60 };
const BENIGN_QUOTA = { tranco_top_1k: 60, tranco_1k_10k: 50, tranco_10k_100k: 50 };

const CODE_HOSTS = ['github.com', 'raw.githubusercontent.com', 'objects.githubusercontent.com', 'gist.github.com',
  'gist.githubusercontent.com', 'gitlab.com', 'bitbucket.org', 'codeberg.org'];
const FILE_HOSTS = ['cdn.discordapp.com', 'media.discordapp.net', 'drive.google.com', 'docs.google.com',
  'drive.usercontent.google.com', 'dropbox.com', 'dl.dropboxusercontent.com', 'res.cloudinary.com', 'mediafire.com',
  'onedrive.live.com', '1drv.ms', 'files.catbox.moe', 'pixeldrain.com', 'transfer.sh', 'firebasestorage.googleapis.com',
  'storage.googleapis.com', 's3.amazonaws.com'];
const FREE_HOST_SUFFIXES = ['workers.dev', 'pages.dev', 'duckdns.org', 'work.gd', 'ngrok-free.app', 'ngrok.io',
  'trycloudflare.com', 'netlify.app', 'vercel.app', 'web.app', 'firebaseapp.com', 'glitch.me', 'repl.co',
  'ddns.net', 'no-ip.org', 'hopto.org', 'serveo.net', 'qzz.io', 'sld.tw', 'devs.surf'];

const onHost = (host, list) => list.some((h) => host === h || host.endsWith(`.${h}`));

function malwareStratum(host) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[')) return 'ip_host';
  if (onHost(host, CODE_HOSTS)) return 'code_hosting';
  if (onHost(host, FILE_HOSTS) || /^s3[.-].*amazonaws\.com$/.test(host)) return 'file_sharing';
  if (onHost(host, FREE_HOST_SUFFIXES)) return 'free_dynamic_host';
  return 'dedicated_domain';
}

// Shared hosts serve many unrelated owners; cap per owner, not per host.
function ownerKey(u, stratum) {
  if (stratum === 'code_hosting' || stratum === 'file_sharing') {
    return `${u.hostname}/${u.pathname.split('/').filter(Boolean)[0] || ''}`;
  }
  return u.hostname;
}

// Real, legitimate downloads and install scripts on the kinds of hosts URLhaus
// lists most (GitHub releases, raw GitHub, GitLab, file shares) and on vendor
// sites, with executable and archive paths. Without these, a model could score
// well just by flagging every .exe or raw.githubusercontent.com URL.
// Each one returned HTTP 200 when this list was made (2026-10).
const BENIGN_HARD = [
  'https://github.com/git-for-windows/git/releases/download/v2.47.0.windows.1/Git-2.47.0-64-bit.exe',
  'https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.7/npp.8.7.Installer.x64.exe',
  'https://github.com/microsoft/terminal/releases/download/v1.21.2361.0/Microsoft.WindowsTerminal_1.21.2361.0_8wekyb3d8bbwe.msixbundle',
  'https://github.com/obsproject/obs-studio/releases/download/30.2.3/OBS-Studio-30.2.3-Windows-Installer.exe',
  'https://github.com/keepassxreboot/keepassxc/releases/download/2.7.9/KeePassXC-2.7.9-Win64.msi',
  'https://github.com/PowerShell/PowerShell/releases/download/v7.4.5/PowerShell-7.4.5-win-x64.msi',
  'https://github.com/cli/cli/releases/download/v2.58.0/gh_2.58.0_windows_amd64.zip',
  'https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-x86_64-pc-windows-msvc.zip',
  'https://github.com/neovim/neovim/releases/download/v0.10.2/nvim-win64.zip',
  'https://github.com/jgm/pandoc/releases/download/3.5/pandoc-3.5-windows-x86_64.msi',
  'https://github.com/ShareX/ShareX/releases/download/v16.1.0/ShareX-16.1.0-setup.exe',
  'https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh',
  'https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh',
  'https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh',
  'https://raw.githubusercontent.com/python-poetry/install.python-poetry.org/main/install-poetry.py',
  'https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3',
  'https://raw.githubusercontent.com/github/gitignore/main/Python.gitignore',
  'https://raw.githubusercontent.com/torvalds/linux/master/README',
  'https://raw.githubusercontent.com/microsoft/vscode/main/README.md',
  'https://gitlab.com/gitlab-org/gitlab-runner/-/raw/main/README.md',
  'https://gitlab.com/inkscape/inkscape/-/archive/master/inkscape-master.zip',
  'https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe',
  'https://nodejs.org/dist/v20.18.0/node-v20.18.0-x64.msi',
  'https://www.7-zip.org/a/7z2408-x64.exe',
  'https://get.videolan.org/vlc/3.0.21/win64/vlc-3.0.21-win64.exe',
  'https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US',
  'https://dl.google.com/chrome/install/latest/chrome_installer.exe',
  'https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe',
  'https://download.sysinternals.com/files/ProcessExplorer.zip',
  'https://aka.ms/vs/17/release/vc_redist.x64.exe',
  'https://go.microsoft.com/fwlink/?LinkID=760868',
  'https://get.docker.com/',
  'https://sh.rustup.rs/',
  'https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe',
  'https://bootstrap.pypa.io/get-pip.py',
  'https://downloads.raspberrypi.com/imager/imager_latest.exe',
  'https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.11.tar.xz',
  'https://archive.apache.org/dist/tomcat/tomcat-10/v10.1.30/bin/apache-tomcat-10.1.30.zip',
  'https://repo1.maven.org/maven2/junit/junit/4.13.2/junit-4.13.2.jar',
  'https://files.pythonhosted.org/packages/source/r/requests/requests-2.32.3.tar.gz',
  'https://registry.npmjs.org/express/-/express-4.21.1.tgz',
  'https://www.dropbox.com/download?plat=win',
  'https://zoom.us/client/latest/ZoomInstallerFull.exe',
  'https://download.teamviewer.com/download/TeamViewer_Setup_x64.exe',
  'https://www.win-rar.com/fileadmin/winrar-versions/winrar/winrar-x64-701.exe',
];

// --- helpers --------------------------------------------------------------------

// mulberry32: small seeded PRNG so the sample is reproducible.
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function shuffle(items, rand) {
  const a = [...items];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

// URLhaus CSV: every field is double-quoted, comment lines start with '#'.
function parseCsvLine(line) {
  const out = [];
  const re = /"((?:[^"]|"")*)"(?:,|$)/g;
  let m;
  while ((m = re.exec(line))) out.push(m[1].replace(/""/g, '"'));
  return out;
}

function parseUrl(raw) {
  try {
    const u = new URL(raw);
    return ['http:', 'https:'].includes(u.protocol) && u.hostname ? u : null;
  } catch {
    return null;
  }
}

// --- malicious: URLhaus ---------------------------------------------------------

const rand = rng(Number(args.seed));
const urlhausRows = readFileSync(args.urlhaus, 'utf8').split(/\r?\n/)
  .filter((l) => l && !l.startsWith('#'))
  .map(parseCsvLine)
  .filter((r) => r.length >= 9)
  .map(([id, dateadded, url, status, , threat, tags]) => ({ id, dateadded, url, status, threat, tags }));

const urlhausHosts = new Set();
const pools = Object.fromEntries(Object.keys(MALICIOUS_QUOTA).map((k) => [k, []]));
for (const row of urlhausRows) {
  const u = parseUrl(row.url);
  if (!u) continue;
  urlhausHosts.add(u.hostname.toLowerCase());
  pools[malwareStratum(u.hostname.toLowerCase())].push({ ...row, u });
}

const malicious = [];
const seenUrls = new Set();
for (const [stratum, quota] of Object.entries(MALICIOUS_QUOTA)) {
  const perOwner = new Map();
  const cap = stratum === 'ip_host' ? 1 : 2;
  let taken = 0;
  for (const row of shuffle(pools[stratum], rand)) {
    if (taken >= quota) break;
    const key = ownerKey(row.u, stratum);
    if ((perOwner.get(key) || 0) >= cap || seenUrls.has(row.u.href)) continue;
    perOwner.set(key, (perOwner.get(key) || 0) + 1);
    seenUrls.add(row.u.href);
    taken++;
    malicious.push({
      url: row.url,
      label: 'malicious',
      source: 'urlhaus',
      stratum,
      threat: row.threat,
      tags: row.tags && row.tags !== 'None' ? row.tags.split(',') : [],
      urlhaus: { id: Number(row.id), dateadded: row.dateadded, status: row.status },
    });
  }
  if (taken < quota) console.warn(`warning: only ${taken}/${quota} URLs for ${stratum}`);
}

// --- benign: Tranco + hard negatives ------------------------------------------

// A Tranco domain is skipped when URLhaus lists it or any host under it (so
// github.com, google.com, dropbox.com stay out of the plain-domain sample;
// the hard negatives above cover them with real paths).
const listedUnder = (domain) => {
  for (const h of urlhausHosts) if (h === domain || h.endsWith(`.${domain}`)) return true;
  return false;
};

const tranco = readFileSync(args.tranco, 'utf8').split(/\r?\n/)
  .map((l) => l.split(','))
  .filter(([rank, domain]) => rank && domain)
  .map(([rank, domain]) => ({ rank: Number(rank), domain: domain.trim().toLowerCase() }));
const bands = {
  tranco_top_1k: tranco.filter((t) => t.rank <= 1000),
  tranco_1k_10k: tranco.filter((t) => t.rank > 1000 && t.rank <= 10000),
  tranco_10k_100k: tranco.filter((t) => t.rank > 10000 && t.rank <= 100000),
};

const benign = [];
for (const [stratum, quota] of Object.entries(BENIGN_QUOTA)) {
  let taken = 0;
  for (const t of shuffle(bands[stratum], rand)) {
    if (taken >= quota) break;
    if (listedUnder(t.domain) || !parseUrl(`https://${t.domain}/`)) continue;
    taken++;
    benign.push({ url: `https://${t.domain}/`, label: 'benign', source: 'tranco', stratum, tranco: { rank: t.rank } });
  }
}
for (const url of BENIGN_HARD) {
  benign.push({ url, label: 'benign', source: 'curated', stratum: 'download_on_shared_or_vendor_host' });
}

// --- write -----------------------------------------------------------------------

const entries = [...malicious, ...benign].map((e, i) => ({ id: i + 1, ...e }));
const count = (list, key) => list.reduce((m, e) => ({ ...m, [e[key]]: (m[e[key]] || 0) + 1 }), {});
const dataset = {
  description: 'Labelled URLs for evaluating Jev. Malicious: URLhaus (abuse.ch) malware-distribution URLs, ' +
    'stratified by hosting type. Benign: Tranco top-list domains (excluding any domain URLhaus lists) and ' +
    'real software downloads on the kinds of hosts URLhaus abuses. Malicious URLs are live malware links: ' +
    'do not open them.',
  generated: new Date().toISOString(),
  sources: {
    urlhaus: { url: 'https://urlhaus.abuse.ch/downloads/csv_recent/', rows: urlhausRows.length,
      terms: 'https://urlhaus.abuse.ch/api/ (CC0)' },
    tranco: { url: 'https://tranco-list.eu/top-1m.csv.zip', rows: tranco.length },
  },
  seed: Number(args.seed),
  counts: { label: count(entries, 'label'), stratum: count(entries, 'stratum') },
  entries,
};
writeFileSync(args.out, `${JSON.stringify(dataset, null, 1)}\n`);
console.log(`wrote ${entries.length} entries to ${args.out}`);
console.log(dataset.counts);
