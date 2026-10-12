const $ = (id) => document.getElementById(id);

const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
const url = tab?.url || '';

function render(status) {
  const { verdict, text, domain, userTrusted } = status;
  $('domain').textContent = domain;
  const risky = verdict.action !== 'allow';
  $('status').className = `status ${risky ? (verdict.action === 'block' ? 'block' : 'warn') : 'ok'}`;
  $('icon').textContent = risky ? (verdict.action === 'block' ? '⛔' : '⚠️') : '✅';

  if (risky) {
    $('headline').textContent = text.headline;
    $('advice').textContent = verdict.overridden ? 'You chose to continue to this site.' : text.advice;
    $('advice').hidden = false;
    $('reasons').replaceChildren(...text.reasons.map((r) => Object.assign(document.createElement('li'), { textContent: r })));
    $('reasons').hidden = !text.reasons.length;
  } else if (verdict.source === 'internal') {
    $('headline').textContent = 'This is on your own network';
  } else if (verdict.source === 'trusted') {
    $('headline').textContent = userTrusted ? 'You trust this website' : 'This is a well-known website';
  } else {
    $('headline').textContent = 'No problems found';
  }

  // Only offer to trust sites we haven't flagged; trusting a flagged site
  // should be a deliberate act on the warning itself.
  $('trust').hidden = !(verdict.action === 'allow' && verdict.source === 'heuristics');
  $('untrust').hidden = !userTrusted;
}

async function refresh() {
  const status = await chrome.runtime.sendMessage({ type: 'getTabStatus', tabId: tab.id, url });
  if (status) render(status);
}

if (/^https?:/.test(url)) {
  $('trust').addEventListener('click', async () => {
    await chrome.runtime.sendMessage({ type: 'trustSite', domain: new URL(url).hostname });
    refresh();
  });
  $('untrust').addEventListener('click', async () => {
    await chrome.runtime.sendMessage({ type: 'untrustSite', domain: new URL(url).hostname });
    refresh();
  });
  await refresh();
} else {
  $('headline').textContent = 'Nothing to check on this page';
}
