// Gate page: shown instead of a destination that is blocked or needs review.
// The address arrives as ?url=... from the background script, or after the
// '#' from a declarativeNetRequest redirect rule.
const target = new URLSearchParams(location.search).get('url') || location.hash.slice(1);
const $ = (id) => document.getElementById(id);

function goToSafety() {
  chrome.runtime.sendMessage({ type: 'goToSafety' });
}

async function proceed() {
  await chrome.runtime.sendMessage({ type: 'proceedAnyway', url: target });
  location.replace(target);
}

$('address').textContent = target;
$('safe').addEventListener('click', goToSafety);
$('no').addEventListener('click', goToSafety);
$('yes').addEventListener('click', proceed);
$('safe').focus();

if (/^https?:/.test(target)) {
  const res = await chrome.runtime.sendMessage({ type: 'describeUrl', url: target });
  const verdict = res?.verdict;
  if (verdict && (verdict.action === 'allow' || verdict.overridden)) {
    // Allowed since the gate was shown (e.g. the user now trusts the site).
    location.replace(target);
  } else {
    const mode = verdict?.action === 'needs_review' ? 'review' : 'block';
    document.body.dataset.mode = mode;
    document.title = mode === 'block' ? 'Dangerous website blocked' : 'Check this website';
    $('icon').textContent = mode === 'block' ? '⛔' : '⚠️';
    $('address-label').textContent = mode === 'block' ? 'Blocked address' : 'Address';
    if (res?.text) {
      $('headline').textContent = res.text.headline;
      $('advice').textContent = res.text.advice;
      $('reasons').replaceChildren(...res.text.reasons.map((r) => Object.assign(document.createElement('li'), { textContent: r })));
    }
    if (mode === 'review') {
      // Warning signs, not proof: one deliberate click continues.
      $('continue').textContent = 'Continue to the website';
      $('continue').addEventListener('click', proceed);
    } else {
      // Known or near-certain scam: confirm twice.
      $('continue').addEventListener('click', () => {
        $('continue').hidden = true;
        $('confirm').hidden = false;
        $('no').focus();
      });
    }
  }
}
