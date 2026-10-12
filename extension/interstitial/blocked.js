const target = new URLSearchParams(location.search).get('url') || '';
const $ = (id) => document.getElementById(id);

function goToSafety() {
  chrome.runtime.sendMessage({ type: 'goToSafety' });
}

$('address').textContent = target;
$('safe').addEventListener('click', goToSafety);
$('no').addEventListener('click', goToSafety);
$('continue').addEventListener('click', () => {
  $('continue').hidden = true;
  $('confirm').hidden = false;
  $('no').focus();
});
$('yes').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ type: 'proceedAnyway', url: target });
  location.replace(target);
});

if (/^https?:/.test(target)) {
  const res = await chrome.runtime.sendMessage({ type: 'describeUrl', url: target });
  if (res?.text) {
    $('headline').textContent = res.text.headline;
    $('advice').textContent = res.text.advice;
    for (const r of res.text.reasons) {
      const li = document.createElement('li');
      li.textContent = r;
      $('reasons').appendChild(li);
    }
  }
}
$('safe').focus();
