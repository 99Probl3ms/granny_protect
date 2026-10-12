// Content script (classic script, runs in every top-level http(s) page).
//  1. Extracts a small feature summary of the page and sends it to the
//     background for a verdict.
//  2. If the page is risky, shows a warning and locks password / card /
//     gift-card fields until the user deliberately chooses to continue.
//  3. Re-checks when the page adds a sensitive field later (single-page apps).
//  4. While a check is still running (the background may be waiting on the
//     Tier 3 model), holds typing in sensitive fields and says "Checking…".

(() => {
  if (window.top !== window || window.__grannyProtect) return;
  window.__grannyProtect = true;

  const MAX_TEXT = 6000;
  const MAX_RECHECKS = 5;
  // Never hold the user's typing longer than this, even if the background
  // doesn't answer (it gives up on the model well before this).
  const MAX_PENDING_MS = 4000;

  const GIFT_RE = /gift.?card|claim.?code|redemption|card.?pin|scratch/i;
  const CARD_RE = /card.?num|cc.?num|credit.?card|debit.?card|\bcvv\b|\bcvc\b|security.?code|expir/i;
  const SSN_RE = /\bssn\b|social.?security/i;
  const OTP_RE = /one.?time|\botp\b|verification.?code|2fa|auth.?code|sms.?code/i;
  const PHONE_RE = /(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b/g;

  let state = {
    verdict: null,       // last verdict from the background
    text: null,          // plain-language strings for it
    locked: false,       // sensitive inputs blocked until the user decides
    pending: false,      // a verdict is being computed; sensitive inputs held
    heldField: null,     // field the user tried to use while pending
    checking: null,      // "Checking this website…" note
    overlay: null,
    fullscreen: false,
    rechecks: 0,
  };

  // -------------------------------------------------------------------------
  // Feature extraction

  function describeInput(el) {
    return [el.name, el.id, el.placeholder, el.getAttribute('aria-label'), el.autocomplete, labelText(el)]
      .filter(Boolean).join(' ');
  }

  function labelText(el) {
    if (el.labels && el.labels.length) return [...el.labels].map((l) => l.innerText).join(' ');
    return '';
  }

  function isVisible(el) {
    const r = el.getBoundingClientRect();
    const cs = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none';
  }

  /** Classify an input as a sensitive kind, or null. */
  function sensitiveKind(el) {
    if (!(el instanceof HTMLInputElement) || el.type === 'hidden') return null;
    if (el.type === 'password') return 'password';
    const ac = (el.autocomplete || '').toLowerCase();
    const desc = describeInput(el);
    if (ac === 'one-time-code' || OTP_RE.test(desc)) return 'otp';
    if (GIFT_RE.test(desc)) return 'giftCard';
    if (ac.startsWith('cc-') || CARD_RE.test(desc)) return 'card';
    if (SSN_RE.test(desc)) return 'ssn';
    return null;
  }

  function extractFeatures() {
    const fields = { password: 0, card: 0, ssn: 0, giftCard: 0, otp: 0 };
    for (const el of document.querySelectorAll('input')) {
      const kind = sensitiveKind(el);
      if (kind && isVisible(el)) fields[kind]++;
    }

    const forms = [];
    for (const form of document.forms) {
      const hasPassword = !!form.querySelector('input[type=password]');
      if (!hasPassword) continue;
      let actionHost = location.hostname;
      try {
        actionHost = new URL(form.getAttribute('action') || location.href, location.href).hostname;
      } catch { /* keep page host */ }
      forms.push({ actionHost, hasPassword });
    }

    const meta = (sel) => document.querySelector(sel)?.getAttribute('content') || '';
    const identityTexts = [];
    for (const img of [...document.images].slice(0, 15)) {
      const t = [img.alt, img.title].filter(Boolean).join(' ');
      if (t) identityTexts.push(t);
    }
    for (const h of [...document.querySelectorAll('h1, h2, header, [class*=logo], [id*=logo]')].slice(0, 6)) {
      identityTexts.push((h.innerText || h.getAttribute('aria-label') || '').slice(0, 200));
    }

    const text = (document.body?.innerText || '').slice(0, MAX_TEXT);
    return {
      title: document.title.slice(0, 300),
      siteName: meta('meta[property="og:site_name"]') || meta('meta[name="application-name"]'),
      identityTexts: identityTexts.filter(Boolean),
      text,
      fields,
      forms,
      phoneNumbers: (text.match(PHONE_RE) || []).length,
      fullscreen: state.fullscreen,
    };
  }

  // -------------------------------------------------------------------------
  // Talking to the background

  let analysisSeq = 0;

  async function analyze() {
    const seq = ++analysisSeq;
    state.pending = true;
    const giveUp = setTimeout(() => seq === analysisSeq && endPending(), MAX_PENDING_MS);
    let res;
    try {
      res = await chrome.runtime.sendMessage({ type: 'analyzePage', features: extractFeatures() });
    } catch {
      res = null; // extension reloaded / background unavailable
    } finally {
      clearTimeout(giveUp);
    }
    if (seq !== analysisSeq) return; // a newer check is running
    if (!res) {
      endPending();
      return;
    }
    state.verdict = res.verdict;
    state.text = res.text;
    const risky = res.verdict.action !== 'allow' && !res.verdict.overridden;
    if (risky) {
      state.locked = true;
      state.heldField = null;
      showOverlay();
    } else {
      state.locked = false;
      removeOverlay();
    }
    endPending();
  }

  function endPending() {
    state.pending = false;
    removeChecking();
    const field = state.heldField;
    state.heldField = null;
    if (field && !state.locked && field.isConnected) field.focus();
  }

  // -------------------------------------------------------------------------
  // Input guard: while locked, sensitive fields can't be focused or typed in.

  // While a check is pending, hold the field and say we're checking; once the
  // verdict arrives the field is refocused (if safe) or the warning shown.
  function hold(target) {
    if (state.locked) {
      showOverlay();
    } else {
      state.heldField = target;
      showChecking();
    }
  }

  function guarded() {
    return state.locked || state.pending;
  }

  function onFocusIn(e) {
    if (!guarded() || !sensitiveKind(e.target)) return;
    e.target.blur();
    hold(e.target);
  }

  function onKeyDown(e) {
    if (!guarded() || !sensitiveKind(e.target)) return;
    e.preventDefault();
    e.stopImmediatePropagation();
    hold(e.target);
  }

  function onSubmit(e) {
    if (!guarded()) return;
    const form = e.target;
    if (form instanceof HTMLFormElement && [...form.elements].some((el) => sensitiveKind(el))) {
      e.preventDefault();
      e.stopImmediatePropagation();
      hold(null);
    }
  }

  document.addEventListener('focusin', onFocusIn, true);
  document.addEventListener('keydown', onKeyDown, true);
  document.addEventListener('submit', onSubmit, true);

  document.addEventListener('fullscreenchange', () => {
    if (document.fullscreenElement && !state.fullscreen) {
      state.fullscreen = true;
      analyze();
    }
  });

  // Re-check when a sensitive field appears later (single-page apps, pop-ups).
  let recheckTimer;
  const observer = new MutationObserver((mutations) => {
    if (state.rechecks >= MAX_RECHECKS) return;
    const addedSensitive = mutations.some((m) => [...m.addedNodes].some((n) =>
      n.nodeType === 1 && (sensitiveKind(n) || [...(n.querySelectorAll?.('input') || [])].some(sensitiveKind))));
    if (!addedSensitive) return;
    clearTimeout(recheckTimer);
    recheckTimer = setTimeout(() => {
      state.rechecks++;
      analyze();
    }, 400);
  });

  // -------------------------------------------------------------------------
  // Warning overlay (closed shadow DOM so page styles can't interfere).

  const STYLE = `
    :host { all: initial; }
    .backdrop { position: fixed; inset: 0; z-index: 2147483647; display: flex; align-items: center;
      justify-content: center; padding: 16px; box-sizing: border-box;
      font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
    .backdrop.warn { background: rgba(20, 20, 20, 0.82); }
    .backdrop.block { background: #7f1d1d; }
    .card { background: #fff; color: #1a1a1a; max-width: 620px; width: 100%; border-radius: 16px;
      padding: 32px; box-shadow: 0 10px 40px rgba(0,0,0,.4); max-height: 100%; overflow: auto; box-sizing: border-box; }
    .icon { font-size: 56px; line-height: 1; }
    h1 { font-size: 30px; line-height: 1.25; margin: 12px 0 12px; }
    p { font-size: 21px; line-height: 1.5; margin: 0 0 16px; }
    ul { font-size: 18px; line-height: 1.5; margin: 0 0 24px; padding-left: 22px; color: #444; }
    .safe { display: block; width: 100%; font-size: 24px; font-weight: 700; padding: 18px; border: 0;
      border-radius: 12px; background: #1b5e20; color: #fff; cursor: pointer; }
    .safe:focus-visible { outline: 4px solid #ffb300; outline-offset: 3px; }
    .continue { display: block; margin: 20px auto 0; background: none; border: 0; color: #555;
      font-size: 16px; text-decoration: underline; cursor: pointer; }
    .confirm { margin-top: 20px; padding: 16px; border-radius: 12px; background: #fff3e0; }
    .confirm p { font-size: 18px; }
    .confirm button { font-size: 18px; padding: 10px 16px; border-radius: 8px; border: 1px solid #999;
      background: #fff; cursor: pointer; margin-right: 8px; }
    .checking { position: fixed; top: 16px; left: 50%; transform: translateX(-50%); z-index: 2147483647;
      background: #1a1a1a; color: #fff; font: 600 20px/1.3 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
      padding: 14px 22px; border-radius: 12px; box-shadow: 0 6px 24px rgba(0,0,0,.35); }
    @media (prefers-color-scheme: dark) {
      .card { background: #1f1f1f; color: #f2f2f2; }
      ul { color: #ccc; } .continue { color: #bbb; }
      .confirm { background: #3e2a12; } .confirm button { background: #2a2a2a; color: #f2f2f2; }
    }
  `;

  function el(tag, attrs = {}, text) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
    if (text != null) node.textContent = text;
    return node;
  }

  // The page's own scripts can dispatch fake clicks; only a real user may
  // dismiss a warning.
  function onUserClick(button, fn) {
    button.addEventListener('click', (e) => {
      if (e.isTrusted) fn(e);
    });
  }

  function showOverlay() {
    if (state.overlay || !state.text) return;
    const host = el('div', { 'data-granny-protect': '' });
    const root = host.attachShadow({ mode: 'closed' });
    root.appendChild(el('style', {}, STYLE));

    const backdrop = el('div', {
      class: `backdrop ${state.verdict.action}`,
      role: 'alertdialog', 'aria-modal': 'true', 'aria-labelledby': 'gp-title',
    });
    const card = el('div', { class: 'card' });
    card.appendChild(el('div', { class: 'icon', 'aria-hidden': 'true' }, state.verdict.action === 'block' ? '⛔' : '⚠️'));
    card.appendChild(el('h1', { id: 'gp-title' }, state.text.headline));
    card.appendChild(el('p', {}, state.text.advice));
    if (state.text.reasons.length) {
      const ul = el('ul');
      for (const r of state.text.reasons) ul.appendChild(el('li', {}, r));
      card.appendChild(ul);
    }

    const safe = el('button', { class: 'safe', type: 'button' }, 'Take me to safety');
    onUserClick(safe, () => chrome.runtime.sendMessage({ type: 'goToSafety' }));
    card.appendChild(safe);

    const cont = el('button', { class: 'continue', type: 'button' }, 'I understand the risk');
    onUserClick(cont, () => {
      cont.remove();
      const box = el('div', { class: 'confirm' });
      box.appendChild(el('p', {}, 'Are you sure? Only continue if someone you trust has told you this website is safe.'));
      const yes = el('button', { type: 'button' }, 'Yes, continue to the site');
      const no = el('button', { type: 'button' }, 'No, take me to safety');
      onUserClick(yes, async () => {
        await chrome.runtime.sendMessage({ type: 'proceedAnyway' });
        state.locked = false;
        removeOverlay();
      });
      onUserClick(no, () => chrome.runtime.sendMessage({ type: 'goToSafety' }));
      box.append(yes, no);
      card.appendChild(box);
      no.focus();
    });
    card.appendChild(cont);

    backdrop.appendChild(card);
    root.appendChild(backdrop);
    document.documentElement.appendChild(host);
    state.overlay = host;
    if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
    safe.focus();
  }

  function removeOverlay() {
    state.overlay?.remove();
    state.overlay = null;
  }

  function showChecking() {
    if (state.checking || state.overlay) return;
    const host = el('div', { 'data-granny-protect-checking': '' });
    const root = host.attachShadow({ mode: 'closed' });
    root.appendChild(el('style', {}, STYLE));
    root.appendChild(el('div', { class: 'checking', role: 'status' }, 'Checking this website\u2026'));
    document.documentElement.appendChild(host);
    state.checking = host;
  }

  function removeChecking() {
    state.checking?.remove();
    state.checking = null;
  }

  // -------------------------------------------------------------------------

  analyze();
  observer.observe(document.documentElement, { childList: true, subtree: true });
})();
