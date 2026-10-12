// Content script (classic script, runs at document_start in every top-level
// http(s) page).
//  1. Destination gate: asks the background whether this page should be
//     showing at all; if it needs review or is blocked, the page is hidden and
//     the tab goes to the gate page.
//  2. Link gate: screens the page's links in the background, and holds clicks
//     (same tab, new tab, Ctrl/middle click, keyboard Enter) on links that
//     aren't known to be safe until the background has decided.
//  3. Page screening: once the DOM is ready, sends a feature summary of the
//     page for a verdict. If the page is risky, shows a warning and locks
//     password / card / gift-card fields until the user chooses to continue.
//  4. Re-checks when the page adds sensitive fields or new links later.

(() => {
  if (window.top !== window || window.__grannyProtect) return;
  window.__grannyProtect = true;

  const MAX_TEXT = 6000;
  const MAX_RECHECKS = 5;

  const GIFT_RE = /gift.?card|claim.?code|redemption|card.?pin|scratch/i;
  const CARD_RE = /card.?num|cc.?num|credit.?card|debit.?card|\bcvv\b|\bcvc\b|security.?code|expir/i;
  const SSN_RE = /\bssn\b|social.?security/i;
  const OTP_RE = /one.?time|\botp\b|verification.?code|2fa|auth.?code|sms.?code/i;
  const PHONE_RE = /(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b/g;

  const MAX_LINKS_PER_BATCH = 300;

  let state = {
    gated: false,        // destination gate sent this tab to the gate page
    stayed: false,       // user chose to stay on a policy-blocked page (fields stay locked)
    verdict: null,       // last verdict from the background
    text: null,          // plain-language strings for it
    locked: false,       // sensitive inputs blocked until the user decides
    overlay: null,
    fullscreen: false,
    rechecks: 0,
  };

  function send(msg) {
    try {
      return chrome.runtime.sendMessage(msg).catch(() => null);
    } catch {
      return Promise.resolve(null); // extension reloaded
    }
  }

  // -------------------------------------------------------------------------
  // 1. Destination gate

  send({ type: 'checkPage' }).then((res) => {
    if (!res?.gated) return;
    state.gated = true;
    document.documentElement?.style.setProperty('display', 'none', 'important');
    window.stop();
  });

  // -------------------------------------------------------------------------
  // 2. Link gate

  const decisions = new Map(); // link URL (without #fragment) -> allow | needs_review | block
  const pendingScreen = new Set();

  function linkKey(u) {
    return u.origin + u.pathname + u.search;
  }

  function linkUrl(a) {
    try {
      const u = new URL(a.href, location.href);
      return u.protocol === 'http:' || u.protocol === 'https:' ? u : null;
    } catch {
      return null;
    }
  }

  /** Queue the links under `root` that haven't been screened yet. */
  function collectLinks(root) {
    const anchors = root.matches?.('a[href], area[href]') ? [root] : [];
    if (root.querySelectorAll) anchors.push(...root.querySelectorAll('a[href], area[href]'));
    for (const a of anchors) {
      const u = linkUrl(a);
      if (!u) continue;
      const key = linkKey(u);
      if (!decisions.has(key)) pendingScreen.add(key);
    }
    scheduleScreen();
  }

  let screenTimer;
  function scheduleScreen() {
    if (!pendingScreen.size) return;
    clearTimeout(screenTimer);
    screenTimer = setTimeout(screenLinks, 150);
  }

  async function screenLinks() {
    const urls = [...pendingScreen].slice(0, MAX_LINKS_PER_BATCH);
    for (const u of urls) pendingScreen.delete(u);
    const res = await send({ type: 'screenUrls', urls });
    for (const [url, action] of Object.entries(res?.decisions || {})) decisions.set(url, action);
    scheduleScreen();
  }

  /** How the user asked to open the link. */
  function dispositionFor(e, a) {
    if (e.button === 1 || e.ctrlKey || e.metaKey) return e.shiftKey ? 'tab' : 'background';
    if (e.shiftKey) return 'window';
    const target = (a.target || document.querySelector('base[target]')?.target || '').toLowerCase();
    return target && !['_self', '_top', '_parent'].includes(target) ? 'tab' : 'same';
  }

  async function navigateChecked(url, disposition) {
    const res = await send({ type: 'checkNavigation', url, disposition });
    // If the background is unavailable, fall back to a plain navigation; the
    // destination gate still runs on the new page.
    if (!res || (res.allow && !res.handled)) {
      if (disposition === 'same') location.assign(url);
      else window.open(url, '_blank', 'noopener');
    }
  }

  // Bubble phase on window: runs after the page's own handlers, so links the
  // page handles itself (single-page-app routing, pop-ups) are left alone.
  function onLinkActivate(e) {
    if (e.defaultPrevented) return;
    if (e.type === 'click' && e.button !== 0) return;
    if (e.type === 'auxclick' && e.button !== 1) return;
    const a = e.composedPath().find((n) => n instanceof HTMLAnchorElement || n instanceof HTMLAreaElement);
    if (!a || a.hasAttribute('download')) return;
    const u = linkUrl(a);
    if (!u) return;
    // Same-document fragment links ("#section") don't navigate.
    if (linkKey(u) === linkKey(new URL(location.href)) && u.hash) return;
    if (decisions.get(linkKey(u)) === 'allow') return; // known safe: don't interfere
    e.preventDefault();
    navigateChecked(u.href, dispositionFor(e, a));
  }

  window.addEventListener('click', onLinkActivate);
  window.addEventListener('auxclick', onLinkActivate);

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

  // Inputs that have ever been password boxes: "show password" buttons switch
  // them to type=text, and they must stay protected.
  const passwordFields = new WeakSet();

  /** Classify an input as a sensitive kind, or null. */
  function sensitiveKind(el) {
    if (!(el instanceof HTMLInputElement) || el.type === 'hidden') return null;
    if (el.type === 'password') passwordFields.add(el);
    if (passwordFields.has(el)) return 'password';
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
      const hasPassword = [...form.elements].some((el) => sensitiveKind(el) === 'password');
      if (!hasPassword) continue;
      for (const action of formActions(form)) {
        forms.push({ actionHost: action?.hostname || location.hostname, actionProtocol: action?.protocol || location.protocol, hasPassword });
      }
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
      passwordInputs: document.querySelectorAll('input[type=password]').length,
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

  async function analyze() {
    if (state.gated) return;
    const res = await send({ type: 'analyzePage', features: extractFeatures() });
    if (!res || state.gated) return;
    state.verdict = res.verdict;
    state.text = res.text;
    const risky = res.verdict.action !== 'allow' && !res.verdict.overridden;
    if (risky) {
      state.locked = true;
      if (!(res.verdict.policy && state.stayed)) showOverlay();
    } else {
      state.locked = false;
      removeOverlay();
    }
  }

  // -------------------------------------------------------------------------
  // Input guard: while locked, sensitive fields can't be focused or typed in.

  function formAction(form, submitter) {
    try {
      const action = submitter?.hasAttribute('formaction')
        ? submitter.formAction : form.getAttribute('action') || location.href;
      return new URL(action, document.baseURI);
    } catch {
      return null;
    }
  }

  function formActions(form) {
    const submitters = [...document.querySelectorAll('button[formaction], input[formaction]')]
      .filter((el) => el.form === form && ['submit', 'image'].includes(el.type));
    return [formAction(form), ...submitters.map((el) => formAction(form, el))];
  }

  // Enterprise policy, enforced here too so it doesn't wait on the
  // background: no password into an http page or an http form target.
  function violatesPasswordPolicy(el, submitter) {
    if (sensitiveKind(el) !== 'password') return false;
    return location.protocol === 'http:' || (el.form &&
      (formAction(el.form, submitter)?.protocol === 'http:' ||
        formActions(el.form).some((action) => action?.protocol === 'http:')));
  }

  function blocked(el, submitter) {
    if (violatesPasswordPolicy(el, submitter)) {
      // Make sure the verdict (and its overlay text) reflects the policy.
      if (!state.verdict?.policy) analyze();
      state.locked = true;
      return true;
    }
    return state.locked && !!sensitiveKind(el);
  }

  function onFocusIn(e) {
    if (!blocked(e.target)) return;
    e.target.blur();
    showOverlay();
  }

  function onKeyDown(e) {
    if (!blocked(e.target)) return;
    e.preventDefault();
    e.stopImmediatePropagation();
    showOverlay();
  }

  function onSubmit(e) {
    const form = e.target;
    if (!(form instanceof HTMLFormElement)) return;
    if ([...form.elements].some((el) => blocked(el, e.submitter))) {
      e.preventDefault();
      e.stopImmediatePropagation();
      showOverlay();
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

  // Re-check when a sensitive field appears later (single-page apps, pop-ups),
  // and screen links that are added or change destination.
  let recheckTimer;
  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      if (m.type === 'attributes') collectLinks(m.target);
      else for (const n of m.addedNodes) if (n.nodeType === 1) collectLinks(n);
    }
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
      class: `backdrop ${state.verdict.action === 'block' ? 'block' : 'warn'}`,
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

    if (state.verdict.policy) {
      // Enterprise policy: no override. The user may read the page, but the
      // password boxes stay locked.
      const stay = el('button', { class: 'continue', type: 'button' }, 'Stay on this page (password boxes stay locked)');
      onUserClick(stay, () => {
        state.stayed = true;
        removeOverlay();
      });
      card.appendChild(stay);
    } else {
      appendContinue(card);
    }

    backdrop.appendChild(card);
    root.appendChild(backdrop);
    document.documentElement.appendChild(host);
    state.overlay = host;
    if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
    safe.focus();
  }

  function appendContinue(card) {
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
  }

  function removeOverlay() {
    state.overlay?.remove();
    state.overlay = null;
  }

  // -------------------------------------------------------------------------

  function onDomReady() {
    if (state.gated) return;
    collectLinks(document);
    analyze();
    observer.observe(document.documentElement, {
      childList: true, subtree: true, attributes: true, attributeFilter: ['href'],
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', onDomReady, { once: true });
  } else {
    onDomReady();
  }
})();
