// Page Pilot page helper.
// Injected ON DEMAND with chrome.scripting only after the user has granted access to the page.
// It is never declared as a content script for all sites.
//
// Privacy rule: this file never returns the value of any form field, and it skips / redacts anything
// that looks like a password, payment card, ID number, one-time code, bank detail or secret key.
(() => {
  if (window.__pmAgent) return;

  // ---------- sensitive data detection ----------
  const SENSITIVE_RE = /pass(word|code|phrase)?|pwd|\bpin\b|cvv|cvc|\bcsc\b|card.?(num|no\b)|cc.?num|credit.?card|debit.?card|security.?code|\bssn\b|social.?security|tax.?id|national.?id|passport|\botp\b|one.?time|2fa|mfa|verification.?code|auth.?code|\biban\b|routing|account.?(num|no\b)|api.?key|secret|token|private.?key|seed.?phrase|recovery/i;
  const SENSITIVE_AC = /^(cc-|current-password|new-password|one-time-code)/i;
  const PRIVATE_ZONE = '[data-sensitive],[data-private]';
  const RISKY_RE = /\b(submit|send|post|publish|reply|buy|purchase|order|checkout|check out|pay|donate|subscribe|delete|remove|discard|unsubscribe|cancel|confirm|transfer|book|reserve|sign out|log ?out|create account|sign up|register)\b/i;

  const FIELD_SEL = 'input:not([type=hidden]):not([type=submit]):not([type=button]):not([type=reset]):not([type=image]),textarea,select,[contenteditable="true"],[contenteditable=""]';
  const CLICKABLE = 'a[href],button,[role=button],[role=link],[role=tab],[role=menuitem],[role=option],[role=checkbox],[role=switch],input[type=submit],input[type=button],input[type=reset],input[type=checkbox],input[type=radio],summary,[onclick],[tabindex]:not([tabindex="-1"])';
  const SKIP_TAGS = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEMPLATE', 'SVG', 'CANVAS', 'IFRAME', 'INPUT', 'TEXTAREA', 'SELECT', 'OPTION']);

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const norm = (s) => String(s || '').replace(/\s+/g, ' ').trim();
  const lc = (s) => norm(s).toLowerCase();
  const inner = (el) => (el ? (el.innerText != null ? el.innerText : el.textContent) : '');

  function visible(el) {
    if (!el || !el.isConnected) return false;
    const r = el.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) return false;
    const cs = getComputedStyle(el);
    return cs.visibility !== 'hidden' && cs.display !== 'none' && parseFloat(cs.opacity || '1') > 0.05;
  }

  function labelParts(el) {
    const parts = [];
    if (el.labels) for (const l of el.labels) parts.push(inner(l));
    const wrap = el.closest && el.closest('label');
    if (wrap && !(el.labels && [...el.labels].includes(wrap))) parts.push(inner(wrap));
    const aria = el.getAttribute('aria-label');
    if (aria) parts.push(aria);
    const by = el.getAttribute('aria-labelledby');
    if (by) by.split(/\s+/).forEach((id) => { const n = document.getElementById(id); if (n) parts.push(inner(n)); });
    if (el.placeholder) parts.push(el.placeholder);
    if (el.title) parts.push(el.title);
    if (el.name) parts.push(el.name);
    if (el.id) parts.push(el.id);
    return parts.map(norm).filter(Boolean);
  }
  const labelOf = (el) => labelParts(el).join(' ');
  const niceLabel = (el) => (labelParts(el)[0] || el.tagName.toLowerCase()).slice(0, 60);

  function isSensitiveField(el) {
    if (!el || !el.tagName) return false;
    if (el.closest(PRIVATE_ZONE)) return true;
    if ((el.getAttribute('type') || '').toLowerCase() === 'password') return true;
    const ac = el.getAttribute('autocomplete') || '';
    if (ac.split(/\s+/).some((t) => SENSITIVE_AC.test(t))) return true;
    return SENSITIVE_RE.test(labelOf(el));
  }

  function luhn(d) {
    let s = 0, alt = false;
    for (let i = d.length - 1; i >= 0; i--) {
      let n = +d[i];
      if (alt) { n *= 2; if (n > 9) n -= 9; }
      s += n; alt = !alt;
    }
    return s % 10 === 0;
  }

  // Redacts sensitive-looking values in any text we return to the panel.
  function redact(input) {
    let n = 0;
    let t = String(input || '');
    t = t.replace(/\b\d(?:[ -]?\d){12,18}\b/g, (m) => (luhn(m.replace(/\D/g, '')) ? (n++, '[card number hidden]') : m));
    t = t.replace(/\b\d{3}-\d{2}-\d{4}\b/g, () => (n++, '[ID number hidden]'));
    t = t.replace(/\b((?:password|passcode|pin|otp|one-time code|verification code|security code|api[ _-]?key|secret|token)\s*(?:is)?\s*[:=]?\s+)(\S+)/gi, (m, p) => (n++, p + '[hidden]'));
    t = t.replace(/\b(?:sk|pk|rk|ghp|gho|xox[abpr])[-_][A-Za-z0-9_\-]{12,}/g, () => (n++, '[secret key hidden]'));
    t = t.replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/g, () => (n++, '[token hidden]'));
    return { text: t, count: n };
  }

  function textOf(el) {
    if (el.tagName === 'INPUT') return norm(el.value || el.getAttribute('aria-label') || ''); // only buttons reach here
    return norm(inner(el) || el.getAttribute('aria-label') || el.title || el.alt || '');
  }

  function describe(el) {
    const role = el.getAttribute('role') || el.tagName.toLowerCase();
    const t = redact(textOf(el) || niceLabel(el)).text.slice(0, 40);
    return t ? `${role} “${t}”` : role;
  }

  function flash(el) {
    const prev = el.style.outline, prevOff = el.style.outlineOffset;
    el.style.outline = '3px solid #5b4cff';
    el.style.outlineOffset = '2px';
    setTimeout(() => { el.style.outline = prev; el.style.outlineOffset = prevOff; }, 1800);
  }

  function score(label, q) {
    const a = lc(label), b = lc(q);
    if (!a || !b) return 0;
    if (a === b) return 100;
    if (a.startsWith(b)) return 80 - Math.min(30, a.length - b.length);
    if (a.includes(b)) return 60 - Math.min(30, a.length - b.length);
    const words = b.split(' ').filter(Boolean);
    const hit = words.filter((w) => a.includes(w)).length;
    return hit === words.length ? 40 : (25 * hit) / words.length;
  }

  function best(selector, q, labeler) {
    let top = null, topS = 0;
    for (const e of document.querySelectorAll(selector)) {
      if (!visible(e)) continue;
      const s = score(labeler(e), q);
      if (s > topS) { top = e; topS = s; }
    }
    return topS >= 20 ? top : null;
  }

  // Dynamic pages / SPAs: poll for a short time instead of failing immediately.
  async function waitFor(fn, ms = 3000) {
    const end = Date.now() + ms;
    let r = fn();
    while (!r && Date.now() < end) { await sleep(150); r = fn(); }
    return r;
  }

  function pageText(limit) {
    const out = [];
    let len = 0;
    const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    while (w.nextNode() && len < limit) {
      const n = w.currentNode, p = n.parentElement;
      if (!p || SKIP_TAGS.has(p.tagName) || !n.nodeValue.trim()) continue;
      if (p.closest(PRIVATE_ZONE)) continue;
      if (!visible(p)) continue; // hidden text (a common prompt-injection trick) is ignored
      const s = norm(n.nodeValue);
      out.push(s);
      len += s.length + 1;
    }
    return out.join(' ').slice(0, limit);
  }

  function hasValue(f) {
    if (f.type === 'checkbox' || f.type === 'radio') return f.checked;
    if (f.isContentEditable) return !!norm(f.textContent);
    return !!f.value;
  }

  const uniq = (a) => [...new Set(a)];

  // ---------- actions ----------
  let lastTarget = null;

  function read() {
    let total = 0;
    const red = (s) => { const r = redact(s); total += r.count; return r.text; };
    const headings = [...document.querySelectorAll('h1,h2,h3')].filter(visible).slice(0, 15).map((h) => red(textOf(h))).filter(Boolean);
    const buttons = uniq([...document.querySelectorAll('button,[role=button],input[type=submit],input[type=button]')]
      .filter(visible).map((b) => red(textOf(b) || niceLabel(b))).filter(Boolean)).slice(0, 20);
    const links = uniq([...document.querySelectorAll('a[href]')].filter(visible).map((a) => red(textOf(a))).filter(Boolean));
    const fields = [...document.querySelectorAll(FIELD_SEL)].filter(visible).slice(0, 30).map((f) => {
      const sensitive = isSensitiveField(f);
      return {
        label: red(niceLabel(f)),
        type: (f.getAttribute('type') || f.tagName).toLowerCase(),
        sensitive,
        filled: sensitive ? null : hasValue(f), // we report "filled or empty", never the value itself
      };
    });
    const text = red(pageText(3000));
    const title = red(document.title);
    const sens = fields.filter((f) => f.sensitive).length;
    return {
      ok: true, title, url: location.origin + location.pathname, // query strings may carry tokens: dropped
      headings, buttons, links: links.slice(0, 15), linkCount: links.length, fields, text, redactions: total,
      summary: `Read “${title || 'untitled'}”: ${headings.length} headings, ${fields.length} form fields` +
        (sens ? ` (${sens} sensitive, not read)` : '') + (total ? `, ${total} sensitive values hidden` : ''),
    };
  }

  async function find({ query }) {
    const ql = lc(query);
    const matches = [];
    const scan = () => {
      matches.length = 0;
      const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      while (w.nextNode()) {
        const n = w.currentNode, p = n.parentElement;
        if (!p || SKIP_TAGS.has(p.tagName)) continue;
        if (!lc(n.nodeValue).includes(ql)) continue;
        if (p.closest(PRIVATE_ZONE) || !visible(p)) continue;
        matches.push(p);
      }
      return matches.length;
    };
    await waitFor(scan, 2500);
    if (!matches.length) {
      return { ok: false, error: `Couldn’t find “${query}” on this page (waited 2.5 s for content to load). Try other words, or scroll first.` };
    }
    matches[0].scrollIntoView({ block: 'center', behavior: 'smooth' });
    flash(matches[0]);
    const snippets = matches.slice(0, 5).map((m) => redact(norm(inner(m)).slice(0, 160)).text);
    return { ok: true, count: matches.length, snippets, summary: `Found ${matches.length} match${matches.length > 1 ? 'es' : ''} for “${query}”, scrolled to the first` };
  }

  function scroller() {
    const se = document.scrollingElement || document.documentElement;
    if (se.scrollHeight > se.clientHeight + 10) return se;
    let bestEl = null, area = 0;
    for (const e of document.querySelectorAll('body *')) {
      if (e.scrollHeight > e.clientHeight + 50 && /(auto|scroll)/.test(getComputedStyle(e).overflowY)) {
        const a = e.clientWidth * e.clientHeight;
        if (a > area) { area = a; bestEl = e; }
      }
    }
    return bestEl || se;
  }

  async function scroll({ dir = 'down' }) {
    const s = scroller();
    const before = s.scrollTop, h = s.clientHeight;
    if (dir === 'down') s.scrollBy({ top: h * 0.8 });
    else if (dir === 'up') s.scrollBy({ top: -h * 0.8 });
    else if (dir === 'top') s.scrollTo({ top: 0 });
    else s.scrollTo({ top: s.scrollHeight });
    await sleep(400);
    const after = s.scrollTop;
    if (after === before && (dir === 'down' || dir === 'up')) {
      return { ok: true, summary: `Already at the ${dir === 'down' ? 'bottom' : 'top'} of the page` };
    }
    const pct = Math.round((100 * after) / Math.max(1, s.scrollHeight - h));
    return { ok: true, summary: `Scrolled ${dir}, now ${Math.min(100, pct)}% down the page` };
  }

  function riskOf(e) {
    const t = textOf(e) || labelOf(e);
    const m = t.match(RISKY_RE);
    if (m) return `have an external effect (“${m[0]}”)`;
    const form = e.form || e.closest('form');
    const isSubmit = (e.tagName === 'BUTTON' && (e.getAttribute('type') || 'submit') === 'submit' && form) ||
      (e.tagName === 'INPUT' && e.type === 'submit');
    return isSubmit ? 'submit a form' : null;
  }

  function coveredBy(e) {
    const r = e.getBoundingClientRect();
    const x = r.left + r.width / 2, y = r.top + r.height / 2;
    if (x < 0 || y < 0 || x > innerWidth || y > innerHeight) return null;
    const top = document.elementFromPoint(x, y);
    if (!top || e === top || e.contains(top) || top.contains(e)) return null;
    if (top.tagName === 'LABEL' && top.control === e) return null;
    return top;
  }

  const clickLabel = (el) => textOf(el) || labelOf(el);

  // Elements seen in an observation get a stable data-pp-id so the AI can target them exactly.
  function byId(id) {
    const safe = String(id).replace(/[^\w-]/g, '');
    return safe ? document.querySelector(`[data-pp-id="${safe}"]`) : null;
  }
  const goneMsg = (id) => `Element [${id}] is no longer on the page (the page changed). Use the newest observation.`;

  async function resolveClick({ target, id }) {
    const e = id != null ? byId(id) : await waitFor(() => best(CLICKABLE, target, clickLabel), 3000);
    if (!e || !visible(e)) {
      return { ok: false, error: id != null ? goneMsg(id) : `Couldn’t find a button or link matching “${target}”. The page may have changed. Try “read page” to see what’s available.` };
    }
    lastTarget = { el: e, query: id != null ? '#' + id : target };
    const risk = riskOf(e);
    return { ok: true, text: redact(clickLabel(e)).text.slice(0, 80), risky: !!risk, reason: risk };
  }

  async function click({ target, id, confirmedText }) {
    const key = id != null ? '#' + id : target;
    let e = lastTarget && lastTarget.query === key && visible(lastTarget.el) ? lastTarget.el : null;
    if (!e) { // element was re-rendered (SPA) -> locate it again
      const r = await resolveClick({ target, id });
      if (!r.ok) return r;
      e = lastTarget.el;
    }
    const text = redact(clickLabel(e)).text.slice(0, 80);
    if (riskOf(e) && confirmedText !== text) {
      return { ok: false, error: 'The button changed after you confirmed it. Retry so you can review it again.' };
    }
    e.scrollIntoView({ block: 'center' });
    await sleep(150);
    const cover = coveredBy(e);
    if (cover) return { ok: false, error: `“${text}” is covered by another element (${describe(cover)}), probably a pop-up. Try “close popup” first.` };
    flash(e);
    if (e.focus) e.focus();
    e.click();
    return { ok: true, summary: `Clicked “${text}”` };
  }

  function setValue(el, v) {
    const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype
      : el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, v); // works with React-controlled inputs
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }

  async function fill({ field, value, id }) {
    const e = id != null ? byId(id) : await waitFor(() => best(FIELD_SEL, field, labelOf), 3000);
    if (!e) return { ok: false, error: id != null ? goneMsg(id) : `Couldn’t find a field matching “${field}”.` };
    if (isSensitiveField(e)) {
      return { ok: false, refused: true, error: `“${niceLabel(e)}” is a sensitive field (password, payment, ID or code). Page Pilot never fills or reads these, so please type it yourself.` };
    }
    if (e.disabled || e.readOnly) return { ok: false, error: `“${niceLabel(e)}” is disabled or read-only.` };
    e.scrollIntoView({ block: 'center' });
    e.focus();
    let verify = true;
    if (e.isContentEditable) {
      e.textContent = value;
      e.dispatchEvent(new InputEvent('input', { bubbles: true }));
    } else if (e.type === 'checkbox' || e.type === 'radio') {
      const want = /^(yes|true|on|check(ed)?|1|tick|y)$/i.test(value);
      if (e.checked !== want) e.click();
      verify = e.checked === want;
    } else if (e.tagName === 'SELECT') {
      const opts = [...e.options].map((o) => ({ o, s: score(o.text, value) })).sort((a, b) => b.s - a.s);
      if (!opts.length || opts[0].s < 20) {
        return { ok: false, error: `No option like “${value}” in “${niceLabel(e)}”. Options: ${[...e.options].map((o) => o.text).slice(0, 8).join(', ')}` };
      }
      setValue(e, opts[0].o.value);
      verify = e.value === opts[0].o.value;
    } else {
      setValue(e, value);
      verify = e.value === value;
    }
    e.dispatchEvent(new Event('blur', { bubbles: true }));
    flash(e);
    if (!verify) return { ok: false, error: `Typed into “${niceLabel(e)}” but the page changed the value. It may need a specific format.` };
    return { ok: true, summary: `Filled “${niceLabel(e)}” and checked the value` };
  }

  async function dismiss() {
    const sel = '[role=dialog],[role=alertdialog],dialog[open],[aria-modal=true],[class*=modal],[class*=popup],[class*=cookie],[id*=cookie],[class*=consent],[id*=consent],[class*=banner],[class*=overlay]';
    const dialogs = [...document.querySelectorAll(sel)].filter(visible);
    const passes = [
      /^(×|x|✕|✖|close|dismiss|no,? thanks|not now|maybe later|reject( all)?|decline|skip)$/i,
      /^(accept( all)?|got it|ok(ay)?|i agree|agree|continue|allow( all)?)$/i,
    ];
    for (const re of passes) {
      for (const d of dialogs) {
        const btn = [...d.querySelectorAll('button,[role=button],a,input[type=button]')].filter(visible)
          .find((b) => re.test(textOf(b)) || re.test(b.getAttribute('aria-label') || '') || (re === passes[0] && /close|dismiss/i.test(b.getAttribute('aria-label') || '')));
        if (btn) {
          const t = textOf(btn) || btn.getAttribute('aria-label');
          btn.click();
          await sleep(350);
          return { ok: true, summary: `Closed a pop-up by clicking “${t}”` };
        }
      }
    }
    document.activeElement && document.activeElement.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    return dialogs.length
      ? { ok: false, error: 'I found a pop-up but no obvious close button. Tell me which button to click.' }
      : { ok: true, summary: 'No pop-up found on the page' };
  }

  // Compact, privacy-filtered snapshot for the AI planner.
  function observe() {
    let total = 0;
    const red = (s) => { const r = redact(s); total += r.count; return r.text; };
    window.__pmSeq = window.__pmSeq || 0;
    const items = [];
    for (const e of document.querySelectorAll(CLICKABLE + ',' + FIELD_SEL)) {
      if (items.length >= 150) break;
      if (!visible(e)) continue;
      const isField = e.matches(FIELD_SEL);
      const it = { kind: isField ? 'field' : (e.tagName === 'A' ? 'link' : 'button') };
      if (isField) {
        it.type = (e.getAttribute('type') || e.tagName).toLowerCase();
        it.label = red(niceLabel(e));
        it.sensitive = isSensitiveField(e);
        if (!it.sensitive) {
          it.filled = hasValue(e); // never the value itself
          if (e.tagName === 'SELECT') it.options = [...e.options].slice(0, 12).map((o) => red(norm(o.text))).filter(Boolean);
        }
      } else {
        it.label = red(clickLabel(e)).slice(0, 80);
        if (!it.label) continue;
        if (riskOf(e)) it.risky = true;
      }
      let id = e.getAttribute('data-pp-id');
      if (!id) { id = String(++window.__pmSeq); e.setAttribute('data-pp-id', id); }
      it.id = id;
      const r = e.getBoundingClientRect();
      it.inView = r.bottom > 0 && r.top < (window.innerHeight || 800);
      items.push(it);
    }
    const s = scroller();
    const scrollPct = Math.min(100, Math.round((100 * s.scrollTop) / Math.max(1, s.scrollHeight - s.clientHeight)));
    return {
      ok: true,
      title: red(document.title),
      url: location.origin + location.pathname,
      headings: [...document.querySelectorAll('h1,h2,h3')].filter(visible).slice(0, 12).map((x) => red(textOf(x))).filter(Boolean),
      items,
      text: red(pageText(2000)),
      dialog: [...document.querySelectorAll('[role=dialog],[role=alertdialog],[aria-modal=true],dialog[open]')].some(visible),
      scroll: scrollPct,
      redactions: total,
    };
  }

  const actions = { ping: () => ({ ok: true }), read, observe, find, scroll, resolveClick, click, fill, dismiss };

  async function run(action, params) {
    try {
      const f = actions[action];
      if (!f) return { ok: false, error: `Unknown action ${action}` };
      return await f(params || {});
    } catch (e) {
      return { ok: false, error: String((e && e.message) || e) };
    }
  }

  window.__pmAgent = { run };
})();
