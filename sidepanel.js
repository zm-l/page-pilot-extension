'use strict';
// Page Pilot side panel: permission flow, planning, step execution, confirmation and recovery.

const $ = (s) => document.querySelector(s);
const logEl = $('#log');
const HOSTS_ALL = ['http://*/*', 'https://*/*'];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

class CancelError extends Error { constructor(m = 'Stopped') { super(m); } }
class RefusedError extends Error {}

// ---------------------------------------------------------------- sensitive data policy
const SENSITIVE_TOPIC = /\b(pass(word|code|phrase)s?|pwd|pins?|pin codes?|cvv|cvc|credit ?cards?|card numbers?|debit cards?|security codes?|ssn|social security( number)?|tax id|passport( numbers?)?|otp|one[- ]time (codes?|passwords?)|2fa|mfa|verification codes?|bank (accounts?|details)|account numbers?|routing numbers?|iban|api ?keys?|secrets?|tokens?|private keys?|seed phrases?|recovery (phrases?|codes?))\b/i;
const SENSITIVE_VERB = /\b(read|show|get|copy|extract|tell|reveal|what|display|fill|type|enter|paste|send|export|grab|list|give|save|remember|autofill|steal|dump|scrape|collect)\b/i;
const REFUSAL = 'I can’t do that. Page Pilot never reads, copies or fills sensitive information: passwords, payment card numbers, ID numbers, one-time codes, bank details or secret keys. Please enter these yourself on the page. I’ll leave those fields alone.';

function luhn(d) {
  let s = 0, alt = false;
  for (let i = d.length - 1; i >= 0; i--) { let n = +d[i]; if (alt) { n *= 2; if (n > 9) n -= 9; } s += n; alt = !alt; }
  return s % 10 === 0;
}
function looksSensitiveValue(v) {
  const d = String(v).replace(/[ -]/g, '');
  return (/^\d{13,19}$/.test(d) && luhn(d)) || /^\d{3}-\d{2}-\d{4}$/.test(String(v).trim()) || /^(sk|pk|ghp|xox[abpr])[-_]\w{12,}/.test(String(v).trim());
}
function sensitiveIntent(text) {
  return SENSITIVE_TOPIC.test(text) && SENSITIVE_VERB.test(text) ? REFUSAL : null;
}

// ---------------------------------------------------------------- DOM helpers
function h(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const k of kids.flat(Infinity)) {
    if (k == null || k === false) continue;
    e.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return e;
}
const scrollLog = () => { logEl.scrollTop = logEl.scrollHeight; };
function add(node) { logEl.append(node); scrollLog(); return node; }
function say(role, ...kids) { return add(h('div', { class: 'msg ' + role }, ...kids)); }
const hostOf = (pat) => (pat ? pat.replace(/^https?:\/\//, '').replace(/\/\*$/, '') : '');

// ---------------------------------------------------------------- choice cards
// `request` callbacks are invoked synchronously inside the click handler so that
// chrome.permissions.request() keeps its required user gesture.
let pending = null;
function ask({ title, body, choices, tone = 'info', kind = 'generic' }) {
  if (pending) pending.resolve({ id: 'cancel' });
  return new Promise((resolve) => {
    const actions = h('div', { class: 'card-actions' });
    const card = h('div', { class: 'card ' + tone }, h('div', { class: 'card-title' }, title),
      body ? h('div', { class: 'card-body' }, body) : null, actions);
    let done = false;
    const finish = (r, btn) => {
      if (done) return;
      done = true;
      if (pending && pending.card === card) pending = null;
      card.classList.add('resolved');
      actions.querySelectorAll('button').forEach((b) => { b.disabled = true; if (b === btn) b.classList.add('chosen'); });
      resolve(r);
    };
    for (const c of choices) {
      const btn = h('button', { class: c.kind || '' }, c.label);
      btn.addEventListener('click', () => {
        if (!c.request) return finish({ id: c.id, ok: true }, btn);
        let p;
        try { p = c.request(); } catch { return finish({ id: c.id, ok: false }, btn); }
        Promise.resolve(p).then((ok) => finish({ id: c.id, ok: !!ok }, btn), () => finish({ id: c.id, ok: false }, btn));
      });
      actions.append(btn);
    }
    pending = { card, kind, resolve: (r) => finish(r, null) };
    add(card);
  });
}

// ---------------------------------------------------------------- permissions
let taskGrants = new Set(); // site grants that last only for the current task
const knownUrls = new Map(); // tabId -> URL for tabs we opened (lets us offer per-site access without the "tabs" permission)

async function getTab() {
  const [t] = await chrome.tabs.query({ active: true, currentWindow: true });
  return t;
}
function originPattern(url) {
  try {
    const u = new URL(url);
    if (!/^https?:$/.test(u.protocol)) return null;
    return `${u.protocol}//${u.hostname}/*`;
  } catch { return null; }
}
async function canScript(tabId) {
  try { await chrome.scripting.executeScript({ target: { tabId }, func: () => true }); return true; } catch { return false; }
}
// Levels: all | site | task | once (activeTab) | none | restricted
async function accessLevel(tab) {
  if (!tab) return { level: 'none' };
  const url = tab.url || knownUrls.get(tab.id);
  const pat = url ? originPattern(url) : null;
  if (tab.url && !pat) return { level: 'restricted' };
  if (await chrome.permissions.contains({ origins: HOSTS_ALL })) return { level: (await canScript(tab.id)) ? 'all' : 'restricted', pat };
  if (pat && await chrome.permissions.contains({ origins: [pat] })) return { level: taskGrants.has(pat) ? 'task' : 'site', pat };
  if (await canScript(tab.id)) return { level: 'once', pat }; // activeTab from a toolbar click
  return { level: 'none', pat };
}

async function ensurePageAccess() {
  for (;;) {
    const tab = await getTab();
    const a = await accessLevel(tab);
    if (['all', 'site', 'task', 'once'].includes(a.level)) return tab;
    if (a.level === 'restricted') throw new Error('Chrome doesn’t let extensions work on this page (for example chrome:// pages or the Web Store).');
    const host = hostOf(a.pat);
    const choices = [];
    if (a.pat) {
      choices.push({ id: 'task', label: `Allow on ${host} for this task`, kind: 'primary', request: () => chrome.permissions.request({ origins: [a.pat] }) });
      choices.push({ id: 'site', label: `Always allow on ${host}`, request: () => chrome.permissions.request({ origins: [a.pat] }) });
    }
    choices.push({ id: 'all', label: 'Allow on all sites', request: () => chrome.permissions.request({ origins: HOSTS_ALL }) });
    choices.push({ id: 'cancel', label: 'Cancel' });
    const r = await ask({
      kind: 'perm', tone: 'info',
      title: host ? `Allow Page Pilot to use ${host}?` : 'Page Pilot needs access to this tab',
      body: h('div', {},
        h('p', {}, 'To do this step I need to read and act on this page. Sensitive fields such as passwords and card numbers are never read.'),
        h('p', {}, h('b', {}, 'Just this once: '), 'click the Page Pilot icon in the toolbar (or press Alt+Shift+P). Access ends when the tab navigates.'),
        a.pat ? null : h('p', { class: 'muted' }, 'I can’t see this tab’s address yet, so per-site options appear after you allow it once.')),
      choices,
    });
    if (r.id === 'cancel') throw new CancelError();
    if (r.id === 'toolbar') { say('system', 'Access granted for this tab via the toolbar icon.'); continue; }
    if (!r.ok) { say('system', 'Permission wasn’t granted.'); throw new CancelError(); }
    if (r.id === 'task') taskGrants.add(a.pat);
    renderAccess();
  }
}

async function ensureTabs(reason) {
  if (await chrome.permissions.contains({ permissions: ['tabs'] })) return;
  const r = await ask({
    kind: 'perm',
    title: 'Allow Page Pilot to see your tabs?',
    body: h('div', {}, h('p', {}, `To ${reason}, I need the titles and addresses of your open tabs. Chrome calls this “Read your browsing history”.`),
      h('p', { class: 'muted' }, 'Optional, and you can revoke it under Permissions.')),
    choices: [
      { id: 'ok', label: 'Allow tab access', kind: 'primary', request: () => chrome.permissions.request({ permissions: ['tabs'] }) },
      { id: 'cancel', label: 'Cancel' },
    ],
  });
  if (r.id !== 'ok' || !r.ok) throw new CancelError();
}

async function releaseTaskGrants() {
  if (!taskGrants.size) return;
  const origins = [...taskGrants];
  taskGrants = new Set();
  try { await chrome.permissions.remove({ origins }); } catch {}
  say('system', `Task-only access to ${origins.map(hostOf).join(', ')} has been removed.`);
}

// ---------------------------------------------------------------- access bar + settings
let renderTimer = null;
function renderAccess() { clearTimeout(renderTimer); renderTimer = setTimeout(doRenderAccess, 120); }
async function doRenderAccess() {
  const bar = $('#accessBar');
  const tab = await getTab();
  const a = await accessLevel(tab);
  const host = hostOf(a.pat);
  const text = {
    all: 'Access: all websites',
    site: `Access: always allowed on ${host}`,
    task: `Access: ${host}, this task only`,
    once: `Access: this tab only, until it navigates${host ? ` (${host})` : ''}`,
    none: 'No access to this tab',
    restricted: 'Chrome doesn’t allow extensions on this page',
  }[a.level];
  bar.className = 'access-bar ' + a.level;
  bar.replaceChildren(h('span', { class: 'dot' }), h('span', {}, text));
  if (a.level === 'once' && a.pat) {
    bar.append(h('button', { class: 'link', onclick: () => chrome.permissions.request({ origins: [a.pat] }) }, `Always allow ${host}`));
  }
  if (a.level === 'site') bar.append(h('button', { class: 'link', onclick: () => chrome.permissions.remove({ origins: [a.pat] }) }, 'Remove'));
  if (a.level === 'none') bar.append(h('span', { class: 'hint' }, '· click the toolbar icon to allow once'));
}

async function renderSettings() {
  const s = $('#settings');
  const all = await chrome.permissions.getAll();
  const allSites = await chrome.permissions.contains({ origins: HOSTS_ALL });
  const tabs = (all.permissions || []).includes('tabs');
  const sites = (all.origins || []).filter((o) => !HOSTS_ALL.includes(o) && o !== AI_ORIGIN);
  s.replaceChildren(
    ...(await aiSettingsNodes()),
    h('h3', {}, 'Website access'),
    h('div', { class: 'opt' + (allSites ? '' : ' active') }, h('b', {}, 'Ask when needed (recommended)'),
      h('p', {}, 'I ask before touching a site. You choose: just once, for the task, or always for that site.')),
    h('div', { class: 'opt' + (allSites ? ' active' : '') }, h('b', {}, 'Allow on all websites'),
      h('p', {}, 'I never ask for site access. Sensitive data is still never read, and risky actions still need your OK.')),
    allSites
      ? h('button', { onclick: () => chrome.permissions.remove({ origins: HOSTS_ALL }) }, 'Switch to “Ask when needed”')
      : h('button', { class: 'primary', onclick: () => chrome.permissions.request({ origins: HOSTS_ALL }) }, 'Allow on all websites'),
    h('h3', {}, 'Sites you’ve allowed'),
    sites.length
      ? h('ul', { class: 'sites' }, sites.map((o) => h('li', {}, hostOf(o), ' ', h('button', { class: 'link', onclick: () => chrome.permissions.remove({ origins: [o] }) }, 'Remove'))))
      : h('p', { class: 'muted' }, allSites ? 'Covered by “all websites”.' : 'None yet.'),
    h('h3', {}, 'Tab access'),
    h('p', {}, 'Only needed to list tabs or switch tabs by title. Opening, closing and switching by number work without it.'),
    tabs
      ? h('button', { onclick: () => chrome.permissions.remove({ permissions: ['tabs'] }) }, 'Revoke tab access')
      : h('button', { onclick: () => chrome.permissions.request({ permissions: ['tabs'] }) }, 'Allow tab access'),
    h('h3', {}, 'Always on, whatever you allow'),
    h('ul', { class: 'rules' },
      h('li', {}, 'Never reads or fills passwords, card numbers, ID numbers, one-time codes, bank details or secret keys.'),
      h('li', {}, 'Form field values are never read, only whether a field is filled.'),
      h('li', {}, 'Hidden page text is ignored, and page content is never treated as instructions.'),
      h('li', {}, 'Submitting, sending, buying, deleting and closing tabs always ask first.')),
    h('button', { class: 'danger', onclick: () => chrome.permissions.remove({ origins: [...HOSTS_ALL, ...sites], permissions: ['tabs'] }) }, 'Revoke everything'),
  );
}

// ---------------------------------------------------------------- parsing
function parse(input) {
  return input.split(/\s*(?:;|\n|,?\s*\bthen\b|,?\s*\band then\b)\s*/i).map((s) => s.trim()).filter(Boolean).map(parseOne);
}
function parseOne(raw) {
  const s = raw.replace(/^(please|and)\s+/i, '').replace(/[.!]$/, '').trim();
  let m;
  const strip = (x) => x.replace(/^["'“”]+|["'“”]+$/g, '').trim();
  if (sensitiveIntent(s)) return { type: 'refuse', reason: REFUSAL, label: `“${s}” (refused: sensitive data)` };
  if (/^(help|\?|what can you do)/i.test(s)) return { type: 'help', label: 'Show help' };
  if (/^(read|summari[sz]e|describe|look at|what'?s on|what is on)/i.test(s)) return { type: 'page', action: 'read', label: 'Read this page (sensitive data filtered)' };
  if (/^(close|dismiss|hide)\s+(the\s+)?(pop-?up|dialog|modal|banner|cookie( banner| notice)?|overlay)/i.test(s)) return { type: 'page', action: 'dismiss', label: 'Close the pop-up' };
  if ((m = s.match(/^(?:find|search(?: for)?|look for|locate|where is)\s+(.+)$/i))) return { type: 'page', action: 'find', args: { query: strip(m[1]) }, label: `Find “${strip(m[1])}”` };
  if ((m = s.match(/^scroll(?:\s+(?:to\s+)?(?:the\s+)?(up|down|top|bottom))?/i))) { const dir = (m[1] || 'down').toLowerCase(); return { type: 'page', action: 'scroll', args: { dir }, label: `Scroll ${dir}` }; }
  if ((m = s.match(/^(?:fill(?: in)?|set)\s+(?:the\s+)?(.+?)\s+(?:field\s+)?(?:with|to|as)\s+(.+)$/i))) return fillStep(strip(m[1]), strip(m[2]));
  if ((m = s.match(/^(?:type|enter|write|put)\s+(.+?)\s+(?:in|into|in the|into the)\s+(?:the\s+)?(.+?)(?:\s+field|\s+box)?$/i))) return fillStep(strip(m[2]), strip(m[1]));
  if ((m = s.match(/^(?:click|press|tap|select|choose)\s+(?:on\s+)?(?:the\s+)?(.+?)(?:\s+(?:button|link|tab))?$/i))) return { type: 'page', action: 'click', args: { target: strip(m[1]) }, label: `Click “${strip(m[1])}”` };
  if (/^(list|show)\s+(all\s+)?(my\s+|open\s+)?tabs$/i.test(s)) return { type: 'tabs', action: 'list', label: 'List open tabs' };
  if (/^close\s+(this\s+|the\s+|current\s+)?tab$/i.test(s)) return { type: 'tabs', action: 'close', label: 'Close this tab' };
  if ((m = s.match(/^(?:switch|go|change)\s+to\s+(?:the\s+)?tab\s+(.+)$/i)) || (m = s.match(/^(?:switch|go)\s+to\s+(.+?)\s+tab$/i))) return { type: 'tabs', action: 'switch', args: { which: strip(m[1]) }, label: `Switch to tab “${strip(m[1])}”` };
  if ((m = s.match(/^(?:open|go to|navigate to|visit)\s+(?:a\s+new\s+tab\s+(?:with|for)\s+)?(\S+)$/i))) {
    let url = strip(m[1]);
    if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
    try { new URL(url); return { type: 'tabs', action: 'open', args: { url }, label: `Open ${new URL(url).hostname} in a new tab` }; } catch {}
  }
  return { type: 'unknown', text: s, label: `“${s}” (not understood)` };
}
function fillStep(field, value) {
  if (SENSITIVE_TOPIC.test(field) || looksSensitiveValue(value)) {
    return { type: 'refuse', reason: REFUSAL, label: `Fill “${field}” (refused: sensitive data)` };
  }
  return { type: 'page', action: 'fill', args: { field, value }, label: `Fill “${field}” with “${value}”` };
}

// ---------------------------------------------------------------- page calls
async function pageCall(action, args) {
  const tab = await ensurePageAccess();
  try {
    await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ['content.js'] });
    const [res] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: (a, p) => window.__pmAgent.run(a, p),
      args: [action, args || {}],
    });
    return { tab, result: (res && res.result) || { ok: false, error: 'No response from the page.' } };
  } catch (e) {
    throw new Error(`Couldn’t run on this page: ${e.message}. It may be reloading. Retry in a moment.`);
  }
}
async function waitSettled(tabId) {
  await sleep(500);
  const end = Date.now() + 10000;
  while (Date.now() < end) {
    try { const t = await chrome.tabs.get(tabId); if (t.status === 'complete') break; } catch { return; }
    await sleep(250);
  }
  await sleep(300);
}

// ---------------------------------------------------------------- result rendering
function renderRead(r) {
  say('agent result',
    h('div', { class: 'untrusted' }, 'Page content is shown as data. I never follow instructions written on web pages.'),
    h('b', {}, r.title || 'Untitled page'), h('div', { class: 'muted' }, r.url),
    r.redactions ? h('p', { class: 'sens' }, `${r.redactions} sensitive value(s) hidden.`) : null,
    r.headings.length ? [h('h4', {}, 'Headings'), h('ul', {}, r.headings.map((x) => h('li', {}, x)))] : null,
    r.fields.length ? [h('h4', {}, 'Form fields'), h('ul', {}, r.fields.map((f) => h('li', {}, `${f.label} (${f.type}) `,
      f.sensitive ? h('span', { class: 'sens' }, 'sensitive, not read') : h('span', { class: 'muted' }, f.filled ? 'filled' : 'empty'))))] : null,
    r.buttons.length ? [h('h4', {}, 'Buttons'), h('div', {}, r.buttons.join(' · '))] : null,
    r.links.length ? [h('h4', {}, `Links (${r.linkCount})`), h('div', {}, r.links.join(' · '))] : null,
    r.text ? h('details', {}, h('summary', {}, 'Visible text (excerpt)'), h('pre', {}, r.text)) : null);
}
function renderFind(r) {
  say('agent result', h('h4', {}, `Matches (${r.count})`), h('ul', {}, r.snippets.map((x) => h('li', {}, x))));
}
function renderTabs(ts) {
  say('agent result', h('h4', {}, 'Tabs in this window'),
    h('ol', {}, ts.map((t) => h('li', {}, (t.active ? '▶ ' : '') + (t.title || '(untitled)'), ' ', h('span', { class: 'muted' }, t.url ? new URL(t.url).hostname : '')))));
}
function showHelp() {
  say('agent',
    h('b', {}, 'Things I can do'),
    h('ul', {},
      h('li', {}, '“read page”: summarise headings, fields, buttons and links'),
      h('li', {}, '“find shipping”: find text and scroll to it'),
      h('li', {}, '“scroll down / up / top / bottom”'),
      h('li', {}, '“click Sign up”: risky buttons ask you first'),
      h('li', {}, '“fill email with ada@example.com”, “type Ada into name”'),
      h('li', {}, '“close popup”: dismiss cookie banners or modals'),
      h('li', {}, '“open example.com”, “list tabs”, “switch to tab 2”, “close tab”')),
    h('p', {}, 'Chain steps with “then” or “;”. Example: ', h('i', {}, 'close popup then fill name with Ada then click Create account')),
    h('p', { class: 'muted' }, 'I refuse to read or fill passwords, card numbers, ID numbers, one-time codes, bank details and secret keys.'));
}

// ---------------------------------------------------------------- step execution
let run = null;

async function confirmRisky(title, body, yesLabel) {
  const r = await ask({ tone: 'warn', title, body, choices: [{ id: 'yes', label: yesLabel, kind: 'danger' }, { id: 'no', label: 'No, skip it' }] });
  if (r.id === 'cancel') throw new CancelError();
  return r.id === 'yes';
}

// Shared by simple commands and the AI agent: the confirmation rule lives here, not in the planner.
async function clickFlow(args) {
  const { result: t } = await pageCall('resolveClick', args);
  if (!t.ok) throw new Error(t.error);
  let confirmedText;
  if (t.risky) {
    const yes = await confirmRisky('Confirm before I click', h('div', {},
      h('p', {}, `I’m about to click “${t.text}”. This may ${t.reason}.`),
      h('p', { class: 'muted' }, 'This affects things outside this page, so I won’t do it without your OK.')), `Yes, click “${t.text.slice(0, 30)}”`);
    if (!yes) return 'Skipped. You chose not to click it';
    confirmedText = t.text;
  }
  const { tab, result } = await pageCall('click', { ...args, confirmedText });
  if (!result.ok) throw new Error(result.error);
  await waitSettled(tab.id);
  try {
    const [r] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: () => !!window.__pmAgent });
    return result.summary + (r && r.result === false ? '. The page changed (new page loaded)' : '');
  } catch {
    return result.summary + '. Opened a page I can’t access yet. I’ll ask if a later step needs it';
  }
}

async function tabAction(action, args = {}) {
  if (action === 'open') {
    const t = await chrome.tabs.create({ url: args.url });
    knownUrls.set(t.id, args.url);
    await waitSettled(t.id);
    return `Opened ${new URL(args.url).hostname} in a new tab`;
  }
  if (action === 'list') {
    await ensureTabs('list your tabs');
    const ts = await chrome.tabs.query({ currentWindow: true });
    renderTabs(ts);
    return `${ts.length} tabs: ` + ts.map((t) => `${t.index + 1}. ${t.title || '(untitled)'}${t.active ? ' (active)' : ''}`).join('; ');
  }
  if (action === 'close') {
    const t = await getTab();
    if (!(await confirmRisky('Close this tab?', 'Anything you haven’t saved on that page will be lost.', 'Close tab'))) return 'Skipped. You chose to keep the tab';
    await chrome.tabs.remove(t.id);
    return 'Closed the tab';
  }
  if (action === 'switch') {
    let ts = await chrome.tabs.query({ currentWindow: true });
    let t;
    const n = parseInt(args.which, 10);
    if (!isNaN(n)) t = ts.find((x) => x.index === n - 1);
    else {
      await ensureTabs('find a tab by its title');
      ts = await chrome.tabs.query({ currentWindow: true });
      const q = String(args.which).toLowerCase();
      t = ts.find((x) => (x.title || '').toLowerCase().includes(q) || (x.url || '').toLowerCase().includes(q));
    }
    if (!t) throw new Error(`No tab matches “${args.which}”.`);
    await chrome.tabs.update(t.id, { active: true });
    await sleep(200);
    return `Switched to tab ${t.index + 1}`;
  }
  throw new Error('Unsupported tab action');
}

async function execStep(s) {
  switch (s.type) {
    case 'help': showHelp(); return 'Help shown';
    case 'refuse': throw new RefusedError(s.reason);
    case 'unknown': throw new Error(`I don’t understand “${s.text}”. Type “help” to see what I can do.`);
    case 'page': {
      if (s.action === 'click') return clickFlow(s.args);
      const { result } = await pageCall(s.action, s.args);
      if (!result.ok) { if (result.refused) throw new RefusedError(result.error); throw new Error(result.error); }
      if (s.action === 'read') renderRead(result);
      if (s.action === 'find') renderFind(result);
      return result.summary;
    }
    case 'tabs': return tabAction(s.action, s.args);
  }
  throw new Error('Unsupported step');
}

function renderPlan(steps) {
  const list = h('ol', { class: 'plan' });
  const items = steps.map((s) => {
    const li = h('li', { class: 'step pending' }, h('span', { class: 'st' }), h('div', {}, h('div', {}, s.label), h('div', { class: 'detail' })));
    list.append(li);
    return li;
  });
  add(h('div', { class: 'msg agent' }, h('div', { class: 'plan-title' }, `Plan: ${steps.length} step${steps.length > 1 ? 's' : ''}`), list));
  return {
    set(i, status, detail) {
      items[i].className = 'step ' + status;
      if (detail !== undefined) items[i].querySelector('.detail').textContent = detail || '';
      scrollLog();
    },
  };
}

function setRunning(on, text) {
  $('#runBar').classList.toggle('hidden', !on);
  if (text) $('#runStatus').textContent = text;
}

async function runTask(text) {
  say('user', text);
  const steps = parse(text);
  if (!steps.length) return;
  if (steps.length === 1 && steps[0].type === 'refuse') { say('agent refuse', REFUSAL); return; }
  if (steps.length === 1 && steps[0].type === 'help') { showHelp(); return; }

  const plan = renderPlan(steps);
  run = { cancelled: false };
  const stats = { done: 0, failed: 0, refused: 0, skipped: 0 };
  let i = 0;
  try {
    for (; i < steps.length; i++) {
      if (run.cancelled) throw new CancelError();
      const s = steps[i];
      setRunning(true, `Step ${i + 1} of ${steps.length}: ${s.label}`);
      plan.set(i, 'running', '');
      for (;;) {
        try {
          const out = await execStep(s);
          if (/^Skipped/.test(out)) { plan.set(i, 'skipped', out); stats.skipped++; } else { plan.set(i, 'done', out); stats.done++; }
          break;
        } catch (e) {
          if (e instanceof CancelError || run.cancelled) throw new CancelError();
          if (e instanceof RefusedError) { plan.set(i, 'refused', e.message); stats.refused++; break; }
          plan.set(i, 'failed', e.message);
          const r = await ask({
            tone: 'error', title: `Step ${i + 1} didn’t work`, body: e.message,
            choices: [{ id: 'retry', label: 'Retry', kind: 'primary' }, { id: 'skip', label: 'Skip this step' }, { id: 'stop', label: 'Stop task' }],
          });
          if (r.id === 'retry') { plan.set(i, 'running', 'Retrying…'); continue; }
          if (r.id === 'skip') { plan.set(i, 'skipped', e.message); stats.skipped++; break; }
          throw new CancelError();
        }
      }
    }
    const allGood = stats.done === steps.length;
    say(allGood ? 'agent ok' : 'agent',
      allGood ? `Done. All ${steps.length} step(s) completed.`
        : `Finished: ${stats.done} done` + (stats.skipped ? `, ${stats.skipped} skipped` : '') + (stats.refused ? `, ${stats.refused} refused for privacy` : '') + '.');
  } catch (e) {
    for (let j = i; j < steps.length; j++) plan.set(j, 'cancelled');
    say('agent', `Stopped at step ${Math.min(i + 1, steps.length)}. Nothing else will run.${stats.done ? ` ${stats.done} step(s) had already completed.` : ''}`);
  } finally {
    setRunning(false);
    run = null;
    await releaseTaskGrants();
    renderAccess();
  }
}

// ---------------------------------------------------------------- onboarding
async function onboarding() {
  const { onboarded } = await chrome.storage.local.get('onboarded');
  if (onboarded) { await greet(); return; }
  const r = await ask({
    title: 'Welcome to Page Pilot',
    body: h('div', {},
      h('p', {}, 'Tell me what to do on a web page: read it, find things, scroll, click, fill forms or manage tabs. I show a plan, run it step by step and tell you what happened.'),
      h('p', {}, h('b', {}, 'I start with no access to any website. '), 'When a task needs a page, I ask first. You can allow it once, for the task, always for that site, or for every site.'),
      h('p', {}, h('b', {}, 'I never read sensitive information. '), 'Passwords, card numbers, ID numbers, one-time codes, bank details and secret keys are skipped and hidden.'),
      h('p', {}, 'Submitting, sending, buying and deleting always need your OK.')),
    choices: [
      { id: 'ask', label: 'Ask me when needed (recommended)', kind: 'primary' },
      { id: 'all', label: 'Allow on all sites', request: () => chrome.permissions.request({ origins: HOSTS_ALL }) },
    ],
  });
  await chrome.storage.local.set({ onboarded: true });
  say('agent', r.id === 'all' && r.ok
    ? 'All-sites access granted. You can switch back any time under Permissions.'
    : 'Got it. I’ll ask before using any site.');
  await greet();
}

async function greet() {
  if (await aiEnabled()) {
    say('agent', `Hi! Tell me what you want done in plain words. I’m using ${(await getAI()).model}. Start with “/” to use a simple command instead, for example “/read page”.`);
  } else {
    say('agent', h('span', {}, 'Hi! I’m in simple-command mode (type “help”). To use plain-language requests, add an OpenRouter API key under ',
      h('button', { class: 'link', onclick: openSettings }, 'Settings → AI model'), '.'));
  }
}

// ---------------------------------------------------------------- wiring
async function openSettings() {
  await renderSettings();
  $('#settings').classList.remove('hidden');
}

$('#form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const text = $('#input').value.trim();
  if (!text) return;
  $('#input').value = '';
  if (run) {
    if (questionHook) { questionHook(text); return; }
    if (run.notes) { addNote(text); return; }
    say('system', 'I’m still working. Press Stop first if you want to change the task.');
    return;
  }
  if (/^\/?(help|\?)$/i.test(text)) { say('user', text); (await aiEnabled()) ? showAIHelp() : showHelp(); return; }
  if (text.startsWith('/') || !(await aiEnabled())) runTask(text.replace(/^\//, ''));
  else runAgent(text);
});
$('#input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); $('#form').requestSubmit(); }
});
$('#stopBtn').addEventListener('click', () => {
  if (run) run.cancelled = true;
  if (aiAbort) aiAbort.abort();
  if (pending) pending.resolve({ id: 'cancel' });
});
$('#settingsBtn').addEventListener('click', async () => {
  const s = $('#settings');
  if (s.classList.contains('hidden')) await renderSettings();
  s.classList.toggle('hidden');
});
async function renderMode() {
  const on = await aiEnabled();
  const ai = await getAI();
  $('#modeTag').textContent = on ? 'AI · ' + ai.model.split('/').pop() : 'Simple commands';
  $('#modeTag').className = 'mode ' + (on ? 'on' : 'off');
  const chips = on
    ? ['Summarize this page', 'Close the cookie pop-up', 'Find the pricing and tell me the cheapest plan', 'help']
    : ['read page', 'close popup', 'find pricing', 'scroll down', 'list tabs', 'help'];
  $('#chips').replaceChildren(...chips.map((c) => h('button', { onclick: () => { $('#input').value = c; $('#form').requestSubmit(); } }, c)));
}
chrome.storage.onChanged.addListener((ch) => { if (ch.aiKey || ch.aiModel) renderMode(); });

chrome.runtime.onMessage.addListener((m) => {
  if (m && m.type === 'activeTabGranted') {
    if (pending && pending.kind === 'perm') pending.resolve({ id: 'toolbar' });
    renderAccess();
  }
});
const refreshAll = () => { renderAccess(); if (!$('#settings').classList.contains('hidden')) renderSettings(); };
chrome.permissions.onAdded.addListener(refreshAll);
chrome.permissions.onRemoved.addListener(refreshAll);
chrome.tabs.onActivated.addListener(renderAccess);
chrome.tabs.onUpdated.addListener((id, info) => { if (info.status === 'complete') renderAccess(); });
chrome.windows.onFocusChanged.addListener(renderAccess);

renderAccess();
renderMode();
onboarding();
