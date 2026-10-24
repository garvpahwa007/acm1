/* ============================================================================
   PhishGuard UI — vanilla JS, no build step, no external dependencies.
   Rendering is string-based and escaped through esc(); nothing here trusts
   server output with innerHTML.
   ========================================================================== */
'use strict';

/* ------------------------------------------------------------------- utils */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
));
const num = (n) => Number(n || 0).toLocaleString('en-IN');

async function api(path, opts) {
  const res = await fetch(path, opts);
  let body;
  try { body = await res.json(); } catch { body = {}; }
  if (!res.ok) throw new Error(body.error || `${res.status} ${res.statusText}`);
  return body;
}
const postJSON = (path, data) => api(path, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
});

let toastId = 0;
function toast(msg, kind = 'ok', ms = 5200) {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.innerHTML = `<span>${esc(msg)}</span><button class="x" aria-label="Dismiss">×</button>`;
  $('#toasts').appendChild(el);
  const close = () => el.remove();
  el.querySelector('.x').onclick = close;
  setTimeout(close, ms);
}

/* ------------------------------------------------------------ tier vocabulary */
const TIERS = {
  malicious:   { label: 'Malicious',        icon: '⛔', color: 'var(--danger)' },
  suspicious:  { label: 'Suspicious',       icon: '⚠',  color: 'var(--warn)' },
  unknown:     { label: 'Unknown — verify', icon: '?',  color: 'var(--unknown)' },
  likely_safe: { label: 'Likely safe',      icon: '✓',  color: 'var(--ok)' },
  safe:        { label: 'Likely safe',      icon: '✓',  color: 'var(--ok)' },
  low:         { label: 'Low risk',         icon: '✓',  color: 'var(--ok)' },
};
const tierOf = (label) => TIERS[label] || TIERS.unknown;
const sevClass = (sev) => ({ critical: 'b-critical', high: 'b-high', medium: 'b-medium',
  low: 'b-low', info: 'b-info' }[sev] || 'b-info');

/* ------------------------------------------------------------------- theme */
function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  localStorage.setItem('pg-theme', t);
  $('#theme-label').textContent = t === 'dark' ? 'Light mode' : 'Dark mode';
  $('#theme-icon').innerHTML = t === 'dark'
    ? '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5M17.5 17.5 19 19M19 5l-1.5 1.5M6.5 17.5 5 19"/>'
    : '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/>';
}
applyTheme(localStorage.getItem('pg-theme') || 'dark');
$('#theme-toggle').onclick = () =>
  applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');

/* ----------------------------------------------------------------- routing */
const ROUTES = {
  link: { title: 'Check a link', crumb: 'Instant lexical verdict, then infrastructure, reputation and a click preview' },
  email: { title: 'Check an email', crumb: 'Authentication, header forensics, BEC language, links, attachments and bank-detail diffs' },
  sweep: { title: 'Org sweep', crumb: 'Report-to-sweep: one report protects everyone who received the same campaign' },
  coverage: { title: 'Coverage & design', crumb: 'What the engine does, what it deliberately does not, and where its limits are' },
};
function go(route) {
  if (!ROUTES[route]) route = 'link';
  $$('.view').forEach((v) => { v.hidden = v.id !== `view-${route}`; });
  $$('.nav-item[data-route]').forEach((b) =>
    b.setAttribute('aria-current', b.dataset.route === route ? 'page' : 'false'));
  $('#page-title').textContent = ROUTES[route].title;
  $('#page-crumb').textContent = ROUTES[route].crumb;
  if (route === 'sweep') loadSweep();
  history.replaceState(null, '', `#${route}`);
  window.scrollTo({ top: 0, behavior: 'instant' });
  if (route === 'link') $('#url-input').focus({ preventScroll: true });
}
$$('.nav-item[data-route]').forEach((b) => { b.onclick = () => go(b.dataset.route); });
window.addEventListener('hashchange', () => go(location.hash.slice(1)));

/* ------------------------------------------------------- recent checks ---- */
function getRecent() {
  try { return JSON.parse(localStorage.getItem('pg-recent') || '[]'); } catch { return []; }
}
function pushRecent(item) {
  const list = getRecent().filter((r) => r.label !== item.label);
  list.unshift({ ...item, ts: Date.now() });
  localStorage.setItem('pg-recent', JSON.stringify(list.slice(0, 7)));
  renderRecent();
}
function renderRecent() {
  const list = getRecent();
  const box = $('#recent');
  if (!list.length) {
    box.innerHTML = '<div class="recent-empty">Nothing checked yet</div>';
    return;
  }
  box.innerHTML = list.map((r, i) => {
    const t = tierOf(r.tier);
    return `<button class="recent-item" data-recent="${i}" title="${esc(r.label)}">
      <span class="dot" style="background:${t.color}"></span>
      <span>${esc(r.short || r.label)}</span></button>`;
  }).join('');
  $$('.recent-item', box).forEach((b) => {
    b.onclick = () => {
      const r = getRecent()[Number(b.dataset.recent)];
      go(r.kind === 'email' ? 'email' : 'link');
      if (r.kind === 'email') { $('#eml-raw').value = r.payload; setEmailMode('paste'); analyseEmail(r.payload, false); }
      else { $('#url-input').value = r.payload; analyseUrl(r.payload); }
    };
  });
}
renderRecent();

/* ---------------------------------------------------------------- header ---- */
async function loadHeader() {
  try {
    const h = await api('/api/health');
    const keys = Object.entries(h.intel || {}).filter(([, v]) => v).map(([k]) => k);
    $('#engine-ver').textContent = '0.9.0';
    $('#engine-intel').textContent = keys.length ? keys.join(', ') : 'BYO-key';
    $('#engine-domains').textContent = num(h.stats.domains_seen);
    $('#engine-reports').textContent = num(h.stats.reports);
    $('#chip-intel').innerHTML = `<span class="dot" style="background:${keys.length ? 'var(--ok)' : 'var(--warn)'}"></span> intel <b>${esc(keys.length ? keys.join(' + ') : 'BYO-key')}</b>`;
    $('#chip-clusters').innerHTML = `<span class="dot" style="background:var(--accent)"></span> clusters <b>${num(h.stats.clusters)}</b>`;
    return h;
  } catch { return null; }
}

/* ============================================================================
   Shared renderers
   ========================================================================== */

function gauge(score, tierLabel) {
  const r = 44, c = 2 * Math.PI * r;
  const off = c * (1 - Math.max(0, Math.min(100, score)) / 100);
  return `<div class="gauge" role="img" aria-label="Risk score ${score} out of 100">
    <svg viewBox="0 0 104 104" width="104" height="104">
      <circle class="track" cx="52" cy="52" r="${r}" fill="none" stroke-width="9"/>
      <circle class="fill" cx="52" cy="52" r="${r}" fill="none" stroke-width="9"
              stroke-linecap="round" stroke-dasharray="${c.toFixed(1)}"
              stroke-dashoffset="${off.toFixed(1)}"/>
    </svg>
    <div class="num">${esc(score)}<small>/ 100</small></div>
  </div>`;
}

function verdictHero(v, opts = {}) {
  const t = tierOf(v.label);
  const facts = opts.facts || '';
  const sigs = v.signals || [];
  const contentN = sigs.filter((s) => ['content', 'auth', 'attachment', 'reputation'].includes(s.category)).length;
  const trust = (v.label === 'malicious' || v.label === 'suspicious') && contentN === 0
    ? `<span class="chip" title="Every signal came from naming, infrastructure or language — we never observed the payload itself.">
         <span class="dot" style="background:var(--warn)"></span> naming evidence only — payload not observed</span>`
    : (contentN > 0 ? `<span class="chip"><span class="dot" style="background:var(--ok)"></span> ${contentN} content-level signal${contentN === 1 ? '' : 's'}</span>` : '');
  return `<div class="verdict" data-tier="${esc(v.label)}">
    <div class="verdict-inner">
      ${gauge(v.score, v.label)}
      <div class="verdict-copy">
        <span class="verdict-tier">${t.icon} ${esc(t.label)}</span>
        <h2>${esc(v.headline)}</h2>
        <div class="lede">${esc(v.explain)}</div>
        <div class="verdict-meta">
          <span class="chip"><span class="dot" style="background:${v.intel_ok ? 'var(--ok)' : 'var(--warn)'}"></span>
            ${v.intel_ok ? 'corroborated'
              : (v.provisional ? 'instant pass · verifying' : 'degraded — lexical only')}</span>
          <span class="chip">confidence <b>${esc(v.confidence)}</b></span>
          <span class="chip" title="${esc(v.confidence_text)}">${esc(v.confidence_text)}</span>
          ${trust}
          ${v.receipt_id ? `<span class="chip mono">${esc(v.receipt_id)}</span>` : ''}
        </div>
      </div>
      <div class="verdict-actions">
        <button class="btn btn-ghost btn-sm" data-act="receipt">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" width="14" height="14"><path d="M4 2v20l3-2 3 2 3-2 3 2 3-2V2l-3 2-3-2-3 2-3-2-3 2Z"/><path d="M8 8h8M8 12h6"/></svg>
          View receipt</button>
        <button class="btn btn-ghost btn-sm" data-act="copy">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" width="14" height="14"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>
          Copy defanged</button>
      </div>
    </div>
    ${facts ? `<div class="factstrip">${facts}</div>` : ''}
  </div>`;
}

const fact = (k, v, cls = '') => `<div class="f"><div class="k">${esc(k)}</div><div class="v ${cls}">${v}</div></div>`;

function signalsCard(v) {
  const counts = v.counts || {};
  const total = (v.signals || []).length;
  if (!total) {
    return `<div class="card"><div class="card-head"><h3 class="card-title">Evidence</h3></div>
      <div class="card-body"><div class="callout good"><b>No signals fired.</b>
      <div class="sub">Absence of evidence is not evidence of safety — it means we found nothing to argue with.</div></div></div></div>`;
  }
  const chips = [
    ['all', total], ['critical', counts.critical || 0], ['high', counts.high || 0],
    ['medium', counts.medium || 0], ['low', (counts.low || 0) + (counts.info || 0)],
  ].filter(([, n]) => n > 0 || true);

  const rows = v.signals.map((s) => `
    <div class="sig" data-sev="${esc(s.severity)}">
      <div class="sig-rail"></div>
      <div class="sig-main">
        <div class="sig-title">${esc(s.title)}
          <span class="badge ${sevClass(s.severity)}">${esc(s.severity)}</span>
          <span class="sig-meta">${esc(s.category)} · w${esc(s.weight)}</span></div>
        <div class="sig-ev">${esc(s.evidence)}</div>
        ${s.tip ? `<div class="sig-tip"><b>Remember:</b> ${esc(s.tip)}</div>` : ''}
      </div>
    </div>`).join('');

  return `<div class="card">
    <div class="card-head">
      <h3 class="card-title">Evidence chain</h3>
      <span class="faint tiny">${total} signal${total === 1 ? '' : 's'}</span>
      <div class="spacer"></div>
      <div class="filters">
        ${chips.map(([k, n], i) => `<button class="filter" data-filter="${k}" aria-pressed="${i === 0}">${k} · ${n}</button>`).join('')}
      </div>
    </div>
    <div class="card-body" id="sig-list">${rows}</div>
  </div>`;
}

function bindFilters(root) {
  $$('.filter', root).forEach((b) => {
    b.onclick = () => {
      $$('.filter', root).forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
      const k = b.dataset.filter;
      $$('.sig', root).forEach((s) => {
        const sev = s.dataset.sev;
        const show = k === 'all' || (k === 'low' ? (sev === 'low' || sev === 'info') : sev === k);
        s.hidden = !show;
      });
    };
  });
}

function blastCard(b, preview) {
  if (!b) return '';
  const bad = ['credential_theft', 'malware', 'payment_fraud'].includes(b.risk);
  // If nothing fired at content level AND we could not load the page, saying
  // "no active content detected" would be a false clearance. Say what's true.
  const unobserved = b.risk === 'low' && preview && preview.ok === false;
  const body = unobserved
    ? `<div class="callout warn"><b>Not verified — the page never loaded.</b>
        <div class="sub">We could not observe the destination, so we cannot rule out a credential
        form or a redirect. Treat the blast radius as unknown, not empty.</div>
        <div class="sub faint" style="margin-top:6px">${esc(preview.error || '')}</div></div>`
    : `<div class="callout ${bad ? 'bad' : ''}">
        <b>${esc(b.summary)}</b><div class="sub">${esc(b.consequence)}</div></div>`;
  return `<div class="card"><div class="card-head"><h3 class="card-title">What happens if you click</h3></div>
    <div class="card-body">${body}</div></div>`;
}

function nextStepsCard(v) {
  return `<div class="card"><div class="card-head"><h3 class="card-title">Do this now</h3></div>
    <div class="card-body">
      <ol class="steps">${(v.next_steps || []).map((s) => `<li><span>${esc(s)}</span></li>`).join('')}</ol>
      <hr class="sep">
      <div class="callout"><b>Out-of-band challenge</b>
        <div class="sub">${esc(v.out_of_band.question)}</div>
        <div class="sub faint" style="margin-top:7px">${esc(v.out_of_band.principle)}</div>
      </div>
    </div></div>`;
}

function tipsCard(v) {
  if (!v.tips || !v.tips.length) return '';
  return `<div class="card"><div class="card-head"><h3 class="card-title">What to look for next time</h3>
      <div class="spacer"></div><span class="faint tiny">teach-in-the-moment</span></div>
    <div class="card-body"><div class="tile-grid">
      ${v.tips.map((t, i) => `<div class="tile"><div class="n">0${i + 1}</div><p>${esc(t)}</p></div>`).join('')}
    </div></div></div>`;
}

function infraCard(f) {
  if (!f) return '';
  const reg = f.registration || {}, dns = f.dns || {}, tls = f.tls || {};
  const rows = [
    ['registrable domain', esc(f.registrable_domain || '—')],
    ['displayed host', esc(f.display_host || '—')],
    ['brand impersonated', f.brand_impersonated ? `<span style="color:var(--danger)">${esc(f.brand_impersonated)}</span>` : '—'],
    ['registered', reg.registered ? esc(reg.registered) : esc(reg.error || 'unknown')],
    ['domain age', reg.age_days != null ? `${num(reg.age_days)} days` : 'unknown'],
    ['registrar', esc(reg.registrar || 'unknown')],
    ['resolves', dns.resolves ? 'yes' : 'no'],
    ['MX', (dns.mx || []).length ? esc(dns.mx.slice(0, 2).join(', ')) : 'none'],
    ['SPF', dns.spf ? esc(dns.spf.slice(0, 64)) : 'none published'],
    ['DMARC', dns.dmarc ? esc(dns.dmarc.slice(0, 64)) : 'none published'],
    ['TLS', tls.ok ? `ok · ${esc(tls.issuer || '?')} · ${esc(tls.not_before_days)}d old`
      : esc(tls.error || 'not checked')],
  ];
  if (f.baseline) {
    rows.push(['org baseline', f.baseline.first_contact
      ? '<span style="color:var(--warn)">first time seen here</span>'
      : `seen ${esc(f.baseline.hits)}× since ${esc((f.baseline.first_seen || '').slice(0, 10))}`]);
  }
  if (f.time_of_click && f.time_of_click.seen_before) {
    rows.push(['time-of-click', f.time_of_click.previously_clean_now_bad
      ? '<span style="color:var(--danger)">was clean when first seen, now hostile</span>'
      : (f.time_of_click.content_changed ? 'content changed since first seen' : 'unchanged since first seen')]);
  }
  return `<div class="card"><div class="card-head"><h3 class="card-title">Infrastructure</h3></div>
    <div class="card-body"><dl class="kv">
      ${rows.map(([k, val]) => `<dt>${esc(k)}</dt><dd>${val}</dd>`).join('')}
    </dl></div></div>`;
}

function previewCard(p) {
  if (!p) return '';
  const head = `<div class="card-head"><h3 class="card-title">What you'd land on</h3>
      <div class="spacer"></div>
      <span class="faint tiny">read-only HTML fetch · JS disabled</span></div>`;
  if (!p.ok) {
    return `<div class="card">${head}<div class="card-body">
      <div class="callout warn"><b>Could not fetch a preview</b>
        <div class="sub">${esc(p.error || 'unreachable')}</div>
        <div class="sub faint" style="margin-top:6px">A page that fails to load today can be armed tomorrow.
        This is a time-of-click risk, not a clearance.</div></div></div></div>`;
  }
  const forms = (p.forms || []).length ? `<table class="table" style="margin-top:12px">
      <thead><tr><th>form target</th><th>method</th><th>captures</th><th>fields</th></tr></thead>
      <tbody>${p.forms.map((f) => `<tr>
        <td class="mono">${esc(f.action_host || 'same site')}${f.is_external ? ' <span class="badge b-critical">external</span>' : ''}</td>
        <td>${esc(f.method)}</td>
        <td>${f.has_password ? '<span class="badge b-critical">password</span>' : '—'}</td>
        <td class="mono tiny">${esc((f.fields || []).join(', ') || '—')}</td></tr>`).join('')}</tbody></table>` : '';
  const ext = (p.external_form_actions || []).map((e) => `<div class="callout bad" style="margin-top:10px">
      Password field POSTs to <span class="mono">${esc(e.host)}</span> — a different domain from the page you'd be looking at.
      That is credential harvesting.</div>`).join('');
  return `<div class="card">${head}<div class="card-body">
    <dl class="kv">
      <dt>final URL</dt><dd class="defang">${esc(p.final_url_defanged)}</dd>
      <dt>redirect hops</dt><dd>${esc(p.redirect_hops)}</dd>
      <dt>page title</dt><dd>${esc(p.title || '—')}</dd>
      <dt>http status</dt><dd>${esc(p.status)}</dd>
    </dl>
    ${ext}${forms}
    ${p.text_snippet ? `<div class="callout" style="margin-top:12px"><b>Visible text</b>
      <div class="sub">“${esc(p.text_snippet.slice(0, 260))}…”</div></div>` : ''}
    ${(p.js_redirects || []).length ? `<div class="callout warn" style="margin-top:10px">
      JS / meta redirect to <span class="mono defang">${esc(p.js_redirects[0])}</span></div>` : ''}
    <div class="faint tiny" style="margin-top:12px">${esc(p.disclaimer)}</div>
  </div></div>`;
}

function receiptButton(v, root) {
  $$('[data-act="receipt"]', root).forEach((b) => {
    b.onclick = () => openReceipt(v.receipt_id);
  });
  $$('[data-act="copy"]', root).forEach((b) => {
    b.onclick = async () => {
      const text = (v.facts && v.facts.defanged) || v.subject || '';
      if (!text) { toast('Nothing to copy', 'err'); return; }
      try {
        await navigator.clipboard.writeText(text);
        toast('Copied — safe to paste into a ticket or chat');
      } catch { toast('Clipboard blocked by the browser', 'err'); }
    };
  });
}

/* ------------------------------------------------------------------ drawer */
async function openReceipt(rid) {
  if (!rid) { toast('No receipt for this verdict', 'err'); return; }
  $('#drawer-code').textContent = 'Loading…';
  $('#scrim').classList.add('open');
  $('#drawer').classList.add('open');
  $('#drawer').setAttribute('aria-hidden', 'false');
  try {
    const data = await api(`/api/receipt/${encodeURIComponent(rid)}`);
    $('#drawer-code').textContent = JSON.stringify(data, null, 2);
    $('#drawer-title').textContent = `Audit receipt · ${rid}`;
  } catch (e) {
    $('#drawer-code').textContent = `Could not load receipt: ${e.message}`;
  }
}
function closeDrawer() {
  $('#scrim').classList.remove('open');
  $('#drawer').classList.remove('open');
  $('#drawer').setAttribute('aria-hidden', 'true');
}
$('#scrim').onclick = closeDrawer;
$('#drawer-close').onclick = closeDrawer;
$('#drawer-copy').onclick = async () => {
  try {
    await navigator.clipboard.writeText($('#drawer-code').textContent);
    toast('Receipt copied to clipboard');
  } catch { toast('Clipboard blocked by the browser', 'err'); }
};
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeDrawer();
  if (e.key === '/' || ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k')) {
    const el = document.activeElement;
    if (el && /INPUT|TEXTAREA/.test(el.tagName)) return;
    e.preventDefault();
    go('link'); $('#url-input').focus();
  }
  if (!(e.metaKey || e.ctrlKey) && /INPUT|TEXTAREA/.test(document.activeElement?.tagName || '')) return;
  if (e.key === '1') go('link');
  if (e.key === '2') go('email');
  if (e.key === '3') go('sweep');
});

/* ============================================================================
   LINK flow
   ========================================================================== */
let lastUrl = '';

function setStage(name, state) {
  const el = $(`.stage[data-stage="${name}"]`);
  if (el) el.dataset.state = state;
}
function resetStages() {
  $$('#url-pipeline .stage').forEach((s) => { s.dataset.state = ''; });
}

function skeletonVerdict() {
  return `<div class="card card-pad">
    <div style="display:flex;gap:20px;align-items:center">
      <div class="skel" style="width:104px;height:104px;border-radius:50%"></div>
      <div style="flex:1">
        <div class="skel skel-line" style="width:120px"></div>
        <div class="skel skel-line" style="width:52%;height:22px;margin:12px 0"></div>
        <div class="skel skel-line" style="width:80%"></div>
        <div class="skel skel-line" style="width:64%"></div>
      </div>
    </div>
  </div>`;
}

async function analyseUrl(url) {
  const out = $('#url-out');
  lastUrl = url;
  $('#url-pipeline').hidden = false;
  resetStages();
  $('#btn-url').disabled = true;
  out.innerHTML = skeletonVerdict();
  setStage('lexical', 'run');

  let quick;
  try {
    quick = await postJSON('/api/check/url?mode=quick', { url });
  } catch (e) {
    $('#btn-url').disabled = false;
    setStage('lexical', '');
    out.innerHTML = `<div class="card card-pad"><div class="callout bad"><b>Could not analyse that.</b>
      <div class="sub">${esc(e.message)}</div></div></div>`;
    toast(e.message, 'err');
    return;
  }
  setStage('lexical', 'done');
  ['infra', 'rep', 'preview'].forEach((s) => setStage(s, 'run'));

  const f = quick.facts || {};
  out.innerHTML = verdictHero(quick, {
    facts: fact('registrable domain', esc(f.registrable_domain || '—'))
      + fact('in this workspace', (f.baseline && f.baseline.first_contact)
        ? '<span style="color:var(--warn)">first contact</span>'
        : `seen ${esc(f.baseline ? f.baseline.hits : 0)}×`)
      + fact('pass', 'lexical only')
      + fact('latency', '~5 ms'),
  }) + `<div class="callout" style="display:flex;align-items:center;gap:10px">
      <span class="spinner"></span>
      <div><b>Instant verdict shown.</b> <span class="muted">Corroborating with registration, DNS, TLS and reputation data…</span></div>
    </div>` + signalsCard(quick);
  bindFilters(out);
  receiptButton(quick, out);

  let full;
  try {
    full = await postJSON('/api/check/url', { url });
  } catch (e) {
    ['infra', 'rep', 'preview'].forEach((s) => setStage(s, ''));
    $('#btn-url').disabled = false;
    out.insertAdjacentHTML('afterbegin', `<div class="callout warn" style="margin-bottom:0">
      <b>Full analysis failed.</b> <span class="muted">${esc(e.message)} — the lexical verdict above stands,
      and the app reports “unknown” rather than an unearned green tick.</span></div>`);
    toast('Degraded mode: infrastructure lookups unavailable', 'err');
    pushRecent({ kind: 'url', label: quick.facts.defanged, short: url.slice(0, 34), tier: quick.label, payload: url });
    return;
  }
  ['infra', 'rep', 'preview', 'baseline'].forEach((s) => setStage(s, 'done'));
  $('#btn-url').disabled = false;

  const reg = (full.facts && full.facts.registration) || {};
  const dns = (full.facts && full.facts.dns) || {};
  const tls = (full.facts && full.facts.tls) || {};
  const facts = fact('registrable domain', esc((full.facts || {}).registrable_domain || '—'))
    + fact('domain age', reg.age_days != null
      ? `<span style="color:${reg.age_days <= 30 ? 'var(--danger)' : 'inherit'}">${num(reg.age_days)} days</span>`
      : 'unknown')
    + fact('DNS', dns.resolves ? `resolves · ${(dns.a || []).length} A` : '<span style="color:var(--warn)">no A record</span>')
    + fact('TLS', tls.ok ? `valid · ${esc(tls.not_before_days)}d` : (tls.error ? 'invalid' : 'n/a'))
    + fact('intel', full.intel_ok ? 'corroborated' : 'degraded');

  out.innerHTML = verdictHero(full, { facts })
    + `<div class="grid grid-2">${blastCard(full.blast_radius, full.preview)}${nextStepsCard(full)}</div>`
    + signalsCard(full)
    + `<div class="grid grid-2">${infraCard(full.facts)}${previewCard(full.preview)}</div>`
    + tipsCard(full);
  bindFilters(out);
  receiptButton(full, out);

  pushRecent({ kind: 'url', label: full.facts.defanged || url, short: url.replace(/^https?:\/\//, '').slice(0, 32), tier: full.label, payload: url });
  loadHeader();
}

$('#btn-url').onclick = () => {
  const u = $('#url-input').value.trim();
  if (!u) { toast('Paste a link first', 'err'); $('#url-input').focus(); return; }
  analyseUrl(u);
};
$('#url-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#btn-url').click(); });
$('#url-input').addEventListener('input', (e) => { $('#url-clear').hidden = !e.target.value; });
$('#url-clear').onclick = () => {
  $('#url-input').value = '';
  $('#url-clear').hidden = true;
  $('#url-out').innerHTML = '';
  $('#url-pipeline').hidden = true;
  $('#url-input').focus();
};
$$('[data-demo]').forEach((b) => { b.onclick = () => { $('#url-input').value = b.dataset.demo; analyseUrl(b.dataset.demo); }; });

/* ============================================================================
   EMAIL flow
   ========================================================================== */
let emailMode = 'file';
let selectedFile = null;

function setEmailMode(mode) {
  emailMode = mode;
  $$('[data-emode]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.emode === mode)));
  $('#eml-raw').hidden = mode !== 'paste';
  $('#eml-drop').hidden = mode !== 'file';
}

$$('[data-emode]').forEach((b) => { b.onclick = () => setEmailMode(b.dataset.emode); });

const drop = $('#eml-drop');
const fileInput = $('#eml-file');
drop.onclick = () => fileInput.click();
drop.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); } };
fileInput.onchange = () => {
  selectedFile = fileInput.files[0] || null;
  if (selectedFile) {
    drop.classList.add('hasfile');
    $('#drop-title').textContent = selectedFile.name;
    $('#drop-sub').textContent = `${(selectedFile.size / 1024).toFixed(1)} KB · ready to analyse`;
  }
};
['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, (e) => {
  e.preventDefault(); drop.classList.add('over');
}));
['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => {
  e.preventDefault(); drop.classList.remove('over');
}));
drop.addEventListener('drop', (e) => {
  const f = e.dataTransfer.files && e.dataTransfer.files[0];
  if (!f) return;
  selectedFile = f;
  const dt = new DataTransfer();
  dt.items.add(f);
  fileInput.files = dt.files;
  drop.classList.add('hasfile');
  $('#drop-title').textContent = f.name;
  $('#drop-sub').textContent = `${(f.size / 1024).toFixed(1)} KB · ready to analyse`;
});

function authStrip(a, dkimVerified) {
  const order = [['spf', 'SPF'], ['dkim', 'DKIM'], ['dmarc', 'DMARC'], ['arc', 'ARC']];
  return order.map(([k, label]) => {
    const val = a && a[k];
    const cls = val === 'pass' ? 'pass' : (val === 'fail' ? 'fail' : (val ? 'mid' : ''));
    const shown = val === 'none' ? 'none' : (val || 'absent');
    const note = k === 'dkim'
      ? (dkimVerified === true ? 'signature verified' : dkimVerified === false ? 'verification failed' : 'header only')
      : '';
    return `<div class="authpill ${cls}">
      <div class="name">${esc(label)}</div>
      <div class="val">${esc(shown)}</div>
      ${note ? `<div class="note">${esc(note)}</div>` : ''}
    </div>`;
  }).join('');
}

function identityCard(e) {
  const dom = (s) => (String(s || '').split('@')[1] || '').toLowerCase();
  const flagged = (x, y) => x && y && dom(x) !== dom(y);
  const rows = [
    ['from', esc(e.from_display || '—') + ' &lt;' + esc(e.from_addr || '—') + '&gt;', false],
    ['reply-to', e.reply_to ? `<span class="defang">${esc(e.reply_to)}</span>` : '—',
      flagged(e.reply_to, e.from_addr)],
    ['return-path', e.return_path ? `<span class="defang">${esc(e.return_path)}</span>` : '—',
      flagged(e.return_path, e.from_addr)],
    ['subject', esc(e.subject), false],
    ['date', esc(e.date || '—'), false],
    ['message-id', esc(e.message_id || '—'), false],
    ['received', `${esc(e.received?.hops ?? '—')} hops${e.received?.anomaly ? ' · <span class="hl">injected hop</span>' : ''}`, !!e.received?.anomaly],
  ];
  return `<div class="card"><div class="card-head"><h3 class="card-title">Sender identity</h3>
      <div class="spacer"></div>
      <span class="faint tiny">only the address after @ identifies the sender</span></div>
    <div class="card-body">
      <div class="authstrip" style="margin-bottom:16px">${authStrip(e.auth, e.dkim_verified)}</div>
      <div class="ident">
        ${rows.map(([k, v, flag]) => `<div class="ident-row ${flag ? 'flag' : ''}">
          <div class="k">${esc(k)}</div><div class="v">${v}</div></div>`).join('')}
      </div>
    </div></div>`;
}

function linksCard(links) {
  if (!links || !links.length) {
    return `<div class="card"><div class="card-head"><h3 class="card-title">Links in the body</h3></div>
      <div class="card-body"><div class="faint small">No links found in this message.</div></div></div>`;
  }
  const rows = links.map((l, i) => `<tr>
    <td class="mono defang" style="max-width:280px">${esc(l.href_defanged)}</td>
    <td class="small">${l.display_text ? esc(l.display_text) : '<span class="faint">—</span>'}
      ${l.display_mismatch ? '<div><span class="badge b-critical">text lies</span></div>' : ''}</td>
    <td><span class="badge ${l.score >= 65 ? 'b-critical' : l.score >= 30 ? 'b-high' : 'b-ok'}">${esc(l.score)}</span></td>
    <td class="small muted">${esc((l.signals || []).slice(0, 2).map((s) => s.title).join('; ') || '—')}</td>
    <td><button class="btn btn-ghost btn-sm" data-deep="${i}">Deep scan</button></td>
  </tr>`).join('');
  return `<div class="card"><div class="card-head"><h3 class="card-title">Links in the body</h3>
      <span class="faint tiny">${links.length}</span>
      <div class="spacer"></div>
      <span class="faint tiny">scores are lexical — deep scan adds infrastructure + preview</span></div>
    <div class="card-body" style="padding:0">
      <table class="table"><thead><tr><th>href (defanged)</th><th>display text</th><th>score</th><th>why</th><th></th></tr></thead>
      <tbody>${rows}</tbody></table>
    </div>
    <div id="deep-out" style="padding:0 20px 20px"></div>
  </div>`;
}

function attachmentsCard(atts) {
  if (!atts || !atts.length) {
    return `<div class="card"><div class="card-head"><h3 class="card-title">Attachments</h3></div>
      <div class="card-body"><div class="faint small">None.</div></div></div>`;
  }
  const rows = atts.map((a) => `<tr>
    <td class="mono">${esc(a.filename)}</td>
    <td class="num">${a.size < 1024 ? `${a.size} B` : `${(a.size / 1024).toFixed(1)} KB`}</td>
    <td>${a.macro_enabled ? '<span class="badge b-high">macro</span> ' : ''}${a.encrypted_archive ? '<span class="badge b-critical">encrypted zip</span> ' : ''}${a.double_extension ? '<span class="badge b-critical">double extension</span>' : ''}${(!a.macro_enabled && !a.encrypted_archive && !a.double_extension) ? '<span class="faint">—</span>' : ''}</td>
    <td class="mono tiny faint">${esc(a.sha256.slice(0, 24))}…</td></tr>`).join('');
  return `<div class="card"><div class="card-head"><h3 class="card-title">Attachments</h3>
      <span class="faint tiny">${atts.length}</span></div>
    <div class="card-body" style="padding:0">
      <table class="table"><thead><tr><th>filename</th><th>size</th><th>flags</th><th>sha256</th></tr></thead>
      <tbody>${rows}</tbody></table>
    </div>
    <div class="card-body" style="padding-top:12px"><div class="faint tiny">
      Files are hashed locally and never opened or executed. Add a VirusTotal key to auto-check these hashes.</div></div>
  </div>`;
}

function paymentCard(v) {
  const accts = v.accounts_found || [];
  const vendor = accts.length ? accts[0].vendor : '';
  return `<div class="card"><div class="card-head"><h3 class="card-title">Payment identifiers</h3></div>
    <div class="card-body">
      ${accts.length ? `<dl class="kv">${accts.map((a) =>
        `<dt>${esc(a.vendor || 'account')}</dt><dd class="defang">${esc(a.value)}</dd>`).join('')}</dl>` :
        '<div class="faint small">No account numbers, IBANs or IFSC codes found.</div>'}
      <div class="faint tiny" style="margin-top:12px">
        Diffed against the vendor's <b>trusted</b> baseline. A value taken from an unverified message never
        becomes the baseline — otherwise one fraudulent invoice would poison the reference and the second
        attempt would look clean.
      </div>
      ${vendor ? `<div class="row" style="margin-top:12px">
        <button class="btn btn-ghost btn-sm" data-confirm="${esc(vendor)}">I verified this by phone → update baseline</button>
      </div><div id="confirm-out" style="margin-top:9px"></div>` : ''}
    </div></div>`;
}

function reportCard(v, e) {
  const c = v.cluster || { reports: 0, clicked: 0 };
  const multi = (c.reports || 0) > 1;
  return `<div class="card"><div class="card-head"><h3 class="card-title">Report to sweep</h3>
      <div class="spacer"></div>
      ${multi ? `<span class="badge b-critical">${esc(c.reports)} reports · ${esc(c.clicked)} clicked</span>` : ''}</div>
    <div class="card-body">
      <div class="callout ${multi ? 'bad' : ''}">
        ${multi
          ? `<b>${esc(c.reports)} people have reported this campaign.</b> ${esc(c.clicked)} clicked.
             Reporting now warns everyone else who received it.`
          : 'First report of this campaign here. Reporting clusters any future copy automatically.'}
      </div>
      <div class="input-row" style="margin-top:14px;flex-wrap:wrap;align-items:center">
        <label class="field" style="flex:0 0 220px">
          <input id="reporter" type="text" placeholder="your name / desk (optional)" style="font-family:var(--sans)">
        </label>
        <label class="small muted" style="display:flex;align-items:center;gap:7px;white-space:nowrap">
          <input type="checkbox" id="clicked-cb"> I already clicked it</label>
        <button class="btn btn-primary btn-sm" id="btn-report">Report → sweep org</button>
      </div>
      <div id="report-out" style="margin-top:12px"></div>
    </div></div>`;
}

function postClickCard() {
  return `<div class="card" id="post-click"><div class="card-head">
      <h3 class="card-title">Post-click response</h3>
      <div class="spacer"></div><span class="badge b-critical">you already clicked</span></div>
    <div class="card-body">
      <div class="callout bad"><b>Order matters.</b>
        <div class="sub">Do these in sequence, fastest blast radius first.</div></div>
      <ol class="steps" style="margin-top:14px">
        <li><span><b>Revoke sessions now</b> — “sign out everywhere” for that account. Changing the password alone leaves the attacker's token alive.</span></li>
        <li><span><b>Change the password</b> from a known-clean device, then re-register MFA.</span></li>
        <li><span><b>Check mailbox rules</b> for auto-forward, hidden folders or delegate access — the standard way attackers keep reading mail after a reset.</span></li>
        <li><span><b>Check sent items and OAuth consents</b> for anything you did not authorise.</span></li>
        <li><span><b>Tell your security team with the receipt ID</b> so they can sweep the cluster and warn the other recipients.</span></li>
        <li><span>If card or payment details were entered: <b>call the bank now</b> — recall odds drop sharply after 24 hours.</span></li>
      </ol>
    </div></div>`;
}

async function analyseEmail(payload, isFile) {
  const out = $('#email-out');
  $('#btn-eml').disabled = true;
  out.innerHTML = `<div class="card card-pad"><div style="display:flex;align-items:center;gap:12px">
      <span class="spinner"></span><div><b>Parsing message…</b>
      <div class="faint small">verifying DKIM, walking the Received chain, scoring links</div></div></div></div>`;

  let v;
  try {
    v = isFile
      ? await api('/api/check/email', { method: 'POST', body: payload })
      : await postJSON('/api/check/email', { raw: payload });
  } catch (e) {
    $('#btn-eml').disabled = false;
    out.innerHTML = `<div class="card card-pad"><div class="callout bad">
      <b>Could not parse that message.</b><div class="sub">${esc(e.message)}</div></div></div>`;
    toast(e.message, 'err');
    return;
  }
  $('#btn-eml').disabled = false;
  const e = v.email || {};
  const links = v.links || [];

  out.innerHTML = verdictHero(v, {
    facts: fact('from', esc(e.from_addr || '—'))
      + fact('authentication', esc((e.auth && (e.auth.dmarc || e.auth.spf)) || 'absent'))
      + fact('links', num(links.length))
      + fact('attachments', num((v.attachments || []).length))
      + fact('received', `${esc(e.received?.hops ?? '—')} hops`),
  })
  + `<div class="grid grid-2">${blastCard(v.blast_radius)}${nextStepsCard(v)}</div>`
  + identityCard(e)
  + signalsCard(v)
  + linksCard(links)
  + `<div class="grid grid-2">${attachmentsCard(v.attachments)}${paymentCard(v)}</div>`
  + tipsCard(v)
  + reportCard(v, e);

  bindFilters(out);
  receiptButton(v, out);

  // deep scan for a single link
  $$('[data-deep]', out).forEach((b) => {
    b.onclick = async () => {
      const l = links[Number(b.dataset.deep)];
      const box = $('#deep-out');
      box.innerHTML = `<div style="display:flex;gap:10px;align-items:center;padding:12px 0">
        <span class="spinner"></span><span class="muted small">Deep-scanning <span class="mono">${esc(l.href_defanged)}</span>…</span></div>`;
      try {
        const d = await postJSON('/api/check/url', { url: l.href });
        box.innerHTML = `<div class="stack" style="margin-top:8px">
          ${verdictHero(d, { facts: fact('domain', esc((d.facts || {}).registrable_domain || '—'))
            + fact('age', ((d.facts || {}).registration || {}).age_days != null
              ? `${num(d.facts.registration.age_days)} days` : 'unknown') })}
          ${signalsCard(d)}${previewCard(d.preview)}</div>`;
        bindFilters(box);
        receiptButton(d, box);
      } catch (err) {
        box.innerHTML = `<div class="callout warn">Deep scan failed: ${esc(err.message)}</div>`;
      }
    };
  });

  // vendor baseline confirmation
  const confBtn = $('[data-confirm]', out);
  if (confBtn) {
    confBtn.onclick = async () => {
      if (!confirm('Only do this after calling the vendor on a number from your own records. Continue?')) return;
      try {
        const d = await postJSON('/api/vendor/confirm', { vendor_key: confBtn.dataset.confirm, by: ($('#reporter') || {}).value || 'analyst' });
        $('#confirm-out').innerHTML = `<div class="callout good">Baseline updated for
          <span class="mono">${esc(d.vendor)}</span> at ${esc(d.confirmed_at)}. Future messages with
          different details will flag again.</div>`;
        toast('Vendor baseline updated');
      } catch (err) {
        $('#confirm-out').innerHTML = `<div class="callout warn">${esc(err.message)}</div>`;
      }
    };
  }

  // report → sweep
  const reportBtn = $('#btn-report', out);
  if (reportBtn) {
    reportBtn.onclick = async () => {
      const clicked = $('#clicked-cb').checked;
      try {
        const d = await postJSON('/api/report', {
          cluster_key: (v.cluster || {}).cluster_key,
          subject: e.subject, sender: e.from_addr,
          links: links.map((l) => l.href),
          reporter: $('#reporter').value,
          clicked, verdict: v.label, score: v.score,
        });
        $('#report-out').innerHTML = `<div class="callout warn"><b>Reported.</b>
          ${esc(d.cluster.reports)} report(s) in this cluster · ${esc(d.cluster.clicked)} clicked.
          Everyone else who receives it now sees this immediately.</div>`;
        if (clicked && !$('#post-click')) {
          out.insertAdjacentHTML('beforeend', postClickCard());
          $('#post-click').scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
        toast('Reported — campaign swept');
        loadHeader();
      } catch (err) { toast(err.message, 'err'); }
    };
  }

  pushRecent({
    kind: 'email', label: e.subject || 'email', short: (e.subject || 'email').slice(0, 30),
    tier: v.label, payload,
  });
  loadHeader();
}

$('#btn-eml').onclick = () => {
  if (emailMode === 'paste') {
    const raw = $('#eml-raw').value;
    if (!raw.trim()) { toast('Paste the raw message source first', 'err'); return; }
    analyseEmail(raw, false);
  } else {
    if (!selectedFile && !fileInput.files[0]) { toast('Choose an .eml file first', 'err'); return; }
    const fd = new FormData();
    fd.append('file', selectedFile || fileInput.files[0]);
    analyseEmail(fd, true);
  }
};
$$('[data-sample]').forEach((b) => {
  b.onclick = async () => {
    try {
      const res = await fetch(`/api/sample/${b.dataset.sample}`);
      if (!res.ok) throw new Error('sample unavailable');
      const txt = await res.text();
      setEmailMode('paste');
      $('#eml-raw').value = txt;
      analyseEmail(txt, false);
    } catch (e) { toast(e.message, 'err'); }
  };
});

/* ============================================================================
   SWEEP view
   ========================================================================== */
async function loadSweep() {
  const kpis = $('#sweep-kpis');
  const list = $('#sweep-list');
  kpis.innerHTML = `<div class="kpi"><div class="label">Loading</div><div class="value">…</div></div>`;
  list.innerHTML = '<div style="padding:18px"><div class="skel skel-line" style="width:60%"></div><div class="skel skel-line" style="width:40%"></div></div>';
  try {
    const [d, money] = await Promise.all([api('/api/clusters'), api('/api/money-deterred')]);
    kpis.innerHTML = `
      <div class="kpi accent">
        <div class="label">Est. loss prevented</div>
        <div class="value mono">₹${num(money.est_value_protected_inr)}</div>
        <div class="foot">${esc(money.method)}</div>
      </div>
      <div class="kpi"><div class="label">Clusters neutralised</div>
        <div class="value mono">${num(money.clusters_neutralised)}</div>
        <div class="foot">campaigns confirmed malicious</div></div>
      <div class="kpi"><div class="label">People protected</div>
        <div class="value mono">${num(money.people_protected)}</div>
        <div class="foot">warned by someone else's report</div></div>
      <div class="kpi"><div class="label">Reports handled</div>
        <div class="value mono">${num(money.reports_handled)}</div>
        <div class="foot">${esc(money.note)}</div></div>`;

    if (!d.clusters.length) {
      list.innerHTML = `<div style="padding:22px"><div class="callout">
        <b>No clusters yet.</b><div class="sub">Analyse an email, then hit “Report → sweep org”.
        Two reports of the same campaign create a cluster and warn the other recipients.</div></div></div>`;
      return;
    }
    list.innerHTML = d.clusters.map((c) => {
      const t = tierOf(c.verdict);
      return `<div class="campaign">
        <div>
          <div class="subj">${esc(c.subject || '(no subject)')}</div>
          <div class="who">${esc(c.sender || '—')}</div>
          <div class="pillrow" style="margin-top:8px">
            <span class="badge ${c.verdict === 'malicious' ? 'b-critical' : c.verdict === 'suspicious' ? 'b-high' : 'b-ok'}">${esc(c.verdict || 'unknown')}</span>
            <span class="chip tiny">${esc(t.icon)} score ${esc(c.score)}</span>
            <span class="chip tiny">last seen ${esc((c.last || '').slice(0, 16).replace('T', ' '))}</span>
          </div>
        </div>
        <div class="stats">
          <div class="stat"><div class="n">${esc(c.reports)}</div><div class="l">reports</div></div>
          <div class="stat"><div class="n ${c.clicked ? 'bad' : ''}">${esc(c.clicked)}</div><div class="l">clicked</div></div>
        </div>
      </div>`;
    }).join('');
  } catch (e) {
    kpis.innerHTML = '';
    list.innerHTML = `<div style="padding:20px"><div class="callout warn">Could not load clusters: ${esc(e.message)}</div></div>`;
  }
}
$('#btn-refresh-clusters').onclick = loadSweep;

/* ------------------------------------------------------------------- start */
loadHeader();
go(location.hash.slice(1) || 'link');
