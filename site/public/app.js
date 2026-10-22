/* PATCH site client. No dependencies, no tracking. Matching logic comes from patchnow (js/patchnow-browser.js). */
(() => {
'use strict';
const Core = window.PatchCore, Parsers = window.PatchParsers;
const $ = (s, r = document) => r.querySelector(s);
const el = (tag, cls, txt) => { const e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; };
const svg = (tag, attrs) => { const e = document.createElementNS('http://www.w3.org/2000/svg', tag); for (const k in attrs) e.setAttribute(k, attrs[k]); return e; };
const OSV = 'https://api.osv.dev/v1';
const fmtN = (n) => Number(n).toLocaleString('en-US');
const fmtTime = (iso) => new Date(iso).toLocaleString([], { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', timeZoneName: 'short' });
const fmtClock = (iso) => new Date(iso).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit', timeZoneName: 'short' });
const nvdLink = (id) => 'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(id);
const link = (text, href, cls) => { const a = el('a', cls || '', text); a.href = href; a.target = '_blank'; a.rel = 'noopener'; return a; };
const td = (content, cls) => { const c = el('td', cls || ''); if (content instanceof Node) c.appendChild(content); else c.textContent = content == null ? '' : content; return c; };

async function getJSON(url, tries = 8) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(url, { cache: 'no-store' });
      if (r.status === 503) { await new Promise((ok) => setTimeout(ok, 5000)); continue; }
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return await r.json();
    } catch (e) { if (i === tries - 1) throw e; await new Promise((ok) => setTimeout(ok, 3000)); }
  }
  throw new Error('feed still warming up');
}

/* ---------- KEV ---------- */
let kevSet = new Set();
const ADV_CVES = ['CVE-2026-109618', 'CVE-2026-109619', 'CVE-2026-110264', 'CVE-2026-111497'];
const kevReady = getJSON('/api/kev', 120).then((k) => {
  kevSet = new Set(k.ids);
  $('#kevCount').textContent = fmtN(k.count);
  $('#kevVer').textContent = 'catalog ' + k.catalogVersion;
  $('#kev30').textContent = fmtN(k.added30d);
  $('#kevRw').textContent = 'ransomware: ' + fmtN(k.ransomwareKnown); $('#kevRw').title = fmtN(k.ransomwareKnown) + ' catalog entries with known use in ransomware campaigns';
  $('#kevMeta').textContent = 'catalog ' + k.catalogVersion + ' · ' + fmtN(k.count) + ' entries';
  const body = $('#kevList'); body.textContent = '';
  k.recent.slice(0, 12).forEach((x) => {
    const tr = el('tr');
    tr.append(td(x.added), td(link(x.cve, nvdLink(x.cve))), td(x.vendor + ' · ' + x.product), td(x.name, 'wrap'), td(x.due), td(x.ransomware === 'Known' ? el('span', 'flag rw', 'KNOWN') : el('span', 'dim', '—')));
    body.appendChild(tr);
  });
  const hits = ADV_CVES.filter((c) => kevSet.has(c));
  if (hits.length) { const n = $('#advKev'); n.textContent = 'Now on CISA KEV (catalog ' + k.catalogVersion + '): ' + hits.join(', ') + '. Treat as exploited.'; n.classList.add('yes'); }
  return k;
}).catch((e) => { $('#kevMeta').textContent = 'feed unavailable: ' + e.message; $('#kevList').textContent = ''; });

/* ---------- pulse ---------- */
let pulse = null;
function renderPulse(p) {
  $('#c24').textContent = fmtN(p.last24h);
  $('#cph').textContent = p.perHour.toFixed(1);
  $('#clh').textContent = fmtN(p.lastHour);
  $('#c30').textContent = fmtN(Math.round(p.avgPerDay30d));
  $('#c30s').textContent = fmtN(p.last30d) + ' in 30 days';
  $('#pulse-asof').textContent = 'NVD synced ' + fmtClock(p.fetchedAt);
  $('#feedDot').className = 'dot live';
  if (p.latest) { const n = $('#newest'); n.textContent = ''; n.appendChild(link(p.latest.id, nvdLink(p.latest.id))); $('#newestAt').textContent = fmtTime(p.latest.published); }
  const s = $('#spark'); s.textContent = '';
  const max = Math.max(...p.hourly, 1), peak = p.hourly.indexOf(max), W = 240 / 24;
  p.hourly.forEach((v, i) => {
    const h = v ? Math.max(1.5, (v / max) * 38) : 0.75;
    const r = svg('rect', { x: (i * W + 1).toFixed(2), y: (40 - h).toFixed(2), width: (W - 2).toFixed(2), height: h.toFixed(2) });
    if (i === 23) r.setAttribute('class', 'now'); else if (i === peak) r.setAttribute('class', 'pk');
    const t = svg('title', {}); t.textContent = v + ' CVEs, ' + (23 - i) + '–' + (24 - i) + ' h ago'; r.appendChild(t);
    s.appendChild(r);
  });
  $('#sparkCap').textContent = '−24h → now · peak ' + fmtN(max) + '/h';
}
getJSON('/api/pulse', 120).then((p) => { pulse = p; renderPulse(p); }).catch((e) => { $('#pulse-asof').textContent = 'NVD feed unavailable'; $('#feedDot').className = 'dot err'; });
setInterval(async () => { try { const p = await getJSON('/api/pulse', 1); pulse = p; renderPulse(p); } catch {} }, 120000);

/* ---------- critical ---------- */
getJSON('/api/critical', 120).then(async (c) => {
  await kevReady;
  $('#critMeta').textContent = fmtN(c.total) + ' in ' + c.windowDays + ' days · synced ' + fmtClock(c.fetchedAt);
  const body = $('#critList'); body.textContent = '';
  if (!c.items.length) { const tr = el('tr'); tr.appendChild(td('No critical CVEs published in the window.', 'dim')); body.appendChild(tr); }
  c.items.slice(0, 12).forEach((x) => {
    const tr = el('tr'), onKev = kevSet.has(x.id);
    tr.append(td(x.published.slice(0, 10)), td(link(x.id, nvdLink(x.id))), td(x.metric ? x.metric.score.toFixed(1) + (x.metric.version ? ' v' + x.metric.version.split('.')[0] : '') : '—', 'r'), td(onKev ? el('span', 'flag kev', 'KEV') : el('span', 'dim', '—')), td(Object.assign(el('span', 'clamp', x.summary), { title: x.summary }), 'wrap'));
    body.appendChild(tr);
  });
}).catch((e) => { $('#critMeta').textContent = 'feed unavailable: ' + e.message; $('#critList').textContent = ''; });

/* ---------- volume (NVD per year) ---------- */
getJSON('/api/volume', 200).then((v) => {
  const box = $('#volChart'); box.textContent = '';
  const years = v.years;
  const max = Math.max(...years.map((y) => y.complete ? y.count : Math.max(y.count, v.projection ? v.projection.value : 0)));
  const bars = el('div', 'vbars'), labels = el('div', 'vyears');
  years.forEach((y) => {
    const col = el('div', 'vb' + (y.complete ? '' : ' cur'));
    const proj = !y.complete && v.projection ? v.projection.value : null;
    col.appendChild(el('div', 'val', y.complete ? (y.count / 1000).toFixed(1) + 'k' : (y.count / 1000).toFixed(1) + 'k YTD'));
    if (proj && proj > y.count) { const pj = el('div', 'proj'); pj.style.height = ((proj - y.count) / max * 100).toFixed(2) + '%'; pj.title = 'Projected ' + fmtN(proj) + ' (' + v.projection.method + ')'; col.appendChild(pj); }
    const b = el('div', 'bar'); b.style.height = (y.count / max * 100).toFixed(2) + '%'; b.title = y.year + ': ' + fmtN(y.count) + ' CVE records' + (y.complete ? '' : ' through ' + y.through);
    col.appendChild(b); bars.appendChild(col);
    labels.appendChild(el('span', '', String(y.year)));
  });
  box.append(bars, labels);
  const last = years[years.length - 1], prev = years[years.length - 2];
  $('#volMeta').textContent = years[0].year + '–' + last.year;
  if (last && prev && v.projection) $('#volNote').textContent = 'Rejected records excluded. ' + last.year + ' through ' + last.through + ': ' + fmtN(last.count) + ' (' + (last.count / prev.count).toFixed(2) + '× all of ' + prev.year + '); dashed outline = linear projection to ' + fmtN(v.projection.value) + '. Source: NVD CVE API 2.0.';
}).catch((e) => { $('#volMeta').textContent = 'unavailable: ' + e.message; });

/* ---------- checker ---------- */
const KIND_NAMES = ['package-lock.json', 'npm-shrinkwrap.json', 'package.json', 'yarn.lock', 'composer.lock', 'requirements.txt', 'poetry.lock', 'go.mod', 'Cargo.lock'];
function detectKind(name, text) {
  const n = (name || '').split(/[\\/]/).pop();
  const byName = KIND_NAMES.find((k) => n === k);
  if (byName) return byName === 'npm-shrinkwrap.json' ? 'package-lock.json' : byName;
  if (/\.txt$/i.test(n)) return 'requirements.txt';
  const t = text.trim();
  if (t.startsWith('{')) {
    try { const j = JSON.parse(t); if (j.lockfileVersion || (j.packages && !Array.isArray(j.packages))) return 'package-lock.json'; if (Array.isArray(j.packages) || j['content-hash']) return 'composer.lock'; return 'package.json'; } catch { return 'invalid-json'; }
  }
  if (/^# yarn lockfile v1|^__metadata:/m.test(t)) return 'yarn.lock';
  if (/^\[\[package\]\]/m.test(t)) return /^source = "registry\+/m.test(t) || /^checksum = /m.test(t) ? 'Cargo.lock' : 'poetry.lock';
  if (/^module\s+\S+/m.test(t)) return 'go.mod';
  return 'requirements.txt';
}
const NOTES = {
  'package.json': 'package.json lists ranges, not installed versions; the lowest version each range allows was checked. Use package-lock.json for exact results.',
  'requirements.txt': 'Only exact pins (name==version) can be checked; other lines are skipped.',
  'go.mod': 'The Go standard library was checked at the version in the toolchain/go directive (a minimum); your actual toolchain may be newer. Use the runtime check below.',
};
function parse(kind, text) {
  const fn = Parsers.KINDS[kind]; if (!fn) throw new Error('Unsupported format: ' + kind);
  let pkgs = fn(text);
  if (kind === 'go.mod') { const g = Parsers.go.parseGoMod(text); const v = g.toolchain || g.goVersion; if (v) pkgs = pkgs.concat([{ ecosystem: 'Go', name: 'stdlib', version: v.split('.').length === 2 ? v + '.0' : v, approx: true }]); }
  const seen = new Set();
  return pkgs.filter((p) => { const k = p.ecosystem + '|' + p.name + '|' + p.version; if (seen.has(k)) return false; seen.add(k); return true; });
}
const results = $('#results'), rStatus = $('#rStatus'), rStats = $('#rStats'), rList = $('#rList'), rTable = $('#rTable'), rNote = $('#rNote');
function status(cls, text, spin) { rStatus.className = 'r-status ' + (cls || ''); rStatus.textContent = ''; if (spin) rStatus.appendChild(el('span', 'spin')); rStatus.appendChild(el('span', '', text)); }
async function pool(items, n, fn) { let i = 0; await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) { const k = i++; await fn(items[k]); } })); }
let scanning = false;
async function scan(text, name, kindSel) {
  if (scanning) return; scanning = true; $('#scan').disabled = true;
  results.hidden = false; rStats.textContent = ''; rList.textContent = ''; rTable.hidden = true; rNote.textContent = '';
  status('', 'Parsing in your browser…', true);
  try {
    if (!text.trim()) throw new Error('Paste a lockfile or drop one above.');
    const kind = kindSel && kindSel !== 'auto' ? kindSel : detectKind(name, text);
    if (kind === 'invalid-json') throw new Error('That looks like JSON but does not parse.');
    const pkgs = parse(kind, text);
    if (!pkgs.length) throw new Error('No package versions found in that ' + kind + '.');
    status('', 'Querying OSV.dev for ' + fmtN(pkgs.length) + ' packages (name and version only)…', true);
    const hits = [];
    for (let i = 0; i < pkgs.length; i += 500) {
      const b = pkgs.slice(i, i + 500);
      const r = await fetch(OSV + '/querybatch', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ queries: b.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })) }) });
      if (!r.ok) throw new Error('OSV.dev returned HTTP ' + r.status);
      const j = await r.json(); j.results.forEach((res, k) => { if (res.vulns && res.vulns.length) hits.push({ pkg: b[k], ids: res.vulns.map((v) => v.id) }); });
    }
    const ids = [...new Set(hits.flatMap((h) => h.ids))], CAP = 400;
    status('', 'Fetching ' + fmtN(Math.min(ids.length, CAP)) + ' advisories and checking CISA KEV…', true);
    await kevReady;
    const details = new Map();
    await pool(ids.slice(0, CAP), 12, async (id) => { try { const r = await fetch(OSV + '/vulns/' + encodeURIComponent(id)); if (r.ok) details.set(id, await r.json()); } catch {} });
    const rows = hits.map(({ pkg, ids }) => {
      const advs = ids.map((id) => {
        const v = details.get(id);
        if (!v) return { id, label: 'UNRATED', score: null, summary: '(details not fetched)', cves: [], kev: [], fixed: null };
        const sv = Core.severityOf(v), cves = Core.cvesOf(v);
        return { id, label: sv.label, score: sv.score, summary: v.summary || (v.details || '').split('\n')[0].slice(0, 200), cves, kev: cves.filter((c) => kevSet.has(c)), fixed: Core.fixedFor(v, pkg) };
      }).sort((a, b) => (b.kev.length - a.kev.length) || (Core.RANK[b.label] - Core.RANK[a.label]) || ((b.score || 0) - (a.score || 0)));
      return { pkg, advs, kev: advs.some((a) => a.kev.length), top: Core.RANK[advs[0].label], upgrade: Core.upgradeTarget(advs.map((a) => a.fixed)) };
    }).sort((a, b) => (b.kev - a.kev) || (b.top - a.top) || (b.advs.length - a.advs.length));
    const kevPkgs = rows.filter((r) => r.kev).length, crit = rows.filter((r) => r.advs.some((a) => a.label === 'CRITICAL')).length;
    [['', pkgs.length, 'packages scanned'], ['', rows.length, 'vulnerable'], ['', ids.length, 'advisories'], ['crit', crit, 'with a critical'], ['kev', kevPkgs, 'known exploited (KEV)']].forEach(([c, n, l]) => { const d = el('div', c); d.append(el('b', '', fmtN(n)), el('span', '', l)); rStats.appendChild(d); });
    if (kevPkgs) status('bad', kevPkgs + ' package' + (kevPkgs > 1 ? 's are' : ' is') + ' affected by a vulnerability CISA lists as exploited in the wild. Patch these first.');
    else if (rows.length) status('warn', rows.length + ' vulnerable package' + (rows.length > 1 ? 's' : '') + '. None is currently on CISA KEV.');
    else status('good', 'No known vulnerabilities in these ' + fmtN(pkgs.length) + ' package versions (OSV.dev, ' + new Date().toLocaleString() + ').');
    rows.forEach((r, ri) => {
      const top = r.advs[0], kevN = r.advs.filter((a) => a.kev.length).length;
      const tr = el('tr', 'pkg'); tr.tabIndex = 0;
      const pn = el('span', '', r.pkg.name); const pc = el('td'); pc.appendChild(pn); pc.appendChild(el('span', 'pv', '@' + r.pkg.version)); if (r.kev) { pc.appendChild(document.createTextNode(' ')); pc.appendChild(el('span', 'flag kev', 'KEV')); }
      const meta = [r.pkg.ecosystem, r.pkg.dev ? 'dev' : '', r.pkg.indirect ? 'indirect' : '', r.pkg.approx ? 'min' : ''].filter(Boolean).join(' · ');
      tr.append(td(el('span', 'sev ' + top.label, top.label + (top.score != null ? ' ' + top.score.toFixed(1) : ''))), pc, td(r.pkg.version + '  ' + meta), td(String(r.advs.length), 'r'), td(String(kevN), 'r' + (kevN ? ' yes' : '')), td(r.upgrade ? '≥ ' + r.upgrade : 'no fix listed', r.upgrade ? 'fix' : 'nofix'), td('+'));
      const ex = el('tr', 'advs'); ex.hidden = !(r.kev && ri === 0); const cell = el('td'); cell.colSpan = 7; const list = el('div', 'adv-list');
      r.advs.forEach((a) => {
        const sc = el('span'); sc.appendChild(el('span', 'sev ' + a.label, a.label + (a.score != null ? ' ' + a.score.toFixed(1) : ''))); list.appendChild(sc);
        const idc = el('span'); idc.appendChild(link(a.kev.length ? a.kev[0] : (a.cves[0] || a.id), 'https://osv.dev/vulnerability/' + encodeURIComponent(a.id))); if (a.kev.length) { idc.appendChild(document.createTextNode(' ')); idc.appendChild(el('span', 'flag kev', 'KEV')); }
        list.append(idc, el('span', 'sum', a.summary || a.id), el('span', 'fx', a.fixed ? 'fixed ' + a.fixed : 'no fix'));
      });
      cell.appendChild(list); ex.appendChild(cell);
      tr.lastChild.textContent = ex.hidden ? '+' : '−';
      const toggle = () => { ex.hidden = !ex.hidden; tr.lastChild.textContent = ex.hidden ? '+' : '−'; };
      tr.addEventListener('click', toggle); tr.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
      rList.append(tr, ex);
    });
    rTable.hidden = !rows.length;
    rNote.textContent = [NOTES[kind], ids.length > CAP ? 'Details shown for the first ' + CAP + ' advisories.' : '', 'Severity: GitHub advisory rating, else CVSS v3 base score. "Upgrade to" is the smallest version that clears every listed advisory. The CLI excludes dev dependencies by default; this checker shows them, marked "dev".'].filter(Boolean).join(' ');
  } catch (e) { status('bad', e.message || String(e)); }
  finally { scanning = false; $('#scan').disabled = false; }
}
const drop = $('#drop'), file = $('#file');
drop.addEventListener('click', () => file.click());
drop.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); file.click(); } });
['dragenter', 'dragover'].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add('over'); }));
['dragleave', 'drop'].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove('over'); }));
async function handleFiles(files) { const f = files && files[0]; if (!f) return; if (f.size > 25e6) return status('bad', 'File too large (25 MB limit).'); const t = await f.text(); $('#paste').value = t.length > 200000 ? t.slice(0, 200000) + '\n… (' + fmtN(t.length) + ' characters; showing the start)' : t; $('#pasteKind').value = 'auto'; scan(t, f.name, 'auto'); }
drop.addEventListener('drop', (e) => handleFiles(e.dataTransfer.files));
file.addEventListener('change', () => handleFiles(file.files));
$('#scan').addEventListener('click', () => scan($('#paste').value, '', $('#pasteKind').value));
$('#sample').addEventListener('click', async () => { const t = await (await fetch('/sample-package-lock.json')).text(); $('#paste').value = t; $('#pasteKind').value = 'package-lock.json'; scan(t, 'package-lock.json', 'package-lock.json'); });

/* ---------- runtime check (patchnow runtime-advisories table) ---------- */
const RT = { rtNode: 'node', rtPhp: 'php', rtGo: 'go', rtGl: 'gitlab' };
Object.entries(RT).forEach(([id, runtime]) => {
  const inp = $('#' + id), out = $('#' + id + 'Out');
  inp.addEventListener('input', () => {
    const raw = inp.value.trim(); out.className = '';
    if (!raw) { out.textContent = ''; return; }
    const r = Core.checkRuntime(Parsers.runtimeAdvisories, runtime, raw);
    if (!r || r.status === 'unknown') { out.className = 'warn'; out.textContent = 'Enter a version such as 1.2.3.'; return; }
    const a = r.advisory;
    if (r.status === 'patched') { out.className = 'ok'; out.textContent = 'Patched (' + r.fixed + ' or later on this line).'; }
    else if (r.status === 'vulnerable') { out.className = 'bad'; out.textContent = 'Vulnerable. Upgrade to ' + r.fixed + '.' + (a.note ? ' ' + a.note : ''); }
    else if (r.status === 'eol') { out.className = 'bad'; out.textContent = a.eolMessage; }
    else { out.className = 'ok'; out.textContent = 'Newer than these fixes. Check the vendor for later advisories.'; }
    out.title = a.title;
  });
});

/* ---------- misc ---------- */
$('#copyYaml').addEventListener('click', async () => { try { await navigator.clipboard.writeText($('#yamlSrc').textContent); $('#copyYaml').textContent = 'Copied'; setTimeout(() => ($('#copyYaml').textContent = 'Copy'), 1600); } catch {} });
})();
