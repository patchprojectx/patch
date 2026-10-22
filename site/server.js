// PATCH site: a small zero-dependency server. It serves the static files and cached proxies for
// NVD (CVE API 2.0) and the CISA KEV catalog (which sends no CORS headers,
// so a static site cannot read it directly). Node >= 18 (global fetch).
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT) || 4970;
const HOST = process.env.HOST || '0.0.0.0';
const SITE_URL = (process.env.SITE_URL || 'https://patchproject.xyz').replace(/\/+$/, '');
const ROOT = path.join(__dirname, 'public');
const NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const NVD_KEY = process.env.NVD_API_KEY || '';
const REFRESH_MS = 15 * 60 * 1000;
const NVD_GAP_MS = NVD_KEY ? 1200 : 6500; // NVD public rate limit: 5 req / 30 s without a key

const volume = require('./lib/volume');
const VOLUME_FILE = path.join(__dirname, '.cache', 'volume.json');
const VOLUME_SEED = path.join(__dirname, 'data', 'volume-seed.json');
// Fresh checkout / ephemeral disk: start from the committed seed of completed years so only the current year is fetched.
if (!fs.existsSync(VOLUME_FILE) && fs.existsSync(VOLUME_SEED)) {
  try { fs.mkdirSync(path.dirname(VOLUME_FILE), { recursive: true }); fs.copyFileSync(VOLUME_SEED, VOLUME_FILE); } catch (e) { console.error('[volume] seed copy failed:', e.message); }
}
const cache = { pulse: null, critical: null, kev: null, volume: null, errors: {} };
{ const v = volume.summarize(volume.load(VOLUME_FILE)); if (v.years.length) cache.volume = v; }

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let nvdChain = Promise.resolve();
function nvd(params) {
  const run = async () => {
    const url = NVD + '?' + new URLSearchParams(params).toString();
    let lastErr;
    for (let i = 0; i < 3; i++) {
      try {
        const res = await fetch(url, { headers: NVD_KEY ? { apiKey: NVD_KEY } : {}, signal: AbortSignal.timeout(60000) });
        if (!res.ok) throw new Error('NVD HTTP ' + res.status);
        const json = await res.json();
        await sleep(NVD_GAP_MS);
        return json;
      } catch (e) { lastErr = e; await sleep(NVD_GAP_MS * 2); }
    }
    throw lastErr;
  };
  const p = nvdChain.then(run, run);
  nvdChain = p.catch(() => {});
  return p;
}
const iso = (d) => d.toISOString().replace(/\.\d{3}Z$/, '.000Z');
const asUTC = (s) => new Date(/Z|[+-]\d\d:\d\d$/.test(s) ? s : s + 'Z');

function bestMetric(m = {}) {
  for (const k of ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30']) {
    const arr = m[k];
    if (arr && arr.length) {
      const pick = arr.find((x) => x.type === 'Primary') || arr[0];
      return { version: pick.cvssData.version, score: pick.cvssData.baseScore, severity: pick.cvssData.baseSeverity, source: pick.source };
    }
  }
  return null;
}

async function refreshPulse() {
  const now = new Date();
  const start = new Date(now - 24 * 3600e3);
  const hourly = new Array(24).fill(0);
  let total = 0, idx = 0, latest = null;
  do {
    const j = await nvd({ pubStartDate: iso(start), pubEndDate: iso(now), resultsPerPage: 2000, startIndex: idx });
    total = j.totalResults;
    for (const v of j.vulnerabilities) {
      const age = (now - asUTC(v.cve.published)) / 3600e3;
      const b = 23 - Math.min(23, Math.max(0, Math.floor(age)));
      hourly[b]++;
      if (!latest || asUTC(v.cve.published) > asUTC(latest.published)) latest = { id: v.cve.id, published: v.cve.published };
    }
    idx += j.resultsPerPage || 2000;
  } while (idx < total);
  const d30 = await nvd({ pubStartDate: iso(new Date(now - 30 * 86400e3)), pubEndDate: iso(now), resultsPerPage: 1 });
  cache.pulse = {
    window: { start: start.toISOString(), end: now.toISOString() },
    last24h: total,
    perHour: +(total / 24).toFixed(1),
    lastHour: hourly[23],
    hourly, // index 0 = 24-23h ago ... 23 = last hour
    latest: latest ? { id: latest.id, published: asUTC(latest.published).toISOString() } : null,
    last30d: d30.totalResults,
    avgPerDay30d: +(d30.totalResults / 30).toFixed(1),
    source: 'NVD CVE API 2.0 (pubStartDate/pubEndDate)',
    fetchedAt: new Date().toISOString(),
  };
}

async function refreshCritical() {
  const now = new Date();
  const start = new Date(now - 7 * 86400e3);
  const out = new Map();
  for (const sev of ['cvssV3Severity', 'cvssV4Severity']) {
    const j = await nvd({ pubStartDate: iso(start), pubEndDate: iso(now), [sev]: 'CRITICAL', resultsPerPage: 2000 });
    for (const v of j.vulnerabilities) {
      const c = v.cve;
      const desc = (c.descriptions.find((d) => d.lang === 'en') || {}).value || '';
      out.set(c.id, { id: c.id, published: asUTC(c.published).toISOString(), status: c.vulnStatus, metric: bestMetric(c.metrics), summary: desc.replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;/g, "'").slice(0, 280) });
    }
  }
  const list = [...out.values()].sort((a, b) => b.published.localeCompare(a.published));
  cache.critical = { windowDays: 7, total: list.length, items: list.slice(0, 40), source: 'NVD CVE API 2.0, CVSS v3.x or v4.0 severity CRITICAL', fetchedAt: new Date().toISOString() };
}

async function refreshKev() {
  const res = await fetch(KEV_URL, { signal: AbortSignal.timeout(60000) });
  if (!res.ok) throw new Error('KEV HTTP ' + res.status);
  const j = await res.json();
  const v = j.vulnerabilities.slice().sort((a, b) => (b.dateAdded + b.cveID).localeCompare(a.dateAdded + a.cveID));
  cache.kev = {
    catalogVersion: j.catalogVersion, dateReleased: j.dateReleased, count: j.count,
    recent: v.slice(0, 24).map((x) => ({ cve: x.cveID, vendor: x.vendorProject, product: x.product, name: x.vulnerabilityName, added: x.dateAdded, due: x.dueDate, ransomware: x.knownRansomwareCampaignUse })),
    ids: v.map((x) => x.cveID),
    addedByYear: v.reduce((m, x) => { const y = x.dateAdded.slice(0, 4); m[y] = (m[y] || 0) + 1; return m; }, {}),
    added30d: v.filter((x) => Date.now() - Date.parse(x.dateAdded + 'T00:00:00Z') <= 30 * 86400e3).length,
    ransomwareKnown: v.filter((x) => x.knownRansomwareCampaignUse === 'Known').length,
    source: KEV_URL, fetchedAt: new Date().toISOString(),
  };
}

async function guard(name, fn) {
  try { await fn(); delete cache.errors[name]; }
  catch (e) { cache.errors[name] = String(e.message || e); console.error('[refresh]', name, e.message || e); }
}
async function refreshAll() {
  await guard('kev', refreshKev);
  await guard('pulse', refreshPulse);
  await guard('critical', refreshCritical);
  await guard('volume', async () => { cache.volume = await volume.refresh(nvd, VOLUME_FILE); });
}
refreshAll();
setInterval(refreshAll, REFRESH_MS).unref?.();

const TYPES = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.woff2': 'font/woff2', '.txt': 'text/plain; charset=utf-8', '.yml': 'text/plain; charset=utf-8', '.webmanifest': 'application/manifest+json', '.webp': 'image/webp', '.tgz': 'application/gzip', '.sha256': 'text/plain; charset=utf-8' };
const SEC = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self' https://api.osv.dev; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
};

function send(res, code, body, headers = {}) {
  res.writeHead(code, { ...SEC, ...headers });
  res.end(body);
}
function api(res, key) {
  const data = cache[key];
  if (!data) return send(res, 503, JSON.stringify({ pending: true, error: cache.errors[key] || 'warming up — first fetch in progress' }), { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'Retry-After': '10' });
  send(res, 200, JSON.stringify({ ...data, stale: !!cache.errors[key] }), { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=120' });
}

http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'Method not allowed');
  if (u.pathname === '/api/pulse') return api(res, 'pulse');
  if (u.pathname === '/api/critical') return api(res, 'critical');
  if (u.pathname === '/api/kev') return api(res, 'kev');
  if (u.pathname === '/api/volume') return api(res, 'volume');
  if (u.pathname === '/healthz') return send(res, 200, 'ok', { 'Content-Type': 'text/plain' });
  let p = decodeURIComponent(u.pathname);
  if (p.endsWith('/')) p += 'index.html';
  const file = path.normalize(path.join(ROOT, p));
  if (!file.startsWith(ROOT)) return send(res, 403, 'Forbidden');
  fs.readFile(file, (err, buf) => {
    if (err) return send(res, 404, 'Not found', { 'Content-Type': 'text/plain' });
    const ext = path.extname(file);
    if (ext === '.html') {
      // og:url / absolute og:image come from SITE_URL (default https://patchproject.xyz)
      const esc = SITE_URL.replace(/[<>"&]/g, '');
      buf = Buffer.from(buf.toString('utf8')
        .replace('<!--OG_URL-->', esc ? '<meta property="og:url" content="' + esc + '/">' : '')
        .replace(/%%SITE_URL%%/g, esc));
    }
    const longCache = ['.woff2', '.png', '.ico', '.svg', '.webp'].includes(ext);
    const dl = ext === '.tgz' ? { 'Content-Disposition': 'attachment; filename="' + path.basename(file) + '"' } : {};
    send(res, 200, req.method === 'HEAD' ? '' : buf, { 'Content-Type': TYPES[ext] || 'application/octet-stream', 'Cache-Control': longCache ? 'public, max-age=86400' : 'no-cache', ...dl });
  });
}).listen(PORT, HOST, () => console.log('PATCH listening on http://' + HOST + ':' + PORT + ' (SITE_URL ' + SITE_URL + ')'));
