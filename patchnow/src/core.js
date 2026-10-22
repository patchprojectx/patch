/*
 * patchnow core — pure, dependency-free matching semantics shared by the CLI
 * and the in-browser checker (loaded as window.PatchCore on the site).
 * Version ordering, OSV range evaluation, fixed-version selection, severity.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.PatchCore = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /* ---------- versions ---------- */
  function parseVersion(v) {
    let s = String(v == null ? '' : v).trim().replace(/^[vV=]/, '').replace(/\+.*$/, '');
    const m = s.match(/^(\d+(?:\.\d+)*)(.*)$/);
    if (!m) return { nums: [], rest: s.toLowerCase(), post: false };
    const nums = m[1].split('.').map((x) => parseInt(x, 10));
    let rest = m[2].replace(/^[-.]/, '').toLowerCase();
    const post = /^(post|\.post|-post|p\d|pl\d)/.test(m[2].replace(/^[-.]/, '').toLowerCase()) || /^post/.test(rest);
    if (post) rest = '';
    return { nums, rest, post };
  }
  function cmpIdent(a, b) {
    const pa = a.split(/[.\-]/), pb = b.split(/[.\-]/);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const x = pa[i], y = pb[i];
      if (x === undefined) return -1;
      if (y === undefined) return 1;
      const nx = /^\d+$/.test(x), ny = /^\d+$/.test(y);
      if (nx && ny) { const d = parseInt(x, 10) - parseInt(y, 10); if (d) return d < 0 ? -1 : 1; continue; }
      if (nx !== ny) return nx ? -1 : 1;
      // split alpha+digits like "rc10" vs "rc2"
      const ax = x.match(/^([a-z]*)(\d*)$/), ay = y.match(/^([a-z]*)(\d*)$/);
      if (ax && ay && ax[1] === ay[1] && ax[2] && ay[2]) { const d = parseInt(ax[2], 10) - parseInt(ay[2], 10); if (d) return d < 0 ? -1 : 1; continue; }
      if (x !== y) return x < y ? -1 : 1;
    }
    return 0;
  }
  /** Compare two version strings. Semver-compatible; tolerant of PEP 440 / Go / Composer forms. */
  function cmpVer(a, b) {
    if (a === b) return 0;
    const A = parseVersion(a), B = parseVersion(b);
    const n = Math.max(A.nums.length, B.nums.length);
    for (let i = 0; i < n; i++) {
      const x = A.nums[i] || 0, y = B.nums[i] || 0;
      if (x !== y) return x < y ? -1 : 1;
    }
    if (A.post !== B.post) return A.post ? 1 : -1;
    if (!A.rest && !B.rest) return 0;
    if (!A.rest) return 1;   // release > prerelease
    if (!B.rest) return -1;
    return cmpIdent(A.rest, B.rest);
  }

  /* ---------- OSV ranges ---------- */
  /** Is `version` inside one OSV range object ({type, events}) ? GIT ranges are not evaluated. */
  function inRange(range, version) {
    if (!range || range.type === 'GIT') return null;
    const evs = (range.events || []).slice().sort((x, y) => {
      const vx = x.introduced ?? x.fixed ?? x.last_affected ?? x.limit, vy = y.introduced ?? y.fixed ?? y.last_affected ?? y.limit;
      if (vx === '0') return -1; if (vy === '0') return 1;
      return cmpVer(vx, vy);
    });
    let affected = false;
    for (const e of evs) {
      if (e.introduced !== undefined && (e.introduced === '0' || cmpVer(version, e.introduced) >= 0)) affected = true;
      else if (e.fixed !== undefined && cmpVer(version, e.fixed) >= 0) affected = false;
      else if (e.last_affected !== undefined && cmpVer(version, e.last_affected) > 0) affected = false;
    }
    return affected;
  }
  const normName = (eco, n) => {
    const s = String(n || '');
    if (eco === 'PyPI') return s.toLowerCase().replace(/[-_.]+/g, '-');
    if (eco === 'Packagist' || eco === 'npm') return s.toLowerCase();
    return s;
  };
  function affectedEntries(vuln, pkg) {
    return (vuln.affected || []).filter((a) => a.package && a.package.ecosystem === pkg.ecosystem && normName(pkg.ecosystem, a.package.name) === normName(pkg.ecosystem, pkg.name));
  }
  /** Local re-evaluation of whether an OSV record affects pkg@version (OSV querybatch is authoritative; this is used for tests/offline). */
  function isAffected(vuln, pkg) {
    for (const a of affectedEntries(vuln, pkg)) {
      if ((a.versions || []).includes(pkg.version)) return true;
      for (const r of a.ranges || []) if (inRange(r, pkg.version)) return true;
    }
    return false;
  }
  /**
   * Smallest fixed version greater than the current version, preferring fixes from the
   * range(s) that actually contain the current version. Returns null if none is published.
   */
  function fixedFor(vuln, pkg) {
    const own = [], any = [];
    for (const a of affectedEntries(vuln, pkg)) {
      for (const r of a.ranges || []) {
        if (r.type === 'GIT') continue;
        const hit = inRange(r, pkg.version);
        for (const e of r.events || []) if (e.fixed && cmpVer(e.fixed, pkg.version) > 0) (hit ? own : any).push(e.fixed);
      }
    }
    const pick = (own.length ? own : any).sort(cmpVer);
    return pick[0] || null;
  }
  /** Highest of the per-vulnerability minimum fixes: the one version that clears every listed vuln. */
  function upgradeTarget(fixes) {
    const f = fixes.filter(Boolean).sort(cmpVer);
    return f.length ? f[f.length - 1] : null;
  }

  /* ---------- severity ---------- */
  function cvss3(vec) {
    if (!/^CVSS:3\.[01]\//.test(vec || '')) return null;
    const m = {}; vec.split('/').slice(1).forEach((p) => { const [k, v] = p.split(':'); m[k] = v; });
    const AV = { N: .85, A: .62, L: .55, P: .2 }[m.AV], AC = { L: .77, H: .44 }[m.AC], UI = { N: .85, R: .62 }[m.UI], changed = m.S === 'C';
    const PR = { N: .85, L: changed ? .68 : .62, H: changed ? .5 : .27 }[m.PR];
    const CIA = (x) => ({ H: .56, L: .22, N: 0 }[x]);
    if ([AV, AC, UI, PR, CIA(m.C), CIA(m.I), CIA(m.A)].some((x) => x == null)) return null;
    const iss = 1 - (1 - CIA(m.C)) * (1 - CIA(m.I)) * (1 - CIA(m.A));
    const imp = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
    const ex = 8.22 * AV * AC * PR * UI;
    if (imp <= 0) return 0;
    const up = (x) => { const i = Math.round(x * 100000); return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10; };
    return changed ? up(Math.min(1.08 * (imp + ex), 10)) : up(Math.min(imp + ex, 10));
  }
  const LEVELS = ['UNRATED', 'LOW', 'MODERATE', 'HIGH', 'CRITICAL'];
  const RANK = { UNRATED: 0, LOW: 1, MODERATE: 2, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
  const bucket = (s) => (s == null ? 'UNRATED' : s >= 9 ? 'CRITICAL' : s >= 7 ? 'HIGH' : s >= 4 ? 'MODERATE' : s > 0 ? 'LOW' : 'UNRATED');
  /** {label, score}: advisory label (GitHub database_specific.severity) if present, else CVSS v3 base score bucket. */
  function severityOf(v) {
    let score = null;
    for (const s of v.severity || []) if (/^CVSS_V3/.test(s.type)) { score = cvss3(s.score); if (score != null) break; }
    const ds = v.database_specific && v.database_specific.severity;
    let label = ds ? String(ds).toUpperCase() : bucket(score);
    if (label === 'MEDIUM') label = 'MODERATE';
    if (!(label in RANK)) label = bucket(score);
    return { label, score };
  }
  const cvesOf = (v) => [v.id, ...(v.aliases || [])].filter((x) => /^CVE-\d{4}-\d+$/.test(x)).filter((x, i, a) => a.indexOf(x) === i);

  /* ---------- runtime advisories (curated table; see data/runtime-advisories.json) ---------- */
  function checkRuntime(table, runtime, version) {
    const t = table.find((x) => x.runtime === runtime);
    if (!t) return null;
    const v = String(version).trim().replace(/^v|^go/i, '');
    const m = v.match(/^(\d+)\.(\d+)(?:\.(\d+))?/);
    if (!m) return { status: 'unknown', message: 'unrecognized version' };
    const full = [m[1], m[2], m[3] || '0'].join('.');
    const line = t.lineKey === 'major' ? m[1] : m[1] + '.' + m[2];
    const fixed = t.fixed[line];
    if (fixed) return cmpVer(full, fixed) >= 0
      ? { status: 'patched', fixed, advisory: t }
      : { status: 'vulnerable', fixed, advisory: t };
    if (cmpVer(full, t.newerThan) > 0) return { status: 'newer', advisory: t };
    return { status: 'eol', advisory: t, message: t.eolMessage };
  }

  return { cmpVer, inRange, isAffected, fixedFor, upgradeTarget, cvss3, severityOf, bucket, RANK, LEVELS, cvesOf, normName, checkRuntime };
});
