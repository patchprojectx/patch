'use strict';
/** Scan pipeline: discover manifests -> parse -> OSV match -> KEV/EPSS enrichment -> findings. */
const fs = require('fs');
const path = require('path');
const parsers = require('./parsers');
const osv = require('./osv');
const intel = require('./intel');
const runtimes = require('./runtimes');
const core = require('./core');

async function scan(opts = {}) {
  const dir = path.resolve(opts.dir || '.');
  const startedAt = new Date().toISOString();
  const errors = [];
  const files = opts.files ? opts.files.map((f) => path.resolve(dir, f)) : parsers.discover(dir, { maxDepth: opts.maxDepth ?? 4 });
  const byKey = new Map(); const fileSummaries = [];
  for (const f of files) {
    let pkgs = [];
    try { pkgs = parsers.parseFile(f); } catch (e) { errors.push({ file: rel(dir, f), error: e.message }); continue; }
    fileSummaries.push({ path: rel(dir, f), packages: pkgs.length });
    for (const p of pkgs) {
      if (p.dev && !opts.includeDev) continue;
      const k = p.ecosystem + '|' + core.normName(p.ecosystem, p.name) + '|' + p.version;
      const cur = byKey.get(k);
      if (cur) { if (!cur.sources.includes(rel(dir, f))) cur.sources.push(rel(dir, f)); cur.dev = cur.dev && !!p.dev; cur.direct = cur.direct || !!p.direct; }
      else byKey.set(k, { ...p, sources: [rel(dir, f)] });
    }
  }
  // runtimes
  let detected = {};
  if (opts.runtimes && typeof opts.runtimes === 'object') detected = opts.runtimes;
  else if (opts.runtimes !== 'off' && opts.runtimes !== false) detected = runtimes.detect();
  if (detected.go) byKey.set('Go|stdlib|' + detected.go, { ecosystem: 'Go', name: 'stdlib', version: detected.go, sources: ['runtime:go'], runtime: true });

  const packages = [...byKey.values()];
  let ids = [];
  if (packages.length) {
    const res = await osv.queryBatch(packages);
    res.forEach((list, i) => { packages[i].vulnIds = list; });
    ids = [...new Set(res.flat())];
  }
  const details = ids.length ? await osv.getVulns(ids) : new Map();

  let kev = null;
  try { kev = await intel.loadKev({ cacheDir: opts.cacheDir }); } catch (e) { errors.push({ source: 'cisa-kev', error: e.message }); }

  const findings = [];
  for (const p of packages) {
    for (const id of p.vulnIds || []) {
      const v = details.get(id);
      if (!v) { errors.push({ source: 'osv', error: 'missing details for ' + id }); continue; }
      if (v.withdrawn) continue;
      const sev = core.severityOf(v);
      const cves = core.cvesOf(v);
      const kevHits = kev ? cves.filter((c) => kev.byCve.has(c)).map((c) => ({ cve: c, ...kev.byCve.get(c) })) : [];
      findings.push({
        kind: p.runtime ? 'runtime' : 'dependency', ecosystem: p.ecosystem, name: p.name, version: p.version, dev: !!p.dev, direct: !!p.direct,
        sources: p.sources, source: p.sources[0], id: v.id, aliases: v.aliases || [], cves, summary: v.summary || firstLine(v.details),
        severity: sev.label, score: sev.score, kev: kevHits.length ? kevHits : null, epss: null,
        fixed: core.fixedFor(v, p), published: v.published || null, modified: v.modified || null,
        references: ['https://osv.dev/vulnerability/' + v.id, ...(v.references || []).filter((r) => r.type === 'ADVISORY' || r.type === 'FIX').map((r) => r.url).slice(0, 3)],
      });
    }
  }
  // Go is matched live through OSV (Go/stdlib); node and php use the curated runtime table.
  for (const f of runtimes.evaluate(Object.fromEntries(Object.entries(detected).filter(([k]) => k !== 'go')))) {
    f.kev = kev ? f.cves.filter((c) => kev.byCve.has(c)).map((c) => ({ cve: c, ...kev.byCve.get(c) })) : null;
    if (f.kev && !f.kev.length) f.kev = null;
    findings.push(f);
  }
  let epssAvailable = false;
  if (opts.epss !== false) {
    const cves = [...new Set(findings.flatMap((f) => f.cves))];
    if (cves.length) {
      try { const m = await intel.loadEpss(cves); epssAvailable = true; for (const f of findings) { const s = f.cves.map((c) => m.get(c)).filter(Boolean).sort((a, b) => b.epss - a.epss)[0]; f.epss = s ? s.epss : null; f.epssPercentile = s ? s.percentile : null; } }
      catch (e) { errors.push({ source: 'epss', error: e.message }); }
    }
  }
  findings.sort((a, b) => (!!b.kev - !!a.kev) || (core.RANK[b.severity] - core.RANK[a.severity]) || ((b.epss || 0) - (a.epss || 0)) || a.name.localeCompare(b.name));
  return {
    tool: { name: 'patchnow', version: require('../package.json').version }, dir, startedAt, finishedAt: new Date().toISOString(),
    files: fileSummaries, runtimes: detected, packagesScanned: packages.length,
    intel: { kev: kev ? { catalogVersion: kev.catalogVersion, count: kev.count, from: kev.from } : null, epss: epssAvailable },
    findings, errors,
  };
}
const rel = (dir, f) => path.relative(dir, f) || path.basename(f);
const firstLine = (s) => (s || '').split('\n')[0].slice(0, 200);
module.exports = { scan };
