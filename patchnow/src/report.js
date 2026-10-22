'use strict';
/** Output formats: text (terminal), json, sarif (2.1.0, for GitHub code scanning). */
const fs = require('fs');
const path = require('path');
const core = require('./core');

function text(result, { color = process.stdout.isTTY } = {}) {
  const c = (code, s) => (color ? '\x1b[' + code + 'm' + s + '\x1b[0m' : s);
  const red = (s) => c('31;1', s), yel = (s) => c('33', s), dim = (s) => c('2', s), grn = (s) => c('32', s), b = (s) => c('1', s);
  const L = [];
  L.push(b('patchnow ' + result.tool.version) + dim('  scan ' + result.finishedAt));
  L.push(dim('manifests: ') + (result.files.map((f) => f.path + ' (' + f.packages + ')').join(', ') || 'none found'));
  const rt = Object.entries(result.runtimes || {}).map(([k, v]) => k + ' ' + v).join(', ');
  if (rt) L.push(dim('runtimes:  ') + rt);
  L.push(dim('intel:     ') + (result.intel.kev ? 'CISA KEV ' + result.intel.kev.catalogVersion + ' (' + result.intel.kev.count + ' entries)' : 'CISA KEV unavailable') + ' · EPSS ' + (result.intel.epss ? 'available' : 'unavailable'));
  L.push('');
  const f = result.findings;
  if (!f.length) { L.push(grn('No known vulnerabilities in ' + result.packagesScanned + ' package versions.')); }
  else {
    const kevN = f.filter((x) => x.kev).length;
    L.push(b(f.length + ' finding' + (f.length > 1 ? 's' : '')) + ' in ' + new Set(f.map((x) => x.ecosystem + x.name + x.version)).size + ' package versions' + (kevN ? ' · ' + red(kevN + ' known exploited (KEV)') : ''));
    L.push('');
    const rows = [['SEVERITY', 'CVSS', 'KEV', 'EPSS', 'PACKAGE', 'VERSION', 'FIXED IN', 'ID', 'SOURCE']];
    for (const x of f) rows.push([x.severity, x.score != null ? x.score.toFixed(1) : '-', x.kev ? 'YES' : '-', x.epss != null ? x.epss.toFixed(3) : '-', x.name, x.version, x.fixed || (x.eol ? 'EOL' : '-'), x.kev ? x.kev[0].cve : (x.cves[0] || x.id), x.source]);
    const w = rows[0].map((_, i) => Math.min(48, Math.max(...rows.map((r) => String(r[i]).length))));
    rows.forEach((r, ri) => {
      let line = r.map((cell, i) => String(cell).slice(0, w[i]).padEnd(w[i])).join('  ');
      if (ri === 0) line = dim(line); else if (f[ri - 1].kev) line = red(line); else if (f[ri - 1].severity === 'CRITICAL') line = yel(line);
      L.push(line);
    });
  }
  if (result.errors.length) { L.push(''); for (const e of result.errors) L.push(yel('warning: ') + (e.file || e.source) + ': ' + e.error); }
  return L.join('\n') + '\n';
}

function sarif(result) {
  const rules = new Map(); const results = [];
  for (const f of result.findings) {
    if (!rules.has(f.id)) rules.set(f.id, {
      id: f.id, name: f.id.replace(/[^A-Za-z0-9]/g, ''), shortDescription: { text: (f.summary || f.id).slice(0, 1000) },
      helpUri: f.references[0], properties: { tags: ['security', f.ecosystem].concat(f.kev ? ['known-exploited'] : []), 'security-severity': String(f.score ?? ({ CRITICAL: 9.5, HIGH: 8, MODERATE: 5.5, LOW: 2, UNRATED: 5 })[f.severity]) },
    });
    const level = f.kev || f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'error' : f.severity === 'MODERATE' ? 'warning' : 'note';
    const msg = f.name + '@' + f.version + ' is affected by ' + f.id + (f.cves.length ? ' (' + f.cves.join(', ') + ')' : '') + '. ' + (f.kev ? 'Listed in CISA KEV (known exploited, added ' + f.kev[0].dateAdded + '). ' : '') + (f.fixed ? 'Fixed in ' + f.fixed + '.' : 'No fixed version published.');
    const uri = f.source && !f.source.startsWith('runtime:') ? f.source.split(path.sep).join('/') : 'patch.yml';
    results.push({ ruleId: f.id, level, message: { text: msg }, locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: lineOf(result.dir, uri, f.name) } } }], partialFingerprints: { 'patchnow/v1': [f.ecosystem, f.name, f.version, f.id].join('|') } });
  }
  return { $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0', runs: [{ tool: { driver: { name: 'patchnow', version: result.tool.version, informationUri: 'https://osv.dev', rules: [...rules.values()] } }, results }] };
}
function lineOf(dir, uri, name) {
  try { const lines = fs.readFileSync(path.join(dir, uri), 'utf8').split('\n'); const i = lines.findIndex((l) => l.includes(name)); return i >= 0 ? i + 1 : 1; } catch { return 1; }
}
module.exports = { text, sarif };
