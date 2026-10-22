'use strict';
/** Runtime detection (node, php, go) and evaluation against the curated runtime advisory table. */
const { execFileSync } = require('child_process');
const core = require('./core');
const TABLE = require('./data/runtime-advisories.json');

function sh(cmd, args) { try { return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000 }).trim(); } catch { return null; } }
function detect() {
  const out = {};
  const n = sh('node', ['-v']); if (n) out.node = n.replace(/^v/, '');
  const p = sh('php', ['-r', 'echo PHP_VERSION;']); if (p && /^\d/.test(p)) out.php = p;
  const g = sh('go', ['env', 'GOVERSION']); if (g && /^go\d/.test(g)) out.go = g.replace(/^go/, '');
  return out;
}
/** Findings for detected runtimes. Go is also checked live via OSV (ecosystem Go, package stdlib) by the scanner. */
function evaluate(versions, table = TABLE) {
  const findings = [];
  for (const [runtime, version] of Object.entries(versions)) {
    const r = core.checkRuntime(table, runtime, version);
    if (!r || r.status === 'patched' || r.status === 'newer' || r.status === 'unknown') continue;
    const a = r.advisory;
    findings.push({
      kind: 'runtime', ecosystem: 'runtime', name: runtime, version, source: 'runtime:' + runtime, sources: ['runtime:' + runtime], dev: false, direct: true, kev: null, epss: null,
      id: 'PATCHNOW-RT-' + runtime.toUpperCase() + '-' + a.published, aliases: a.cves, cves: a.cves, summary: a.title,
      severity: a.severity, score: null, fixed: r.fixed || null, eol: r.status === 'eol', note: r.message || a.note || null,
      references: [a.source],
    });
  }
  return findings;
}
module.exports = { detect, evaluate, TABLE };
