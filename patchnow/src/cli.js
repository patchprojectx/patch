'use strict';
const fs = require('fs');
const path = require('path');
const config = require('./config');
const report = require('./report');
const { scan } = require('./scan');
const { run, scanWithConfig } = require('./runner');
const core = require('./core');
const pkg = require('../package.json');

const HELP = `patchnow ${pkg.version} — exploited-vulnerability response, automated

Usage
  patchnow init  [--dir <path>] [--force]
  patchnow scan  [--dir <path>] [--format text|json|sarif] [--output <file>]
                 [--include-dev] [--no-runtimes] [--no-epss] [--fail-on kev|critical|high|any|none]
  patchnow run   [--dir <path>] [--config <file>] [--dry-run] [--sarif <file>] [--json]
  patchnow watch [--dir <path>] [--config <file>] [--interval 15m] [--dry-run]
  patchnow version | help

Data sources: OSV.dev (advisories), CISA KEV (known exploited), FIRST EPSS (exploit probability).
Policy file: patch.yml. Nothing destructive happens until it sets "armed: true".
Exit codes: 0 ok · 1 --fail-on threshold met · 2 usage/config error · 3 an action failed`;

function parseArgs(argv) {
  const a = { _: [] }; const bool = new Set(['force', 'include-dev', 'no-runtimes', 'no-epss', 'dry-run', 'json', 'help']);
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i];
    if (t.startsWith('--')) { const [k, v] = t.slice(2).split('='); if (bool.has(k)) a[k] = true; else { const val = v ?? argv[++i]; if (val === undefined) throw usage('--' + k + ' needs a value'); a[k] = val; } }
    else if (t === '-h') a.help = true; else a._.push(t);
  }
  return a;
}
const usage = (m) => Object.assign(new Error(m), { exit: 2 });
const out = (s) => process.stdout.write(s);
const err = (s) => process.stderr.write(s + '\n');

function failOn(level, findings) {
  if (!level || level === 'none') return false;
  if (level === 'kev') return findings.some((f) => f.kev);
  if (level === 'any') return findings.length > 0;
  const min = core.RANK[level.toUpperCase()]; if (min == null) throw usage('--fail-on must be kev, critical, high, any or none');
  return findings.some((f) => f.kev || core.RANK[f.severity] >= min);
}
function parseInterval(s) {
  const m = String(s).match(/^(\d+)(s|m|h)?$/); if (!m) throw usage('--interval must look like 15m, 1h or 900s');
  const ms = +m[1] * { s: 1e3, m: 60e3, h: 3600e3 }[m[2] || 'm']; if (ms < 60e3) throw usage('--interval must be at least 1m'); return ms;
}
function loadCfg(a) {
  const dir = path.resolve(a.dir || '.');
  const file = a.config ? path.resolve(a.config) : ['patch.yml', 'patch.yaml'].map((f) => path.join(dir, f)).find(fs.existsSync) || path.join(dir, 'patch.yml');
  try { return config.load(file); } catch (e) { throw usage(e.message); }
}
function printRun(r, a) {
  if (a.json) return out(JSON.stringify({ run: r.runId, dry_run: r.dryRun, fired: r.fired.map((f) => ({ id: f.id, package: f.name, version: f.version, severity: f.severity, kev: !!f.kev, epss: f.epss, fixed: f.fixed })), already_handled: r.deduped.length, actions: r.actions }, null, 2) + '\n');
  out(report.text(r.scan));
  out('\n' + (r.dryRun ? 'Policy: DRY RUN (set armed: true in patch.yml to act)' : 'Policy: ARMED') + ' · ' + r.fired.length + ' new finding(s) matched · ' + r.deduped.length + ' already handled\n');
  for (const x of r.actions) {
    out('  ' + x.action.padEnd(10) + x.status + (x.error ? ' — ' + x.error : '') + '\n');
    for (const p of x.planned || []) if (x.status === 'dry-run') out('      would bump ' + p.package + ' ' + p.from.join(',') + ' → ' + p.to + ' (' + p.strategy + ', ' + p.dir + ')\n');
    for (const p of x.applied || []) out('      bumped ' + p.package + ' ' + p.from.join(',') + ' → ' + p.to + ' via ' + p.method + (p.verified ? ' (verified)' : ' (NOT verified)') + '\n');
    for (const s of x.skipped || []) out('      manual: ' + s.package + ' — ' + s.reason + '\n');
    if (x.pr) out('      pull request: ' + (x.pr.url || x.pr.skipped) + '\n');
    if (x.would) out('      would: ' + x.would + '\n');
    if (x.preview) out('      would send: ' + x.preview + '\n');
    if (x.errors && Object.keys(x.errors).length) for (const [c, e] of Object.entries(x.errors)) out('      ' + c + ' failed: ' + e + '\n');
  }
}

async function main(argv = process.argv.slice(2)) {
  const a = parseArgs(argv); const cmd = a._[0] || 'help';
  if (a.help || cmd === 'help') { out(HELP + '\n'); return 0; }
  if (cmd === 'version' || cmd === '--version' || cmd === '-v') { out(pkg.version + '\n'); return 0; }
  if (cmd === 'init') {
    const file = path.join(path.resolve(a.dir || '.'), 'patch.yml');
    if (fs.existsSync(file) && !a.force) throw usage(file + ' already exists (use --force to overwrite)');
    fs.writeFileSync(file, config.TEMPLATE);
    const gi = path.join(path.dirname(file), '.gitignore');
    const cur = fs.existsSync(gi) ? fs.readFileSync(gi, 'utf8') : '';
    if (!/^\.patchnow\/?$/m.test(cur)) fs.writeFileSync(gi, cur + (cur && !cur.endsWith('\n') ? '\n' : '') + '.patchnow/\n');
    out('wrote ' + path.relative(process.cwd(), file) + ' (dry run until armed: true) and added .patchnow/ to .gitignore\n');
    return 0;
  }
  if (cmd === 'scan') {
    const fmt = a.format || 'text'; if (!['text', 'json', 'sarif'].includes(fmt)) throw usage('--format must be text, json or sarif');
    const r = await scan({ dir: a.dir || '.', includeDev: !!a['include-dev'], runtimes: a['no-runtimes'] ? 'off' : 'auto', epss: !a['no-epss'], cacheDir: path.resolve(a.dir || '.', '.patchnow/cache') });
    const body = fmt === 'json' ? JSON.stringify(r, null, 2) + '\n' : fmt === 'sarif' ? JSON.stringify(report.sarif(r), null, 2) + '\n' : report.text(r, { color: !a.output && process.stdout.isTTY });
    if (a.output) { fs.writeFileSync(a.output, body); err('wrote ' + a.output); } else out(body);
    return failOn(a['fail-on'], r.findings) ? 1 : 0;
  }
  if (cmd === 'run' || cmd === 'watch') {
    const cfg = loadCfg(a);
    const once = async () => {
      const r = await run(cfg, { dryRun: !!a['dry-run'], log: a.json ? () => {} : (m) => err(m) });
      if (a.sarif) fs.writeFileSync(a.sarif, JSON.stringify(report.sarif(r.scan), null, 2));
      printRun(r, a); return r.errored ? 3 : 0;
    };
    if (cmd === 'run') return once();
    const ms = parseInterval(a.interval || '15m');
    err('patchnow watch: every ' + Math.round(ms / 60000) + 'm · Ctrl-C to stop');
    let stop = false; process.on('SIGINT', () => { stop = true; process.exit(0); }); process.on('SIGTERM', () => process.exit(0));
    for (;;) {
      try { await once(); } catch (e) { err(new Date().toISOString() + ' run failed: ' + e.message); }
      if (stop) return 0;
      await new Promise((r) => setTimeout(r, ms));
    }
  }
  throw usage('unknown command "' + cmd + '"\n\n' + HELP);
}
module.exports = { main, parseArgs, failOn, parseInterval };
