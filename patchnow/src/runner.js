'use strict';
/** `patchnow run`: scan -> policy -> dedupe -> actions -> audit. */
const path = require('path');
const crypto = require('crypto');
const { scan } = require('./scan');
const policy = require('./policy');
const { State, Audit } = require('./store');
const G = require('./git');
const ACTIONS = { pin_patch: require('./actions/pin_patch'), safe_mode: require('./actions/safe_mode'), revoke: require('./actions/revoke'), notify: require('./actions/notify') };

async function scanWithConfig(cfg, extra = {}) {
  const dirs = (cfg.scan.paths || ['.']).map((p) => path.resolve(cfg._dir, p));
  const parts = [];
  for (const [i, d] of dirs.entries()) parts.push(await scan({ dir: d, includeDev: cfg.scan.include_dev, runtimes: i === 0 ? (extra.runtimes ?? cfg.scan.runtimes) : 'off', epss: extra.epss ?? cfg.scan.epss, maxDepth: cfg.scan.max_depth, cacheDir: path.resolve(cfg._dir, cfg.cache.path) }));
  if (parts.length === 1) { relocate(parts[0], dirs[0], cfg._dir); return parts[0]; }
  const out = { ...parts[0], dir: cfg._dir, files: [], findings: [], errors: [], packagesScanned: 0 };
  parts.forEach((p, i) => { relocate(p, dirs[i], cfg._dir); out.files.push(...p.files); out.findings.push(...p.findings); out.errors.push(...p.errors); out.packagesScanned += p.packagesScanned; });
  return out;
}
/** make manifest paths relative to the config directory */
function relocate(res, from, to) {
  const fix = (s) => (s.startsWith('runtime:') ? s : path.relative(to, path.join(from, s)) || s);
  res.files.forEach((f) => { f.path = fix(f.path); });
  res.findings.forEach((f) => { f.sources = f.sources.map(fix); f.source = f.sources[0]; });
  res.dir = to;
}

async function run(cfg, { dryRun = false, log = () => {}, now = new Date() } = {}) {
  const runId = now.toISOString().replace(/[-:.]/g, '').slice(0, 15) + '-' + crypto.randomBytes(3).toString('hex');
  const audit = new Audit(path.resolve(cfg._dir, cfg.audit.path), runId);
  const state = new State(path.resolve(cfg._dir, cfg.state.path));
  const dry = dryRun || cfg.armed !== true;
  audit.write('run.start', { armed: cfg.armed === true, dry_run: dry, config: path.basename(cfg._file) });
  let result;
  try { result = await scanWithConfig(cfg); }
  catch (e) { audit.write('run.error', { stage: 'scan', error: e.message }); throw e; }
  audit.write('scan', { packages: result.packagesScanned, files: result.files.map((f) => f.path), findings: result.findings.length, kev_catalog: result.intel.kev && result.intel.kev.catalogVersion, errors: result.errors });

  const decisions = policy.evaluate(result.findings, cfg, now);
  const fire = [], deduped = [];
  for (const d of decisions) {
    const f = d.finding, key = policy.keyOf(f);
    const rec = { key, id: f.id, cves: f.cves, package: f.name, version: f.version, severity: f.severity, kev: !!f.kev, epss: f.epss, decision: d.decision };
    if (d.decision === 'fire' && state.seen(key, cfg.state.refire_after_days, now.getTime())) { deduped.push(f); audit.write('decision', { ...rec, decision: 'already-fired' }); continue; }
    if (d.decision === 'fire') { fire.push(f); rec.trigger = d.trigger; }
    if (d.reason) rec.reason = d.reason;
    audit.write('decision', rec);
  }
  log((dry ? 'DRY RUN · ' : 'ARMED · ') + result.findings.length + ' findings, ' + fire.length + ' new matched policy, ' + deduped.length + ' already handled');

  const ctx = { cfg, runId, dryRun: dry, rootDir: cfg._dir, scan: result, results: {}, log, repo: process.env.GITHUB_REPOSITORY || G.githubRepoFromRemote(cfg._dir) || null };
  const actionResults = [];
  if (fire.length) {
    for (const [i, a] of (cfg.actions || []).entries()) {
      const name = Object.keys(a).find((k) => k !== 'when'); const opts = a[name] || {};
      const when = a.when || opts.when;
      const subset = when ? fire.filter((f) => policy.matchTrigger(f, when)) : fire;
      if (!subset.length) { audit.write('action', { action: name, index: i, status: 'skipped', reason: 'no findings match "when"' }); continue; }
      let r;
      try { r = await ACTIONS[name].execute(opts, subset, ctx); }
      catch (e) { r = { status: 'error', error: e.message }; }
      ctx.results[name + (ctx.results[name] ? '#' + i : '')] = r;
      actionResults.push({ action: name, index: i, findings: subset.length, ...r });
      audit.write('action', { action: name, index: i, dry_run: dry, findings: subset.map(policy.keyOf), ...r });
      log('  ' + name.padEnd(9) + ' ' + r.status + (r.error ? ': ' + r.error : r.pr && r.pr.url ? ' ' + r.pr.url : r.branch ? ' ' + r.branch : ''));
    }
  }
  if (!dry && fire.length) {
    const summary = actionResults.map((r) => r.action + ':' + r.status);
    for (const f of fire) state.mark(policy.keyOf(f), { id: f.id, package: f.name, version: f.version, run: runId, actions: summary });
    state.save();
  }
  const errored = actionResults.filter((r) => r.status === 'error' || r.status === 'failed');
  audit.write('run.end', { fired: fire.length, deduped: deduped.length, actions: actionResults.map((r) => ({ action: r.action, status: r.status })), errors: errored.length });
  return { runId, dryRun: dry, scan: result, decisions, fired: fire, deduped, actions: actionResults, errored: errored.length };
}
module.exports = { run, scanWithConfig };
