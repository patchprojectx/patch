'use strict';
/**
 * End-to-end: a throwaway git repo with known-vulnerable npm packages, a local bare "origin",
 * a local mock of the GitHub REST API and a local webhook receiver. Uses the live OSV, CISA KEV
 * and EPSS APIs (skipped when offline). Nothing leaves the machine except those read-only queries.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync, execFile } = require('child_process');
const BIN = path.join(__dirname, '..', 'bin', 'patchnow.js');
const parsers = require('../src/parsers');

const sh = (cmd, args, cwd) => execFileSync(cmd, args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
const cli = (args, env) => new Promise((resolve) => execFile(process.execPath, [BIN, ...args], { env: { ...process.env, ...env }, encoding: 'utf8', timeout: 300000 }, (err, stdout, stderr) => resolve({ code: err ? err.code : 0, stdout, stderr })));

async function online() {
  try { const r = await fetch('https://api.osv.dev/v1/query', { method: 'POST', body: JSON.stringify({ package: { name: 'lodash', ecosystem: 'npm' }, version: '4.17.15' }), signal: AbortSignal.timeout(10000) }); return r.ok; } catch { return false; }
}
function server(handler) {
  const hits = [];
  const srv = http.createServer((req, res) => { let b = ''; req.on('data', (d) => (b += d)); req.on('end', () => { const hit = { method: req.method, url: req.url, headers: req.headers, body: b ? JSON.parse(b) : null }; hits.push(hit); handler(hit, res); }); });
  return new Promise((r) => srv.listen(0, '127.0.0.1', () => r({ srv, hits, url: 'http://127.0.0.1:' + srv.address().port })));
}
const send = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };

test('e2e: scan → policy → pin_patch (branch, commit, push, PR) → notify → audit → dedupe', { timeout: 600000 }, async (t) => {
  if (!(await online())) return t.skip('OSV API unreachable (offline)');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'patchnow-e2e-'));
  const repo = path.join(tmp, 'app'), origin = path.join(tmp, 'origin.git');
  fs.mkdirSync(repo);
  sh('git', ['init', '-q', '--bare', '-b', 'main', origin]);
  fs.writeFileSync(path.join(repo, 'package.json'), JSON.stringify({ name: 'e2e-fixture', version: '1.0.0', private: true, dependencies: { lodash: '4.17.15', optimist: '0.6.1' } }, null, 2) + '\n');
  sh('npm', ['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund'], repo);
  const before = parsers.parseFile(path.join(repo, 'package-lock.json'));
  assert.ok(before.some((p) => p.name === 'minimist' && p.version === '0.0.10'), 'fixture should pull minimist 0.0.10 transitively via optimist');

  const github = await server((h, res) => {
    if (h.method === 'POST' && h.url === '/repos/patchnow-e2e/fixture/pulls') return send(res, 201, { number: 7, html_url: 'https://github.example.test/patchnow-e2e/fixture/pull/7' });
    if (h.method === 'POST' && h.url === '/repos/patchnow-e2e/fixture/issues/7/labels') return send(res, 200, [{ name: 'security' }]);
    send(res, 404, { message: 'Not Found' });
  });
  const hook = await server((h, res) => send(res, 200, { ok: true }));
  t.after(() => { github.srv.close(); hook.srv.close(); });

  const yml = (armed) => `version: 1
armed: ${armed}
scan:
  runtimes: off
triggers:
  - kev: true
  - severity: critical
  - severity: high
    packages: [lodash]
actions:
  - pin_patch:
      base: main
      repo: patchnow-e2e/fixture
      labels: [security, patchnow]
  - notify:
      webhook: { url_env: E2E_WEBHOOK }
`;
  fs.writeFileSync(path.join(repo, 'patch.yml'), yml(false));
  fs.writeFileSync(path.join(repo, '.gitignore'), '.patchnow/\n');
  sh('git', ['init', '-q', '-b', 'main'], repo);
  sh('git', ['add', '-A'], repo);
  sh('git', ['-c', 'user.name=fixture', '-c', 'user.email=fixture@example.test', 'commit', '-q', '-m', 'fixture'], repo);
  sh('git', ['remote', 'add', 'origin', origin], repo);
  sh('git', ['push', '-q', '-u', 'origin', 'main'], repo);
  const env = { GITHUB_ACTIONS: '', GITHUB_API_URL: github.url, GITHUB_TOKEN: 'test-token-not-real', E2E_WEBHOOK: hook.url + '/patchnow', GITHUB_REPOSITORY: '' };

  // 1. not armed: dry run, nothing changes
  const dry = await cli(['run', '--dir', repo, '--json'], env);
  assert.equal(dry.code, 0, dry.stderr);
  const dj = JSON.parse(dry.stdout);
  assert.equal(dj.dry_run, true);
  const firedIds = dj.fired.map((x) => x.package + '@' + x.version);
  assert.ok(firedIds.includes('lodash@4.17.15'), 'lodash should fire (high, allowlisted trigger)');
  assert.ok(firedIds.includes('minimist@0.0.10'), 'minimist should fire (critical CVE-2021-44906)');
  assert.ok(!firedIds.includes('optimist@0.6.1'));
  assert.equal(dj.actions.find((a) => a.action === 'pin_patch').status, 'dry-run');
  assert.equal(sh('git', ['branch', '--list', 'patchnow/*'], repo), '');
  assert.equal(github.hits.length + hook.hits.length, 0);

  // 2. armed
  fs.writeFileSync(path.join(repo, 'patch.yml'), yml(true));
  sh('git', ['-c', 'user.name=fixture', '-c', 'user.email=fixture@example.test', 'commit', '-q', '-am', 'arm'], repo);
  const live = await cli(['run', '--dir', repo, '--json', '--sarif', path.join(tmp, 'out.sarif')], env);
  assert.equal(live.code, 0, live.stderr + live.stdout);
  const lj = JSON.parse(live.stdout);
  assert.equal(lj.dry_run, false);
  const pin = lj.actions.find((a) => a.action === 'pin_patch');
  assert.equal(pin.status, 'committed', JSON.stringify(pin));
  assert.match(pin.branch, /^patchnow\/\d{8}-[0-9a-f]{7}$/);
  const lod = pin.applied.find((a) => a.package === 'lodash'), mini = pin.applied.find((a) => a.package === 'minimist');
  assert.equal(lod.method, 'direct'); assert.equal(mini.method, 'override');
  assert.ok(lod.verified && mini.verified, 'lockfile must resolve the fixed versions');
  assert.equal(mini.to, '0.2.4'); assert.equal(mini.npm_ls, 'ok');

  // branch + commit exist locally and on origin; working tree back on main and clean
  assert.equal(sh('git', ['rev-parse', '--abbrev-ref', 'HEAD'], repo), 'main');
  assert.equal(sh('git', ['status', '--porcelain'], repo), '');
  assert.equal(sh('git', ['rev-parse', 'refs/heads/' + pin.branch], origin), pin.commit);
  const lockOnBranch = JSON.parse(sh('git', ['show', pin.branch + ':package-lock.json'], repo));
  const pkgOnBranch = JSON.parse(sh('git', ['show', pin.branch + ':package.json'], repo));
  assert.equal(pkgOnBranch.overrides.minimist, '0.2.4');
  assert.equal(pkgOnBranch.dependencies.lodash, lod.to, 'direct dependency pinned exactly as before');
  assert.equal(lockOnBranch.packages['node_modules/lodash'].version, lod.to);
  assert.ok(Object.entries(lockOnBranch.packages).filter(([k]) => k.endsWith('node_modules/minimist')).every(([, v]) => v.version === '0.2.4'));
  assert.match(sh('git', ['log', '-1', '--format=%an <%ae>%n%s', pin.branch], repo), /^patchnow <patchnow@localhost>\nfix\(security\): patch /);
  assert.equal(JSON.parse(fs.readFileSync(path.join(repo, 'package.json'), 'utf8')).overrides, undefined, 'main is untouched');

  // pull request via mock GitHub API
  const pr = github.hits.find((h) => h.url.endsWith('/pulls'));
  assert.equal(pr.headers.authorization, 'Bearer test-token-not-real');
  assert.equal(pr.body.head, pin.branch); assert.equal(pr.body.base, 'main');
  assert.match(pr.body.body, /\| `lodash` \| 4\.17\.15 \|/); assert.match(pr.body.body, /\| `minimist` \| 0\.0\.10 \| \*\*0\.2\.4\*\*/); assert.match(pr.body.body, /CVE-2021-44906|GHSA-xvch-5gv4-984h/);
  assert.equal(pin.pr.url, 'https://github.example.test/patchnow-e2e/fixture/pull/7');
  assert.deepEqual(github.hits.find((h) => h.url.endsWith('/labels')).body, { labels: ['security', 'patchnow'] });

  // notify reached the webhook and carries the PR link
  assert.equal(hook.hits.length, 1);
  assert.equal(hook.hits[0].body.event, 'patchnow.alert');
  assert.match(hook.hits[0].body.text, /pull\/7/);
  assert.ok(hook.hits[0].body.findings.some((x) => x.package === 'minimist' && x.severity === 'CRITICAL'));

  // audit log + state + sarif
  const audit = fs.readFileSync(path.join(repo, '.patchnow/audit.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
  const run2 = audit.filter((e) => e.run === lj.run);
  assert.deepEqual([...new Set(run2.map((e) => e.type))], ['run.start', 'scan', 'decision', 'action', 'run.end']);
  assert.deepEqual(run2.filter((e) => e.type === 'action').map((e) => [e.action, e.status]), [['pin_patch', 'committed'], ['notify', 'sent']]);
  assert.ok(!fs.readFileSync(path.join(repo, '.patchnow/audit.jsonl'), 'utf8').includes('test-token-not-real'), 'token never logged');
  const state = JSON.parse(fs.readFileSync(path.join(repo, '.patchnow/state.json'), 'utf8'));
  assert.equal(Object.keys(state.fired).length, lj.fired.length);
  const sarif = JSON.parse(fs.readFileSync(path.join(tmp, 'out.sarif'), 'utf8'));
  assert.equal(sarif.version, '2.1.0'); assert.ok(sarif.runs[0].results.length >= lj.fired.length);

  // 3. second armed run: same findings are deduplicated, nothing fires again
  const again = await cli(['run', '--dir', repo, '--json'], env);
  const aj = JSON.parse(again.stdout);
  assert.equal(aj.fired.length, 0); assert.equal(aj.already_handled, lj.fired.length); assert.equal(aj.actions.length, 0);
  assert.equal(github.hits.filter((h) => h.url.endsWith('/pulls')).length, 1);
  assert.equal(hook.hits.length, 1);

  // npm itself agrees the patched branch resolves cleanly
  sh('git', ['checkout', '-q', pin.branch], repo);
  sh('npm', ['ls', '--all', '--package-lock-only'], repo);
  sh('git', ['checkout', '-q', 'main'], repo);
  t.diagnostic('fired: ' + firedIds.join(', ') + ' · lodash → ' + lod.to + ' · minimist → ' + mini.to + ' · branch ' + pin.branch);
});

test('live scan: multi-ecosystem fixture matches OSV + KEV (composer, PyPI, Go, crates, npm)', { timeout: 300000 }, async (t) => {
  if (!(await online())) return t.skip('OSV API unreachable (offline)');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'patchnow-live-'));
  const src = path.join(__dirname, 'fixtures/formats');
  for (const [from, to] of [['composer.lock', 'php/composer.lock'], ['requirements.txt', 'py/requirements.txt'], ['go.mod', 'go/go.mod'], ['Cargo.lock', 'rs/Cargo.lock'], ['package-lock.v3.json', 'js/package-lock.json']]) {
    fs.mkdirSync(path.dirname(path.join(tmp, to)), { recursive: true }); fs.copyFileSync(path.join(src, from), path.join(tmp, to));
  }
  const r = await cli(['scan', '--dir', tmp, '--format', 'json', '--no-runtimes', '--fail-on', 'kev'], {});
  assert.equal(r.code, 1, 'facade/ignition 2.5.1 is on KEV (CVE-2021-3129) so --fail-on kev must exit 1');
  const j = JSON.parse(r.stdout);
  const eco = new Set(j.findings.map((f) => f.ecosystem));
  for (const e of ['Packagist', 'PyPI', 'Go', 'crates.io', 'npm']) assert.ok(eco.has(e), 'expected findings for ' + e);
  const ign = j.findings.find((f) => f.name === 'facade/ignition' && f.cves.includes('CVE-2021-3129'));
  assert.ok(ign && ign.kev && ign.kev[0].dateAdded, 'CVE-2021-3129 must be flagged as KEV');
  assert.ok(!j.findings.some((f) => f.name === 'vite'), 'dev dependencies are excluded by default');
  assert.equal(j.files.length, 5);
  t.diagnostic(j.findings.length + ' findings across ' + [...eco].join(', ') + ' · KEV catalog ' + j.intel.kev.catalogVersion);
});
