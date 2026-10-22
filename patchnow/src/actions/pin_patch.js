'use strict';
/**
 * pin_patch — raise each affected package to the smallest version that clears every fired advisory,
 * on a new git branch, commit, push, and open a pull request.
 *
 * Ecosystems:
 *   npm (package-lock.json)  direct dep: npm install name@X --package-lock-only ; transitive: package.json "overrides" + npm install --package-lock-only
 *   pnpm (pnpm-lock.yaml)    package.json "pnpm.overrides" + pnpm install --lockfile-only           (requires pnpm on PATH)
 *   PyPI (requirements.txt)  rewrite the == pin in place
 *   Go (go.mod)              go get module@vX + go mod tidy                                         (requires go on PATH)
 *   crates.io (Cargo.lock)   cargo update -p name --precise X                                       (requires cargo on PATH)
 *   Packagist (composer.lock) composer require name:X --no-install / composer update name --no-install (requires composer)
 *   yarn.lock, poetry.lock, runtimes: reported as manual, not edited.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const core = require('../core');
const parsers = require('../parsers');
const G = require('../git');
const github = require('../github');

function plan(findings, rootDir) {
  const groups = new Map(); // key: manifest|name
  for (const f of findings) {
    if (f.kind !== 'dependency') continue;
    for (const src of f.sources) {
      const k = src + '|' + f.ecosystem + '|' + f.name + '|' + f.version;
      const g = groups.get(k) || { source: src, ecosystem: f.ecosystem, name: f.name, from: f.version, fixes: [], ids: [], findings: [] };
      g.fixes.push(f.fixed); g.ids.push(f.id); g.findings.push(f); groups.set(k, g);
    }
  }
  const items = [];
  for (const g of groups.values()) {
    const unfixed = g.findings.filter((f) => !f.fixed);
    const to = core.upgradeTarget(g.fixes);
    const base = path.basename(g.source);
    const strategy = { 'package-lock.json': 'npm', 'npm-shrinkwrap.json': 'npm', 'pnpm-lock.yaml': 'pnpm', 'requirements.txt': 'requirements', 'go.mod': 'go', 'go.sum': 'go', 'Cargo.lock': 'cargo', 'composer.lock': 'composer', 'package.json': 'npm' }[base] || 'manual';
    items.push({ ...g, to, strategy: to ? strategy : 'manual', unfixed: unfixed.map((f) => f.id), dir: path.dirname(path.join(rootDir, g.source)), reason: !to ? 'no fixed version published' : strategy === 'manual' ? base + ' is not edited automatically in v0.1' : null });
  }
  // several vulnerable versions of one package in one project: keep one item per (dir,name), highest target
  const merged = new Map();
  for (const it of items) {
    const k = it.dir + '|' + it.ecosystem + '|' + it.name;
    const cur = merged.get(k);
    if (!cur) merged.set(k, { ...it, froms: [it.from] });
    else { cur.froms.push(it.from); cur.ids.push(...it.ids); cur.findings.push(...it.findings); cur.to = core.upgradeTarget([cur.to, it.to]); if (cur.to && cur.strategy === 'manual' && it.strategy !== 'manual') { cur.strategy = it.strategy; cur.reason = null; } }
  }
  return [...merged.values()];
}

const run = (cmd, args, cwd, log) => { log && log('  $ ' + cmd + ' ' + args.join(' ')); return execFileSync(cmd, args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, npm_config_update_notifier: 'false' }, timeout: 300000 }); };
const has = (cmd) => { try { execFileSync(cmd, ['--version'], { stdio: 'ignore' }); return true; } catch { return false; } };
function readJson(file) { const t = fs.readFileSync(file, 'utf8'); const indent = (t.match(/^[ \t]+(?=")/m) || ['  '])[0]; return { j: JSON.parse(t), indent, nl: t.endsWith('\n') }; }
function writeJson(file, { j, indent, nl }) { fs.writeFileSync(file, JSON.stringify(j, null, indent) + (nl ? '\n' : '')); }

const NPM_FLAGS = ['--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund'];
function applyNpm(it, log) {
  const pj = path.join(it.dir, 'package.json');
  const P = readJson(pj);
  const sec = ['dependencies', 'devDependencies', 'optionalDependencies'].find((s) => P.j[s] && P.j[s][it.name] !== undefined);
  if (sec) {
    const flag = sec === 'devDependencies' ? ['--save-dev'] : sec === 'optionalDependencies' ? ['--save-optional'] : [];
    const exact = /^\d/.test(P.j[sec][it.name]) ? ['--save-exact'] : [];
    run('npm', ['install', it.name + '@' + it.to, ...flag, ...exact, ...NPM_FLAGS], it.dir, log);
    return { method: 'direct', files: ['package.json', 'package-lock.json'] };
  }
  P.j.overrides = P.j.overrides || {};
  P.j.overrides[it.name] = it.to;
  writeJson(pj, P);
  run('npm', ['install', ...NPM_FLAGS], it.dir, log);
  return { method: 'override', files: ['package.json', 'package-lock.json'] };
}
function applyPnpm(it, log) {
  if (!has('pnpm')) throw new Error('pnpm not found on PATH');
  const pj = path.join(it.dir, 'package.json'); const P = readJson(pj);
  P.j.pnpm = P.j.pnpm || {}; P.j.pnpm.overrides = P.j.pnpm.overrides || {}; P.j.pnpm.overrides[it.name] = it.to; writeJson(pj, P);
  run('pnpm', ['install', '--lockfile-only', '--ignore-scripts'], it.dir, log);
  return { method: 'pnpm-override', files: ['package.json', 'pnpm-lock.yaml'] };
}
/** Rewrite `name==old` pins in requirements.txt text. Pure; exported for tests. */
function rewriteRequirements(text, name, to) {
  const norm = (n) => n.toLowerCase().replace(/[-_.]+/g, '-');
  let n = 0;
  const out = text.split(/(\r?\n)/).map((line) => {
    const m = line.match(/^(\s*)([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?(\s*)(===?)(\s*)([^\s;,\\#]+)(.*)$/);
    if (!m || norm(m[2]) !== norm(name)) return line;
    n++; return m[1] + m[2] + (m[3] || '') + m[4] + m[5] + m[6] + to + m[8].replace(/\s--hash=\S+/g, '');
  }).join('');
  return { text: out, changed: n };
}
function applyRequirements(it) {
  const file = path.join(it.dir, 'requirements.txt');
  const r = rewriteRequirements(fs.readFileSync(file, 'utf8'), it.name, it.to);
  if (!r.changed) throw new Error(it.name + ' pin not found in requirements.txt');
  fs.writeFileSync(file, r.text);
  return { method: 'rewrite-pin', files: ['requirements.txt'] };
}
function applyGo(it, log) {
  if (!has('go')) throw new Error('go not found on PATH');
  run('go', ['get', it.name + '@v' + it.to.replace(/^v/, '')], it.dir, log); run('go', ['mod', 'tidy'], it.dir, log);
  return { method: 'go-get', files: ['go.mod', 'go.sum'] };
}
function applyCargo(it, log) {
  if (!has('cargo')) throw new Error('cargo not found on PATH');
  run('cargo', ['update', '-p', it.name + '@' + it.from, '--precise', it.to], it.dir, log);
  return { method: 'cargo-precise', files: ['Cargo.lock'] };
}
function applyComposer(it, log) {
  if (!has('composer')) throw new Error('composer not found on PATH');
  const cj = JSON.parse(fs.readFileSync(path.join(it.dir, 'composer.json'), 'utf8'));
  if ((cj.require && cj.require[it.name]) || (cj['require-dev'] && cj['require-dev'][it.name])) run('composer', ['require', it.name + ':^' + it.to, '--no-install', '--no-scripts', '-W'], it.dir, log);
  else run('composer', ['update', it.name, '--no-install', '--no-scripts', '-W'], it.dir, log);
  return { method: 'composer', files: ['composer.json', 'composer.lock'] };
}
const TOUCHABLE = ['package.json', 'package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'requirements.txt', 'go.mod', 'go.sum', 'Cargo.lock', 'composer.json', 'composer.lock'];
function snapshot(dir) { const m = new Map(); for (const f of TOUCHABLE) { const p = path.join(dir, f); m.set(p, fs.existsSync(p) ? fs.readFileSync(p) : null); } return m; }
function restore(m) { for (const [p, buf] of m) { if (buf) fs.writeFileSync(p, buf); else if (fs.existsSync(p)) fs.unlinkSync(p); } }
const APPLY = { npm: applyNpm, pnpm: applyPnpm, requirements: applyRequirements, go: applyGo, cargo: applyCargo, composer: applyComposer };

/** Re-parse the manifest and confirm every vulnerable version is gone and the target is present. */
function verify(it) {
  const lockName = { npm: fs.existsSync(path.join(it.dir, 'package-lock.json')) ? 'package-lock.json' : 'npm-shrinkwrap.json', pnpm: 'pnpm-lock.yaml', requirements: 'requirements.txt', go: 'go.mod', cargo: 'Cargo.lock', composer: 'composer.lock' }[it.strategy];
  const pkgs = parsers.parseFile(path.join(it.dir, lockName)).filter((p) => core.normName(p.ecosystem, p.name) === core.normName(it.ecosystem, it.name));
  const left = pkgs.filter((p) => it.froms.includes(p.version));
  const ok = !left.length && pkgs.some((p) => core.cmpVer(p.version, it.to) >= 0);
  let npmLs = null;
  if (it.strategy === 'npm') { try { run('npm', ['ls', it.name, '--package-lock-only', '--all'], it.dir); npmLs = 'ok'; } catch (e) { npmLs = (e.stdout || e.message).slice(0, 400); } }
  return { ok, resolved: [...new Set(pkgs.map((p) => p.version))], npmLs };
}

function prBody(applied, skipped, ctx) {
  const L = ['## patchnow: patch exploited / critical vulnerabilities', '', 'Opened automatically by [patchnow](https://github.com/patchprojectx/patch) because the following findings matched the policy in `' + path.basename(ctx.cfg._file || 'patch.yml') + '`.', ''];
  L.push('| Package | From | To | Advisories | KEV | Severity | EPSS |', '|---|---|---|---|---|---|---|');
  for (const it of applied) {
    const kev = it.findings.filter((f) => f.kev).map((f) => f.kev[0].cve);
    const sev = it.findings.map((f) => f.severity).sort((a, b) => core.RANK[b] - core.RANK[a])[0];
    const epss = Math.max(...it.findings.map((f) => f.epss || 0));
    L.push(`| \`${it.name}\` | ${it.froms.join(', ')} | **${it.to}** | ${[...new Set(it.ids)].map((i) => `[${i}](https://osv.dev/vulnerability/${i})`).join(' ')} | ${kev.length ? 'YES ' + kev.join(', ') : '-'} | ${sev} | ${epss ? epss.toFixed(3) : '-'} |`);
  }
  L.push('', '### How', '');
  for (const it of applied) L.push(`- \`${it.name}\` in \`${path.relative(ctx.rootDir, it.dir) || '.'}\`: ${it.method}${it.verify ? (it.verify.ok ? ' — verified: lockfile resolves ' + it.verify.resolved.join(', ') : ' — **verification failed**, resolves ' + it.verify.resolved.join(', ')) : ''}`);
  if (skipped.length) { L.push('', '### Not changed (needs a human)', ''); for (const s of skipped) L.push(`- \`${s.name}@${s.froms.join(', ')}\` (${s.source}): ${s.reason}`); }
  L.push('', '### Before merging', '', '- Run your test suite; a minimum-fix bump can still be a semver-major change for some packages.', '- Advisory data: OSV.dev · exploitation status: CISA KEV ' + (ctx.scan.intel.kev ? ctx.scan.intel.kev.catalogVersion : 'n/a') + ' · EPSS: FIRST.org', '', '<sub>run ' + ctx.runId + '</sub>');
  return L.join('\n');
}

/** Commit identity: explicit options, else the GitHub Actions bot inside Actions, else a local placeholder. */
function authorOf(o) {
  if (o.author_name || o.author_email) return { name: o.author_name || 'patchnow', email: o.author_email || 'patchnow@localhost' };
  if (process.env.GITHUB_ACTIONS === 'true') return { name: 'github-actions[bot]', email: '41898282+github-actions[bot]@users.noreply.github.com' };
  return { name: 'patchnow', email: 'patchnow@localhost' };
}

async function execute(opts, findings, ctx) {
  const o = { branch_prefix: 'patchnow/', base: null, push: true, open_pr: true, remote: 'origin', token_env: 'GITHUB_TOKEN', repo: null, labels: ['security'], draft: false, allow_dirty: false, ...opts };
  const items = plan(findings, ctx.rootDir);
  const todo = items.filter((i) => i.strategy !== 'manual'), skipped = items.filter((i) => i.strategy === 'manual');
  const summary = { planned: todo.map((i) => ({ package: i.name, ecosystem: i.ecosystem, from: i.froms, to: i.to, strategy: i.strategy, dir: path.relative(ctx.rootDir, i.dir) || '.' })), skipped: skipped.map((s) => ({ package: s.name, from: s.froms, reason: s.reason })) };
  if (!todo.length) return { status: 'nothing-to-do', ...summary };
  if (ctx.dryRun) return { status: 'dry-run', ...summary };

  const root = G.repoRoot(ctx.rootDir);
  if (!root) throw new Error('pin_patch needs a git repository at ' + ctx.rootDir);
  const original = G.currentBranch(root);
  const dirty = G.dirtyFiles(root).filter((f) => !f.startsWith('.patchnow/'));
  if (dirty.length && !o.allow_dirty) throw new Error('working tree has uncommitted changes (' + dirty.slice(0, 5).join(', ') + '); commit or stash them, or set allow_dirty: true');
  const base = o.base || original;
  const hash = crypto.createHash('sha1').update(todo.map((i) => i.name + i.to).sort().join(',')).digest('hex').slice(0, 7);
  const branch = o.branch_prefix + new Date().toISOString().slice(0, 10).replace(/-/g, '') + '-' + hash;
  if (G.tryGit(root, ['rev-parse', '--verify', '--quiet', 'refs/heads/' + branch])) return { status: 'branch-exists', branch, ...summary };

  G.git(root, ['checkout', '-q', '-b', branch, base]);
  const applied = []; const changed = new Set();
  try {
    for (const it of todo) {
      const snap = snapshot(it.dir);
      try {
        const r = APPLY[it.strategy](it, ctx.log);
        it.method = r.method; r.files.forEach((f) => { const p = path.join(it.dir, f); if (fs.existsSync(p)) changed.add(path.relative(root, p)); });
        it.verify = verify(it);
        applied.push(it);
      } catch (e) { it.reason = 'update failed: ' + String(e.stderr || e.message).split('\n').filter(Boolean).slice(-3).join(' '); skipped.push(it); restore(snap); }
    }
    if (!applied.length) { G.git(root, ['checkout', '-q', original]); G.tryGit(root, ['branch', '-D', branch]); return { status: 'failed', ...summary, skipped: skipped.map((s) => ({ package: s.name, reason: s.reason })) }; }
    G.git(root, ['add', '--', ...changed]);
    const title = 'fix(security): patch ' + applied.map((i) => i.name + '@' + i.to).join(', ');
    const msg = title + '\n\n' + applied.map((i) => `${i.name} ${i.froms.join(',')} -> ${i.to} (${[...new Set(i.ids)].join(', ')})`).join('\n') + '\n\nGenerated by patchnow run ' + ctx.runId;
    const author = authorOf(o);
    G.git(root, ['-c', 'user.name=' + author.name, '-c', 'user.email=' + author.email, 'commit', '-q', '--no-verify', '-m', msg]);
    const sha = G.git(root, ['rev-parse', 'HEAD']);
    const result = { status: 'committed', branch, base, commit: sha, title, applied: applied.map((i) => ({ package: i.name, from: i.froms, to: i.to, method: i.method, verified: i.verify.ok, resolved: i.verify.resolved, npm_ls: i.verify.npmLs })), skipped: skipped.map((s) => ({ package: s.name, from: s.froms, reason: s.reason })) };
    if (o.push) { G.git(root, ['push', '-q', '-u', o.remote, branch]); result.pushed = o.remote; }
    if (o.push && o.open_pr) {
      const token = process.env[o.token_env];
      const repo = o.repo || process.env.GITHUB_REPOSITORY || G.githubRepoFromRemote(root, o.remote);
      if (!token) result.pr = { skipped: 'env ' + o.token_env + ' is not set' };
      else if (!repo) result.pr = { skipped: 'cannot determine owner/repo; set pin_patch.repo' };
      else {
        const body = prBody(applied, skipped, ctx);
        const pr = await github.createPull({ repo, token, title, head: branch, base, body, draft: o.draft });
        try { await github.addLabels({ repo, token, number: pr.number, labels: o.labels }); } catch (e) { pr.labelsError = e.message; }
        result.pr = pr;
      }
    }
    return result;
  } finally {
    G.tryGit(root, ['checkout', '-q', original]);
  }
}
module.exports = { execute, plan, rewriteRequirements, prBody, authorOf };
