'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const P = require('../src/parsers');
const F = (n) => path.join(__dirname, 'fixtures/formats', n);
const parseAs = (fixture, as) => P.parseFile(as, fs.readFileSync(F(fixture), 'utf8'));
const pick = (list) => list.map((p) => p.name + '@' + p.version).sort();

test('package-lock v3: packages map, dev flag, nested, skips links/root', () => {
  const r = parseAs('package-lock.v3.json', 'package-lock.json');
  assert.deepEqual(pick(r), ['@babel/core@7.20.0', 'lodash@4.17.15', 'minimist@0.0.10', 'vite@6.2.2']);
  assert.equal(r.find((p) => p.name === 'vite').dev, true);
  assert.equal(r.find((p) => p.name === 'lodash').dev, false);
  assert.equal(r.find((p) => p.name === 'minimist').direct, false);
});
test('package-lock v1: nested dependencies, skips git versions', () => {
  const r = parseAs('package-lock.v1.json', 'package-lock.json');
  assert.deepEqual(pick(r), ['express@4.17.1', 'jest@29.0.0', 'qs@6.7.0']);
  assert.equal(r.find((p) => p.name === 'jest').dev, true);
});
test('pnpm-lock v5 / v6 / v9 keys incl. scopes and peer suffixes', () => {
  assert.deepEqual(pick(parseAs('pnpm-lock.v5.yaml', 'pnpm-lock.yaml')), ['@scope/pkg@2.1.0', 'minimist@1.2.5']);
  const v6 = parseAs('pnpm-lock.v6.yaml', 'pnpm-lock.yaml');
  assert.deepEqual(pick(v6), ['@scope/pkg@2.1.0', 'lodash@4.17.15', 'vitest@1.0.0']);
  assert.equal(v6.find((p) => p.name === 'vitest').dev, true);
  assert.deepEqual(pick(parseAs('pnpm-lock.v9.yaml', 'pnpm-lock.yaml')), ['@scope/pkg@2.1.0', 'axios@0.21.0']);
});
test('yarn.lock classic and berry', () => {
  assert.deepEqual(pick(parseAs('yarn.v1.lock', 'yarn.lock')), ['@babel/code-frame@7.12.13', 'lodash@4.17.15']);
  assert.deepEqual(pick(parseAs('yarn.berry.lock', 'yarn.lock')), ['@scope/pkg@2.1.0', 'lodash@4.17.15']);
});
test('composer.lock: strips v prefix, skips dev branches, marks packages-dev', () => {
  const r = parseAs('composer.lock', 'composer.lock');
  assert.deepEqual(pick(r), ['facade/ignition@2.5.1', 'laravel/framework@8.0.0', 'phpunit/phpunit@9.5.0']);
  assert.equal(r.find((p) => p.name === 'phpunit/phpunit').dev, true);
  assert.ok(r.every((p) => p.ecosystem === 'Packagist'));
});
test('requirements.txt: exact pins only, normalized names, extras, === and hashes', () => {
  const py = require('../src/parsers/python');
  const r = py.parseRequirements(fs.readFileSync(F('requirements.txt'), 'utf8'));
  assert.deepEqual(pick(r.packages), ['django@3.2.0', 'pyyaml@5.3', 'requests@2.25.0', 'urllib3@1.26.4']);
  assert.ok(r.skipped.includes('flask'));
});
test('poetry.lock: names normalized, dev category', () => {
  const r = parseAs('poetry.lock', 'poetry.lock');
  assert.deepEqual(pick(r), ['jinja2@2.11.2', 'pytest@6.0.0']);
  assert.equal(r.find((p) => p.name === 'pytest').dev, true);
});
test('go.mod: single and block requires, indirect, go + toolchain directives', () => {
  const r = require('../src/parsers/go').parseGoMod(fs.readFileSync(F('go.mod'), 'utf8'));
  assert.deepEqual(pick(r.packages), ['github.com/gin-gonic/gin@v1.6.0', 'golang.org/x/crypto@v0.0.0-20200622213623-75b288015ac9', 'golang.org/x/net@v0.7.0']);
  assert.equal(r.packages.find((p) => p.name === 'golang.org/x/crypto').indirect, true);
  assert.equal(r.goVersion, '1.22.1');
  assert.equal(r.toolchain, '1.26.4');
});
test('go.sum: de-duplicates /go.mod lines', () => {
  assert.deepEqual(pick(parseAs('go.sum', 'go.sum')), ['golang.org/x/net@v0.7.0', 'golang.org/x/text@v0.3.0']);
});
test('Cargo.lock: registry crates only', () => {
  assert.deepEqual(pick(parseAs('Cargo.lock', 'Cargo.lock')), ['smallvec@1.6.0', 'tokio@1.0.0']);
});
test('package.json: declared range floors, skips file:/tags', () => {
  const r = parseAs('package.json', 'package.json');
  assert.deepEqual(pick(r), ['jest@29.0.0', 'lodash@4.17.15', 'scoped@1.2.0']);
  assert.equal(r.find((p) => p.name === 'lodash').approximate, true);
  const { rangeFloor } = require('../src/parsers/npm');
  assert.equal(rangeFloor('^1.2.3'), '1.2.3'); assert.equal(rangeFloor('1.x'), '1.0.0'); assert.equal(rangeFloor('workspace:*'), null);
});
test('discover: lockfile beats package.json, skips node_modules, respects depth', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-disc-'));
  const w = (p, t = '{}') => { fs.mkdirSync(path.dirname(path.join(d, p)), { recursive: true }); fs.writeFileSync(path.join(d, p), t); };
  w('package.json'); w('package-lock.json'); w('svc/package.json'); w('node_modules/x/package-lock.json'); w('py/requirements.txt', ''); w('py/poetry.lock', ''); w('a/b/c/d/e/go.mod', '');
  const rel = P.discover(d, { maxDepth: 4 }).map((f) => path.relative(d, f)).sort();
  assert.deepEqual(rel, ['package-lock.json', 'py/poetry.lock', 'svc/package.json']);
  assert.equal(P.detectKind('/x/Cargo.lock').file, 'Cargo.lock');
  assert.equal(P.detectKind('/x/Gemfile.lock'), null);
});
