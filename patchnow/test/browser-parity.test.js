'use strict';
// The site's in-browser checker runs dist/patchnow-browser.js. It must give the same answers as the CLI.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const P = require('../src/parsers');
const core = require('../src/core');

test('browser bundle parses every supported fixture exactly like the CLI', () => {
  const file = path.join(__dirname, '..', 'dist', 'patchnow-browser.js');
  const ctx = { self: {} }; vm.createContext(ctx); vm.runInContext(fs.readFileSync(file, 'utf8'), ctx);
  const B = ctx.self.PatchParsers, BC = ctx.self.PatchCore;
  const F = (n) => fs.readFileSync(path.join(__dirname, 'fixtures/formats', n), 'utf8');
  const cases = [['package-lock.v3.json', 'package-lock.json'], ['package-lock.v1.json', 'package-lock.json'], ['package.json', 'package.json'], ['yarn.v1.lock', 'yarn.lock'], ['composer.lock', 'composer.lock'], ['requirements.txt', 'requirements.txt'], ['poetry.lock', 'poetry.lock'], ['go.mod', 'go.mod'], ['Cargo.lock', 'Cargo.lock']];
  for (const [fx, kind] of cases) assert.deepEqual(JSON.parse(JSON.stringify(B.KINDS[kind](F(fx)))), P.parseFile(kind, F(fx)), fx);
  assert.throws(() => B.KINDS['yarn.lock'](F('yarn.berry.lock')), /CLI only/);
  for (const [a, b] of [['1.2.3', '1.2.10'], ['1.0.0-rc2', '1.0.0'], ['2.0', '2.0.0']]) assert.equal(BC.cmpVer(a, b), core.cmpVer(a, b));
  assert.deepEqual(JSON.parse(JSON.stringify(B.runtimeAdvisories)), require('../src/data/runtime-advisories.json'));
});
