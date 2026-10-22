'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const config = require('../src/config');
const policy = require('../src/policy');
const { State, Audit } = require('../src/store');

const f = (o) => ({ kind: 'dependency', ecosystem: 'npm', name: 'pkg', version: '1.0.0', dev: false, id: 'GHSA-aaaa', aliases: [], cves: ['CVE-2026-0001'], severity: 'HIGH', score: 7.5, kev: null, epss: 0.1, fixed: '1.0.1', ...o });
const cfg = (o) => config.merge(config.DEFAULTS, o);

test('triggers: entries are ORed, keys inside one entry are ANDed', () => {
  const c = cfg({ triggers: [{ kev: true }, { severity: 'high', packages: ['lodash'] }] });
  const d = policy.evaluate([f({ kev: [{ cve: 'CVE-2026-0001' }] }), f({ name: 'lodash' }), f({ name: 'other' }), f({ name: 'lodash', severity: 'MODERATE' })], c);
  assert.deepEqual(d.map((x) => x.decision), ['fire', 'fire', 'no-trigger', 'no-trigger']);
  assert.deepEqual(d.map((x) => x.trigger), [0, 1, undefined, undefined]);
});
test('severity is a minimum; medium is an alias of moderate', () => {
  assert.equal(policy.matchTrigger(f({ severity: 'CRITICAL' }), { severity: 'high' }), true);
  assert.equal(policy.matchTrigger(f({ severity: 'LOW' }), { severity: 'high' }), false);
  assert.equal(policy.matchTrigger(f({ severity: 'MODERATE' }), { severity: 'medium' }), true);
  assert.equal(policy.matchTrigger(f({ severity: 'UNRATED' }), { severity: 'low' }), false);
});
test('epss and cvss comparators; missing values never match', () => {
  assert.equal(policy.matchTrigger(f({ epss: 0.51 }), { epss: '>0.5' }), true);
  assert.equal(policy.matchTrigger(f({ epss: 0.5 }), { epss: '>0.5' }), false);
  assert.equal(policy.matchTrigger(f({ epss: 0.5 }), { epss: '>=0.5' }), true);
  assert.equal(policy.matchTrigger(f({ epss: null }), { epss: '>0' }), false);
  assert.equal(policy.matchTrigger(f({ score: 9.8 }), { cvss: '>=9' }), true);
  assert.equal(policy.matchTrigger(f({ score: 9.8 }), { cvss: 9 }), true);
  assert.equal(policy.matchTrigger(f({ score: null }), { cvss: '>=0' }), false);
});
test('ecosystems, include_dev, runtime, has_fix filters', () => {
  assert.equal(policy.matchTrigger(f({ ecosystem: 'PyPI' }), { ecosystems: ['npm'] }), false);
  assert.equal(policy.matchTrigger(f({ ecosystem: 'PyPI' }), { ecosystems: ['pypi'] }), true);
  assert.equal(policy.matchTrigger(f({ dev: true }), { include_dev: false }), false);
  assert.equal(policy.matchTrigger(f({ kind: 'runtime' }), { runtime: true }), true);
  assert.equal(policy.matchTrigger(f({}), { runtime: true }), false);
  assert.equal(policy.matchTrigger(f({ fixed: null }), { has_fix: true }), false);
});
test('ignore by OSV id, alias or CVE, with expiry and per-package scope', () => {
  const now = new Date('2026-10-22T12:00:00Z');
  const c = cfg({ triggers: [{ severity: 'low' }], ignore: [
    { id: 'CVE-2026-0001', reason: 'not reachable', expires: '2026-12-31' },
    { id: 'GHSA-old', reason: 'expired', expires: '2026-10-21' },
    { id: 'GHSA-scoped', reason: 'only in tool', packages: ['tool'] },
    { id: 'GHSA-today', reason: 'last day', expires: '2026-10-22' },
  ] });
  const d = policy.evaluate([f({}), f({ id: 'GHSA-old', cves: [] }), f({ id: 'GHSA-scoped', cves: [] }), f({ id: 'GHSA-scoped', cves: [], name: 'tool' }), f({ id: 'GHSA-today', cves: [] })], c, now);
  assert.deepEqual(d.map((x) => x.decision), ['ignored', 'fire', 'fire', 'ignored', 'ignored']);
  assert.match(d[0].reason, /not reachable \(until 2026-12-31\)/);
});
test('packages.only / packages.exclude', () => {
  const d = policy.evaluate([f({ name: 'a' }), f({ name: 'b' })], cfg({ triggers: [{ severity: 'low' }], packages: { only: ['a', 'b'], exclude: ['b'] } }));
  assert.deepEqual(d.map((x) => x.decision), ['fire', 'filtered']);
});
test('config: template is valid, defaults are safe, validation errors are specific', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-cfg-'));
  fs.writeFileSync(path.join(d, 'patch.yml'), config.TEMPLATE);
  const c = config.load(path.join(d, 'patch.yml'));
  assert.equal(c.armed, false);
  assert.deepEqual(c.triggers, [{ kev: true }, { severity: 'critical' }, { epss: '>0.5' }]);
  assert.deepEqual(c.actions.map((a) => Object.keys(a)[0]), ['pin_patch', 'notify']);
  const errs = config.validate(config.merge(config.DEFAULTS, { armed: 'yes', triggers: [{ sev: 'x' }, { severity: 'urgent' }, { epss: 'high' }], ignore: [{ id: 'X' }], actions: [{ explode: {} }] }));
  assert.ok(errs.some((e) => /armed/.test(e)));
  assert.ok(config.validate(config.merge(config.DEFAULTS, { armd: true, scan: { runtime: 'x' } })).length === 2);
  assert.ok(errs.some((e) => /unknown key "sev"/.test(e)));
  assert.ok(errs.some((e) => /severity must be/.test(e)));
  assert.ok(errs.some((e) => /epss must look like/.test(e)));
  assert.ok(errs.some((e) => /ignore\[0\]\.reason/.test(e)));
  assert.ok(errs.some((e) => /actions\[0\]/.test(e)));
  assert.ok(config.validate(config.merge(config.DEFAULTS, { actions: [{ pin_patch: { bracnh_prefix: 'x' } }] })).some((e) => /unknown key "bracnh_prefix"/.test(e)));
  assert.throws(() => config.load(path.join(d, 'nope.yml')), /patchnow init/);
});
test('state dedupe and refire window; audit appends JSONL', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-state-'));
  const s = new State(path.join(d, 's/state.json'));
  assert.equal(s.seen('k'), false);
  s.mark('k', { id: 'X' }); s.save();
  const s2 = new State(path.join(d, 's/state.json'));
  assert.equal(s2.seen('k'), true);
  assert.equal(s2.seen('k', 1, Date.now() + 2 * 86400e3), false);
  const a = new Audit(path.join(d, 'a/audit.jsonl'), 'r1'); a.write('x', { n: 1 }); a.write('y', {});
  const lines = fs.readFileSync(path.join(d, 'a/audit.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(lines.length, 2); assert.equal(lines[0].run, 'r1'); assert.equal(lines[0].type, 'x');
  assert.equal(policy.keyOf(f({})), 'npm|pkg|1.0.0|GHSA-aaaa');
});
test('examples/patch.full.yml and examples/patch.yml validate', () => {
  for (const f of ['patch.full.yml', 'patch.yml']) assert.doesNotThrow(() => config.load(path.join(__dirname, '..', 'examples', f)));
  assert.equal(config.TEMPLATE, fs.readFileSync(path.join(__dirname, '..', 'examples', 'patch.yml'), 'utf8'));
});
