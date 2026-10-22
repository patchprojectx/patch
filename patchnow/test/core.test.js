'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const C = require('../src/core');

test('cmpVer: semver, prerelease, PEP 440, go pseudo-versions', () => {
  const lt = (a, b) => assert.equal(C.cmpVer(a, b), -1, a + ' < ' + b);
  lt('1.2.3', '1.2.10'); lt('1.2.3-rc.1', '1.2.3'); lt('1.0.0-alpha', '1.0.0-beta'); lt('1.0.0-rc2', '1.0.0-rc10');
  lt('2.0', '2.0.1'); lt('1.0.0', '1.0.0.post1'); lt('v0.0.0-20200622213623-75b288015ac9', '0.17.0'); lt('4.17.15', '4.17.21');
  assert.equal(C.cmpVer('1.0', '1.0.0'), 0); assert.equal(C.cmpVer('v1.2.3', '1.2.3'), 0); assert.equal(C.cmpVer('1.2.3+build', '1.2.3'), 0);
});
test('inRange: introduced/fixed, last_affected, multiple windows, GIT ignored', () => {
  const r = { type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.6' }, { introduced: '2.0.0' }, { fixed: '2.0.3' }] };
  assert.equal(C.inRange(r, '1.2.5'), true); assert.equal(C.inRange(r, '1.2.6'), false); assert.equal(C.inRange(r, '1.9.0'), false);
  assert.equal(C.inRange(r, '2.0.2'), true); assert.equal(C.inRange(r, '2.0.3'), false);
  assert.equal(C.inRange({ type: 'ECOSYSTEM', events: [{ introduced: '1.0.0' }, { last_affected: '1.4.0' }] }, '1.4.0'), true);
  assert.equal(C.inRange({ type: 'ECOSYSTEM', events: [{ introduced: '1.0.0' }, { last_affected: '1.4.0' }] }, '1.4.1'), false);
  assert.equal(C.inRange({ type: 'GIT', events: [{ introduced: '0' }] }, '1.0.0'), null);
});
const vuln = { id: 'GHSA-test', aliases: ['CVE-2021-44906'], affected: [{ package: { ecosystem: 'npm', name: 'minimist' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '0.2.4' }, { introduced: '1.0.0' }, { fixed: '1.2.6' }] }] }] };
test('isAffected / fixedFor pick the fix from the range containing the version', () => {
  assert.equal(C.isAffected(vuln, { ecosystem: 'npm', name: 'minimist', version: '1.2.5' }), true);
  assert.equal(C.isAffected(vuln, { ecosystem: 'npm', name: 'minimist', version: '1.2.6' }), false);
  assert.equal(C.isAffected(vuln, { ecosystem: 'PyPI', name: 'minimist', version: '1.2.5' }), false);
  assert.equal(C.fixedFor(vuln, { ecosystem: 'npm', name: 'minimist', version: '0.0.10' }), '0.2.4');
  assert.equal(C.fixedFor(vuln, { ecosystem: 'npm', name: 'minimist', version: '1.2.5' }), '1.2.6');
  assert.equal(C.fixedFor({ affected: [{ package: { ecosystem: 'npm', name: 'x' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }] }] }, { ecosystem: 'npm', name: 'x', version: '1.0.0' }), null);
  assert.equal(C.upgradeTarget(['4.17.19', '4.17.21', null, '4.17.12']), '4.17.21');
});
test('name normalization for PyPI and Packagist', () => {
  const v = { affected: [{ package: { ecosystem: 'PyPI', name: 'PyYAML' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '5.4' }] }] }] };
  assert.equal(C.isAffected(v, { ecosystem: 'PyPI', name: 'pyyaml', version: '5.3' }), true);
});
test('cvss3 base scores and severity buckets', () => {
  assert.equal(C.cvss3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.equal(C.cvss3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'), 10);
  assert.equal(C.cvss3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'), 7.5);
  assert.equal(C.cvss3('CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'), 7.8);
  assert.equal(C.cvss3('garbage'), null);
  assert.equal(C.bucket(9.0), 'CRITICAL'); assert.equal(C.bucket(7.0), 'HIGH'); assert.equal(C.bucket(4.0), 'MODERATE'); assert.equal(C.bucket(0.1), 'LOW');
  assert.deepEqual(C.severityOf({ severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] }), { label: 'CRITICAL', score: 9.8 });
  assert.equal(C.severityOf({ database_specific: { severity: 'MODERATE' }, severity: [] }).label, 'MODERATE');
});
test('cvesOf collects CVE ids from id and aliases', () => {
  assert.deepEqual(C.cvesOf({ id: 'GHSA-x', aliases: ['CVE-2021-1', 'PYSEC-1'] }), ['CVE-2021-1']);
  assert.deepEqual(C.cvesOf({ id: 'CVE-2020-2', aliases: [] }), ['CVE-2020-2']);
});
test('runtime table: patched / vulnerable / eol / newer', () => {
  const table = require('../src/data/runtime-advisories.json');
  const s = (rt, v) => C.checkRuntime(table, rt, v).status;
  assert.equal(s('node', '22.23.4'), 'patched'); assert.equal(s('node', '22.11.0'), 'vulnerable'); assert.equal(s('node', '20.19.2'), 'eol');
  assert.equal(s('php', '8.3.36'), 'patched'); assert.equal(s('php', '8.3.35'), 'vulnerable');
  assert.equal(s('go', '1.26.4'), 'vulnerable'); assert.equal(s('go', '1.27.3'), 'patched');
});
