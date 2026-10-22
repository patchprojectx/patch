'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const pin = require('../src/actions/pin_patch');
const notify = require('../src/actions/notify');
const safe = require('../src/actions/safe_mode');
const revoke = require('../src/actions/revoke');
const report = require('../src/report');
const cli = require('../src/cli');
const smtp = require('../src/smtp');
const { redact } = require('../src/http');

const f = (o) => ({ kind: 'dependency', ecosystem: 'npm', name: 'lodash', version: '4.17.15', dev: false, id: 'GHSA-35jh-r3h4-6jhm', aliases: ['CVE-2021-23337'], cves: ['CVE-2021-23337'], severity: 'HIGH', score: 7.2, kev: null, epss: 0.2, fixed: '4.17.21', sources: ['package-lock.json'], source: 'package-lock.json', references: ['https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm'], ...o });
const ctx = (o) => ({ runId: 'test-run', dryRun: false, results: {}, rootDir: '/tmp', cfg: {}, scan: { intel: { kev: null } }, ...o });

function receiver(handler = (req, body, res) => { res.writeHead(200); res.end('{}'); }) {
  const hits = [];
  const srv = http.createServer((req, res) => { let b = ''; req.on('data', (d) => (b += d)); req.on('end', () => { hits.push({ method: req.method, url: req.url, headers: req.headers, body: b }); handler(req, b, res); }); });
  return new Promise((r) => srv.listen(0, '127.0.0.1', () => r({ srv, hits, url: 'http://127.0.0.1:' + srv.address().port })));
}

test('pin_patch.plan: one target per package that clears every advisory; manual when no fix', () => {
  const items = pin.plan([f({}), f({ id: 'GHSA-p6mc', fixed: '4.17.19' }), f({ name: 'nofix', id: 'GHSA-x', fixed: null }), f({ name: 'django', ecosystem: 'PyPI', version: '3.2.0', fixed: '3.2.25', sources: ['requirements.txt'] }), f({ name: 'left-pad', sources: ['yarn.lock'] })], '/repo');
  const by = Object.fromEntries(items.map((i) => [i.name, i]));
  assert.equal(by.lodash.to, '4.17.21'); assert.equal(by.lodash.strategy, 'npm'); assert.equal(by.lodash.ids.length, 2);
  assert.equal(by.nofix.strategy, 'manual'); assert.match(by.nofix.reason, /no fixed version/);
  assert.equal(by.django.strategy, 'requirements');
  assert.equal(by['left-pad'].strategy, 'manual'); assert.match(by['left-pad'].reason, /yarn\.lock/);
});
test('pin_patch.rewriteRequirements keeps extras/markers/comments and drops stale hashes', () => {
  const r = pin.rewriteRequirements('Django==3.2.0  # web\nrequests[socks] == 2.25.0 ; python_version>"3"\nother==1.0\nurllib3==1.26.4 --hash=sha256:abc\n', 'django', '3.2.25');
  assert.equal(r.changed, 1); assert.match(r.text, /^Django==3\.2\.25  # web$/m); assert.match(r.text, /^other==1\.0$/m);
  const r2 = pin.rewriteRequirements('requests[socks] == 2.25.0 ; python_version>"3"\n', 'requests', '2.31.0');
  assert.equal(r2.text, 'requests[socks] == 2.31.0 ; python_version>"3"\n');
  assert.equal(pin.rewriteRequirements('urllib3==1.26.4 --hash=sha256:abc\n', 'urllib3', '1.26.18').text, 'urllib3==1.26.18\n');
});
test('pin_patch dry run reports the plan and touches nothing', async () => {
  const r = await pin.execute({}, [f({})], ctx({ dryRun: true }));
  assert.equal(r.status, 'dry-run'); assert.equal(r.planned[0].to, '4.17.21');
});
test('notify: message text, dry run sends nothing, webhook + slack + telegram + ntfy delivered and signed', async () => {
  const rx = await receiver();
  process.env.T_WEBHOOK = rx.url + '/hook'; process.env.T_SLACK = rx.url + '/slack'; process.env.T_SECRET = 's3cret'; process.env.T_TG = '123:abc';
  process.env.PATCHNOW_TELEGRAM_API = rx.url;
  const o = { webhook: { url_env: 'T_WEBHOOK', secret_env: 'T_SECRET' }, slack: { url_env: 'T_SLACK' }, telegram: { token_env: 'T_TG', chat_id: '42' }, ntfy: { topic: 'pn-test', server: rx.url } };
  const findings = [f({ kev: [{ cve: 'CVE-2021-23337', dateAdded: '2026-01-01' }] })];
  const dry = await notify.execute(o, findings, ctx({ dryRun: true }));
  assert.equal(dry.status, 'dry-run'); assert.equal(rx.hits.length, 0);
  const r = await notify.execute(o, findings, ctx({ results: { pin_patch: { status: 'committed', pr: { url: 'https://example.test/pr/1' } } } }));
  assert.equal(r.status, 'sent', JSON.stringify(r));
  const hook = rx.hits.find((h) => h.url === '/hook'); const body = JSON.parse(hook.body);
  assert.equal(hook.headers['x-patchnow-signature'], 'sha256=' + crypto.createHmac('sha256', 's3cret').update(hook.body).digest('hex'));
  assert.equal(body.event, 'patchnow.alert'); assert.equal(body.findings[0].kev, true); assert.match(body.text, /pr\/1/);
  assert.match(JSON.parse(rx.hits.find((h) => h.url === '/slack').body).text, /1 known exploited/);
  const tg = rx.hits.find((h) => h.url === '/bot123:abc/sendMessage'); assert.equal(JSON.parse(tg.body).chat_id, '42');
  const nt = rx.hits.find((h) => h.url === '/pn-test'); assert.equal(nt.headers.priority, 'urgent'); assert.match(nt.body, /lodash@4\.17\.15/);
  const missing = await notify.execute({ slack: { url_env: 'NOPE_NOT_SET' } }, findings, ctx());
  assert.equal(missing.status, 'failed'); assert.match(missing.errors.slack, /NOPE_NOT_SET/);
  rx.srv.close(); delete process.env.PATCHNOW_TELEGRAM_API;
});
test('notify email: SMTP conversation against a local server', async () => {
  const got = { lines: [] };
  const srv = net.createServer((s) => {
    let data = false, buf = '';
    s.write('220 test ESMTP\r\n');
    s.on('data', (d) => {
      buf += d; let i;
      while ((i = buf.indexOf('\r\n')) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 2);
        if (data) { if (line === '.') { data = false; s.write('250 queued\r\n'); } else got.lines.push(line); continue; }
        if (/^EHLO/.test(line)) s.write('250-test\r\n250 AUTH PLAIN\r\n');
        else if (/^MAIL|^RCPT/.test(line)) s.write('250 ok\r\n');
        else if (line === 'DATA') { data = true; s.write('354 go\r\n'); }
        else if (line === 'QUIT') { s.write('221 bye\r\n'); s.end(); }
        else s.write('500 ?\r\n');
      }
    });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const r = await notify.execute({ email: { host: '127.0.0.1', port: srv.address().port, secure: false, from: 'patchnow <alerts@example.test>', to: ['oncall@example.test'] } }, [f({})], ctx());
  assert.equal(r.status, 'sent', JSON.stringify(r));
  assert.ok(got.lines.some((l) => /^Subject: patchnow: 1 finding matched policy$/.test(l)));
  assert.ok(got.lines.some((l) => /lodash@4\.17\.15/.test(l)));
  // credentials are refused without TLS
  await assert.rejects(smtp.send({ host: '127.0.0.1', port: srv.address().port, secure: false, user: 'u', pass: 'p', from: 'a@b', to: 'c@d', subject: 's', text: 't' }), /STARTTLS/);
  srv.close();
});
test('safe_mode: webhook signed; render hook; vercel promote path; dry run', async () => {
  const rx = await receiver((req, b, res) => { res.writeHead(req.url.includes('promote') ? 201 : 200); res.end('{"deploy":{"id":"dep-1"}}'); });
  process.env.T_SAFE = rx.url + '/flag'; process.env.T_RENDER = rx.url + '/deploy/srv-x?key=k'; process.env.T_VERCEL = 'vtok'; process.env.PATCHNOW_VERCEL_API = rx.url;
  assert.equal((await safe.execute({ provider: 'webhook', url_env: 'T_SAFE' }, [f({})], ctx({ dryRun: true }))).status, 'dry-run');
  assert.equal(rx.hits.length, 0);
  const w = await safe.execute({ provider: 'webhook', url_env: 'T_SAFE', secret_env: 'T_SECRET' }, [f({})], ctx());
  assert.equal(w.status, 'triggered'); assert.equal(JSON.parse(rx.hits[0].body).event, 'patchnow.safe_mode');
  const rd = await safe.execute({ provider: 'render_deploy_hook', url_env: 'T_RENDER' }, [f({})], ctx());
  assert.equal(rd.deploy, 'dep-1'); assert.equal(rx.hits[1].method, 'POST');
  const v = await safe.execute({ provider: 'vercel_promote', token_env: 'T_VERCEL', project_id: 'prj_1', deployment_id: 'dpl_2', team_id: 'team_3' }, [f({})], ctx());
  assert.equal(v.http, 201); assert.equal(rx.hits[2].url, '/v10/projects/prj_1/promote/dpl_2?teamId=team_3'); assert.equal(rx.hits[2].headers.authorization, 'Bearer vtok');
  await assert.rejects(safe.execute({ provider: 'nope' }, [], ctx()), /provider/);
  rx.srv.close(); delete process.env.PATCHNOW_VERCEL_API;
});
test('revoke: dry run unless armed AND confirm; unauthenticated GitHub call; never leaks token values', async () => {
  const rx = await receiver((req, b, res) => { res.writeHead(202); res.end('{}'); });
  process.env.GITHUB_API_URL = rx.url; process.env.T_PAT = 'ghp_' + 'A'.repeat(36); process.env.T_BAD = 'not-a-token';
  const o = { github_tokens_env: ['T_PAT', 'T_BAD', 'T_MISSING'] };
  const d1 = await revoke.execute(o, [f({})], ctx({ dryRun: true }));
  const d2 = await revoke.execute(o, [f({})], ctx());
  assert.equal(d1.status, 'dry-run'); assert.equal(d2.status, 'dry-run'); assert.match(d2.reason, /confirm/); assert.equal(rx.hits.length, 0);
  const live = await revoke.execute({ ...o, confirm: true }, [f({})], ctx());
  assert.equal(live.status, 'revoked'); assert.equal(live.githubHttp, 202); assert.equal(live.githubRevoked, 1);
  assert.equal(rx.hits[0].url, '/credentials/revoke'); assert.equal(rx.hits[0].headers.authorization, undefined);
  assert.deepEqual(JSON.parse(rx.hits[0].body), { credentials: [process.env.T_PAT] });
  assert.ok(!JSON.stringify(live).includes(process.env.T_PAT)); assert.ok(!JSON.stringify(d2).includes(process.env.T_PAT));
  assert.deepEqual(live.github.map((g) => [g.env, g.present, g.valid]), [['T_PAT', true, true], ['T_BAD', true, false], ['T_MISSING', false, false]]);
  rx.srv.close(); delete process.env.GITHUB_API_URL;
});
test('report: SARIF 2.1.0 structure, levels, line locations; text report', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-sarif-'));
  fs.writeFileSync(path.join(d, 'package-lock.json'), '{\n  "packages": {\n    "node_modules/lodash": {}\n  }\n}\n');
  const res = { tool: { name: 'patchnow', version: '0.1.0' }, dir: d, finishedAt: 'now', files: [{ path: 'package-lock.json', packages: 1 }], runtimes: {}, packagesScanned: 1, intel: { kev: null, epss: false }, errors: [],
    findings: [f({ kev: [{ cve: 'CVE-2021-23337', dateAdded: '2026-01-01' }] }), f({ id: 'GHSA-low', severity: 'LOW', score: 2.1 })] };
  const s = report.sarif(res);
  assert.equal(s.version, '2.1.0'); assert.equal(s.runs[0].tool.driver.rules.length, 2);
  assert.equal(s.runs[0].results[0].level, 'error'); assert.equal(s.runs[0].results[1].level, 'note');
  assert.equal(s.runs[0].results[0].locations[0].physicalLocation.region.startLine, 3);
  assert.match(s.runs[0].results[0].message.text, /CISA KEV/);
  assert.equal(s.runs[0].tool.driver.rules[0].properties['security-severity'], '7.2');
  const t = report.text(res, { color: false });
  assert.match(t, /2 findings in 1 package versions · 1 known exploited/); assert.match(t, /HIGH\s+7\.2\s+YES/);
});
test('cli: args, --fail-on thresholds, intervals', () => {
  const a = cli.parseArgs(['scan', '--format', 'sarif', '--no-epss', '--dir=x']);
  assert.deepEqual([a._[0], a.format, a['no-epss'], a.dir], ['scan', 'sarif', true, 'x']);
  assert.throws(() => cli.parseArgs(['scan', '--format']), /needs a value/);
  const fs_ = [f({ severity: 'HIGH' })];
  assert.equal(cli.failOn('kev', fs_), false); assert.equal(cli.failOn('high', fs_), true); assert.equal(cli.failOn('critical', fs_), false);
  assert.equal(cli.failOn('critical', [f({ severity: 'LOW', kev: [{}] })]), true);
  assert.equal(cli.failOn('none', fs_), false); assert.throws(() => cli.failOn('bad', fs_), /fail-on/);
  assert.equal(cli.parseInterval('15m'), 900000); assert.equal(cli.parseInterval('1h'), 3600000); assert.throws(() => cli.parseInterval('10s'), /at least/);
});
test('redact strips secrets from URLs', () => {
  assert.equal(redact('https://api.telegram.org/bot123:ABC-def/sendMessage'), 'https://api.telegram.org/bot***/sendMessage');
  assert.equal(redact('https://api.render.com/deploy/srv-abc?key=xyz'), 'https://api.render.com/deploy/***?key=***');
  assert.equal(redact('https://hooks.slack.com/services/T/B/C'), 'https://hooks.slack.com/services/***');
});
test('pin_patch commit identity: options, GitHub Actions bot, local fallback', () => {
  const saved = process.env.GITHUB_ACTIONS;
  process.env.GITHUB_ACTIONS = 'true';
  assert.deepEqual(pin.authorOf({}), { name: 'github-actions[bot]', email: '41898282+github-actions[bot]@users.noreply.github.com' });
  assert.deepEqual(pin.authorOf({ author_name: 'Sec Bot', author_email: 'sec@example.test' }), { name: 'Sec Bot', email: 'sec@example.test' });
  process.env.GITHUB_ACTIONS = '';
  assert.deepEqual(pin.authorOf({}), { name: 'patchnow', email: 'patchnow@localhost' });
  if (saved === undefined) delete process.env.GITHUB_ACTIONS; else process.env.GITHUB_ACTIONS = saved;
});
