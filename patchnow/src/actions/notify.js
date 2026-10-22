'use strict';
/**
 * notify — tell humans. Channels (any combination):
 *   webhook:  { url_env, secret_env? }            JSON payload; optional HMAC-SHA256 X-Patchnow-Signature
 *   slack:    { url_env }                         Slack incoming webhook
 *   telegram: { token_env, chat_id }              Bot API sendMessage
 *   ntfy:     { topic, server?, token_env? }      ntfy.sh (or self-hosted) push
 *   email:    { host, port?, secure?, user_env?, pass_env?, from, to }   SMTP
 * In a dry run nothing is sent unless send_in_dry_run: true (useful for testing channels).
 */
const smtp = require('../smtp');
const { request, redact } = require('../http');
const { payload, sign } = require('./safe_mode');
const TG = () => (process.env.PATCHNOW_TELEGRAM_API || 'https://api.telegram.org').replace(/\/+$/, '');
const need = (name, ch) => { const v = name && process.env[name]; if (!v) throw new Error(ch + ': environment variable ' + (name || '(unset)') + ' is not set'); return v; };

function message(findings, ctx) {
  const kev = findings.filter((f) => f.kev).length;
  const title = (ctx.dryRun ? '[dry run] ' : '') + 'patchnow: ' + findings.length + ' finding' + (findings.length > 1 ? 's' : '') + ' matched policy' + (kev ? ' (' + kev + ' known exploited)' : '');
  const lines = findings.slice(0, 25).map((f) => '• ' + f.name + '@' + f.version + ' — ' + (f.cves[0] || f.id) + ' ' + f.severity + (f.kev ? ' · KEV' : '') + (f.epss != null ? ' · EPSS ' + f.epss.toFixed(2) : '') + (f.fixed ? ' → ' + f.fixed : ' · no fix'));
  if (findings.length > 25) lines.push('…and ' + (findings.length - 25) + ' more');
  const acts = Object.entries(ctx.results || {}).map(([k, r]) => k + ': ' + r.status + (r.pr && r.pr.url ? ' ' + r.pr.url : r.branch ? ' ' + r.branch : ''));
  if (acts.length) lines.push('', 'Actions:', ...acts.map((a) => '  ' + a));
  if (ctx.repo) lines.push('', 'Repository: ' + ctx.repo);
  lines.push('', 'run ' + ctx.runId);
  return { title, text: lines.join('\n') };
}

async function execute(o, findings, ctx) {
  const channels = ['webhook', 'slack', 'telegram', 'ntfy', 'email'].filter((c) => o[c]);
  if (!channels.length) return { status: 'nothing-configured' };
  const m = message(findings, ctx);
  if (ctx.dryRun && !o.send_in_dry_run) return { status: 'dry-run', channels, preview: m.title };
  const sent = {}, errors = {};
  await Promise.all(channels.map(async (ch) => {
    try { sent[ch] = await SEND[ch](o[ch], m, findings, ctx); } catch (e) { errors[ch] = redact(e.message); }
  }));
  return { status: Object.keys(errors).length ? (Object.keys(sent).length ? 'partial' : 'failed') : 'sent', channels, sent, errors };
}
const SEND = {
  async webhook(c, m, findings, ctx) {
    const body = JSON.stringify({ ...payload(findings, ctx, 'patchnow.alert'), title: m.title, text: m.text, actions: ctx.results || {} });
    const headers = { 'Content-Type': 'application/json' };
    if (c.secret_env) headers['X-Patchnow-Signature'] = sign(body, need(c.secret_env, 'webhook'));
    const r = await request(need(c.url_env, 'webhook'), { method: 'POST', headers, body, expect: [200, 201, 202, 204], retries: 2 });
    return r.status;
  },
  async slack(c, m) { return (await request(need(c.url_env, 'slack'), { method: 'POST', json: { text: '*' + m.title + '*\n' + m.text }, expect: [200], retries: 2 })).status; },
  async telegram(c, m) {
    if (!c.chat_id) throw new Error('telegram.chat_id is required');
    return (await request(TG() + '/bot' + need(c.token_env, 'telegram') + '/sendMessage', { method: 'POST', json: { chat_id: c.chat_id, text: m.title + '\n\n' + m.text, disable_web_page_preview: true }, expect: [200], retries: 2 })).status;
  },
  async ntfy(c, m, findings) {
    if (!c.topic) throw new Error('ntfy.topic is required');
    const headers = { Title: m.title.replace(/[^\x20-\x7e]/g, ''), Priority: findings.some((f) => f.kev) ? 'urgent' : 'high', Tags: 'rotating_light' };
    if (c.token_env) headers.Authorization = 'Bearer ' + need(c.token_env, 'ntfy');
    return (await request((c.server || 'https://ntfy.sh').replace(/\/+$/, '') + '/' + encodeURIComponent(c.topic), { method: 'POST', headers, body: m.text, expect: [200], retries: 2 })).status;
  },
  async email(c, m) {
    for (const k of ['host', 'from', 'to']) if (!c[k]) throw new Error('email.' + k + ' is required');
    const r = await smtp.send({ host: c.host, port: c.port || 587, secure: c.secure, user: c.user_env ? need(c.user_env, 'email') : undefined, pass: c.pass_env ? need(c.pass_env, 'email') : undefined, from: c.from, to: c.to, subject: m.title, text: m.text, rejectUnauthorized: c.tls_reject_unauthorized !== false });
    return 'accepted ' + r.accepted.length;
  },
};
module.exports = { execute, message };
