'use strict';
/**
 * safe_mode — flip production into a degraded-but-safe state while a patch lands.
 * Providers:
 *   render_deploy_hook  POST to a Render deploy hook (e.g. a service/branch configured as a maintenance page). url_env required.
 *   vercel_promote      POST https://api.vercel.com/v10/projects/{project_id}/promote/{deployment_id} (instant promote of a known-safe deployment). token_env, project_id, deployment_id; team_id optional.
 *   webhook             POST JSON to any endpoint (feature-flag service, internal kill switch). url_env required; secret_env adds X-Patchnow-Signature: sha256=HMAC(body).
 */
const crypto = require('crypto');
const { request, redact } = require('../http');
const env = (name, what) => { const v = name && process.env[name]; if (!v) throw new Error(what + ': environment variable ' + (name || '(unset)') + ' is not set'); return v; };
const VERCEL = () => (process.env.PATCHNOW_VERCEL_API || 'https://api.vercel.com').replace(/\/+$/, '');

function payload(findings, ctx, event) {
  return { event, run: ctx.runId, armed: !ctx.dryRun, at: new Date().toISOString(), findings: findings.map((f) => ({ id: f.id, cves: f.cves, package: f.name, version: f.version, ecosystem: f.ecosystem, severity: f.severity, kev: !!f.kev, epss: f.epss, fixed: f.fixed })) };
}
function sign(body, secret) { return 'sha256=' + crypto.createHmac('sha256', secret).update(body).digest('hex'); }

async function execute(o, findings, ctx) {
  const provider = o.provider;
  if (!['render_deploy_hook', 'vercel_promote', 'webhook'].includes(provider)) throw new Error('safe_mode.provider must be render_deploy_hook, vercel_promote or webhook');
  if (provider === 'render_deploy_hook') {
    const url = ctx.dryRun ? process.env[o.url_env] || '(' + o.url_env + ')' : env(o.url_env, 'safe_mode');
    if (ctx.dryRun) return { status: 'dry-run', provider, would: 'POST ' + redact(url) };
    const r = await request(url, { method: 'POST', expect: [200, 201, 202], retries: 1 });
    return { status: 'triggered', provider, http: r.status, deploy: r.data && r.data.deploy ? r.data.deploy.id : undefined };
  }
  if (provider === 'vercel_promote') {
    for (const k of ['project_id', 'deployment_id']) if (!o[k]) throw new Error('safe_mode.' + k + ' is required for vercel_promote');
    const q = o.team_id ? '?teamId=' + encodeURIComponent(o.team_id) : '';
    const url = VERCEL() + '/v10/projects/' + encodeURIComponent(o.project_id) + '/promote/' + encodeURIComponent(o.deployment_id) + q;
    if (ctx.dryRun) return { status: 'dry-run', provider, would: 'POST ' + url };
    const token = env(o.token_env || 'VERCEL_TOKEN', 'safe_mode');
    const r = await request(url, { method: 'POST', headers: { Authorization: 'Bearer ' + token }, expect: [200, 201, 202], retries: 1 });
    return { status: 'triggered', provider, http: r.status };
  }
  const url = ctx.dryRun ? process.env[o.url_env] || '(' + o.url_env + ')' : env(o.url_env, 'safe_mode');
  const body = JSON.stringify(payload(findings, ctx, 'patchnow.safe_mode'));
  if (ctx.dryRun) return { status: 'dry-run', provider, would: (o.method || 'POST') + ' ' + redact(url) };
  const headers = { 'Content-Type': 'application/json' };
  if (o.secret_env) headers['X-Patchnow-Signature'] = sign(body, env(o.secret_env, 'safe_mode'));
  const r = await request(url, { method: o.method || 'POST', headers, body, expect: [200, 201, 202, 204], retries: 1 });
  return { status: 'triggered', provider, http: r.status };
}
module.exports = { execute, payload, sign };
