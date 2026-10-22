'use strict';
/**
 * revoke — revoke credentials that may be exposed by an exploited dependency.
 * Executes only when the policy is armed AND revoke.confirm is true. Otherwise it reports what it would do.
 *   github_tokens_env: [ENV_NAME, ...]  token values are read from these env vars and sent to
 *                      POST https://api.github.com/credentials/revoke (unauthenticated endpoint; 202 = accepted).
 *   npm_token_ids:     [id, ...]        `npm token revoke <id>` with the npm auth already configured in the environment.
 * Token values are never written to logs, audit or output; only env var names and a 4-character suffix.
 */
const { execFileSync } = require('child_process');
const github = require('../github');
const GH = /^(ghp_|github_pat_|gho_|ghu_|ghr_)/;

async function execute(o, findings, ctx) {
  const envs = o.github_tokens_env || [], npmIds = o.npm_token_ids || [];
  if (!envs.length && !npmIds.length) return { status: 'nothing-configured' };
  const gh = envs.map((name) => { const v = process.env[name]; return { env: name, present: !!v, valid: !!v && GH.test(v), suffix: v ? '…' + v.slice(-4) : null, value: v }; });
  const report = { github: gh.map(({ value, ...r }) => r), npm: npmIds.map((id) => ({ id })) };
  const live = !ctx.dryRun && o.confirm === true;
  if (!live) return { status: 'dry-run', reason: ctx.dryRun ? 'policy not armed / --dry-run' : 'revoke.confirm is not true', ...report };
  const creds = gh.filter((g) => g.valid).map((g) => g.value);
  if (creds.length) {
    try { report.githubHttp = await github.revokeCredentials(creds.slice(0, 1000)); report.githubRevoked = creds.length; }
    catch (e) { report.githubError = e.message; }
  }
  for (const n of report.npm) {
    try { execFileSync(o.npm_bin || 'npm', ['token', 'revoke', String(n.id)], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 60000 }); n.revoked = true; }
    catch (e) { n.error = String(e.stderr || e.message).trim().split('\n').pop(); }
  }
  const failed = report.githubError || report.npm.some((n) => n.error);
  return { status: failed ? 'partial' : 'revoked', ...report };
}
module.exports = { execute };
