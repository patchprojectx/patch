'use strict';
/** Minimal GitHub REST client (pull requests, labels, credential revocation). Base URL: GITHUB_API_URL (set by Actions) or api.github.com. */
const { request } = require('./http');
const apiBase = () => (process.env.GITHUB_API_URL || 'https://api.github.com').replace(/\/+$/, '');
const headers = (token) => ({ Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', ...(token ? { Authorization: 'Bearer ' + token } : {}) });

async function createPull({ repo, token, title, head, base, body, draft = false }) {
  const r = await request(apiBase() + '/repos/' + repo + '/pulls', { method: 'POST', headers: headers(token), json: { title, head, base, body, draft, maintainer_can_modify: true }, expect: [201, 422], retries: 1 });
  if (r.status === 422) {
    // a PR for this head may already exist
    const ex = await request(apiBase() + '/repos/' + repo + '/pulls?state=open&head=' + encodeURIComponent(repo.split('/')[0] + ':' + head), { headers: headers(token), expect: [200] });
    if (Array.isArray(ex.data) && ex.data[0]) return { number: ex.data[0].number, url: ex.data[0].html_url, existing: true };
    const e = new Error('GitHub rejected the pull request: ' + JSON.stringify(r.data && (r.data.errors || r.data.message))); e.status = 422; throw e;
  }
  return { number: r.data.number, url: r.data.html_url };
}
async function addLabels({ repo, token, number, labels }) {
  if (!labels || !labels.length) return;
  await request(apiBase() + '/repos/' + repo + '/issues/' + number + '/labels', { method: 'POST', headers: headers(token), json: { labels }, expect: [200, 201], retries: 1 });
}
/** POST /credentials/revoke — unauthenticated by design (authenticated requests get 403). Returns HTTP status (202 = accepted). */
async function revokeCredentials(credentials) {
  const r = await request(apiBase() + '/credentials/revoke', { method: 'POST', headers: { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' }, json: { credentials }, expect: [202], retries: 0 });
  return r.status;
}
module.exports = { createPull, addLabels, revokeCredentials, apiBase };
