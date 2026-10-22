'use strict';
const { execFileSync } = require('child_process');
function git(cwd, args, opts = {}) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, GIT_TERMINAL_PROMPT: '0' }, ...opts }).trim();
}
const tryGit = (cwd, args) => { try { return git(cwd, args); } catch { return null; } };
function repoRoot(cwd) { return tryGit(cwd, ['rev-parse', '--show-toplevel']); }
function currentBranch(cwd) { return tryGit(cwd, ['rev-parse', '--abbrev-ref', 'HEAD']); }
function dirtyFiles(cwd) { const s = tryGit(cwd, ['status', '--porcelain']); return s ? s.split('\n').filter(Boolean).map((l) => l.slice(3)) : []; }
/** owner/repo parsed from a GitHub remote URL (https or ssh). */
function githubRepoFromRemote(cwd, remote = 'origin') {
  const url = tryGit(cwd, ['remote', 'get-url', remote]); if (!url) return null;
  const m = url.match(/github\.com[/:]([^/]+)\/([^/]+?)(?:\.git)?$/);
  return m ? m[1] + '/' + m[2] : null;
}
module.exports = { git, tryGit, repoRoot, currentBranch, dirtyFiles, githubRepoFromRemote };
