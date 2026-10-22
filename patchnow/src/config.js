'use strict';
/** patch.yml loading, defaults and validation. Secrets are never stored in patch.yml: fields ending in _env name an environment variable. */
const fs = require('fs');
const path = require('path');
const YAML = require('yaml');

const ACTIONS = ['pin_patch', 'safe_mode', 'revoke', 'notify'];
const SEVERITIES = ['low', 'moderate', 'medium', 'high', 'critical'];
const ACTION_KEYS = {
  pin_patch: ['branch_prefix', 'base', 'remote', 'push', 'open_pr', 'draft', 'labels', 'token_env', 'repo', 'allow_dirty', 'author_name', 'author_email'],
  safe_mode: ['provider', 'url_env', 'secret_env', 'method', 'token_env', 'project_id', 'deployment_id', 'team_id'],
  revoke: ['github_tokens_env', 'npm_token_ids', 'confirm', 'npm_bin'],
  notify: ['send_in_dry_run', 'webhook', 'slack', 'telegram', 'ntfy', 'email'],
};
const TRIGGER_KEYS = ['kev', 'severity', 'cvss', 'epss', 'ecosystems', 'packages', 'include_dev', 'runtime', 'has_fix'];

const DEFAULTS = {
  version: 1,
  armed: false,
  scan: { paths: ['.'], include_dev: false, runtimes: 'auto', epss: true, max_depth: 4 },
  packages: { only: [], exclude: [] },
  ignore: [],
  triggers: [{ kev: true }, { severity: 'critical' }],
  actions: [],
  state: { path: '.patchnow/state.json', refire_after_days: 0 },
  audit: { path: '.patchnow/audit.jsonl' },
  cache: { path: '.patchnow/cache' },
};

function load(file) {
  const abs = path.resolve(file);
  if (!fs.existsSync(abs)) throw new Error('config not found: ' + file + ' (run `patchnow init`)');
  const raw = YAML.parse(fs.readFileSync(abs, 'utf8')) || {};
  const cfg = merge(DEFAULTS, raw);
  const errs = validate(cfg);
  if (errs.length) throw new Error('invalid ' + path.basename(file) + ':\n  - ' + errs.join('\n  - '));
  cfg._file = abs; cfg._dir = path.dirname(abs);
  return cfg;
}
function merge(a, b) {
  if (Array.isArray(b)) return b;
  if (b && typeof b === 'object' && a && typeof a === 'object' && !Array.isArray(a)) { const o = { ...a }; for (const [k, v] of Object.entries(b)) o[k] = merge(a[k], v); return o; }
  return b === undefined ? a : b;
}
function validate(c) {
  const e = [];
  if (c.version !== 1) e.push('version must be 1');
  const TOP = ['version', 'armed', 'scan', 'packages', 'ignore', 'triggers', 'actions', 'state', 'audit', 'cache', '_file', '_dir'];
  for (const k of Object.keys(c)) if (!TOP.includes(k)) e.push(`unknown top-level key "${k}"`);
  for (const k of Object.keys(c.scan || {})) if (!['paths', 'include_dev', 'runtimes', 'epss', 'max_depth'].includes(k)) e.push(`scan: unknown key "${k}"`);
  if (c.scan && !['auto', 'off', false].includes(c.scan.runtimes)) e.push('scan.runtimes must be auto or off');
  if (typeof c.armed !== 'boolean') e.push('armed must be true or false');
  if (!Array.isArray(c.triggers) || !c.triggers.length) e.push('triggers must be a non-empty list');
  (c.triggers || []).forEach((t, i) => {
    if (!t || typeof t !== 'object') return e.push(`triggers[${i}] must be a mapping`);
    for (const k of Object.keys(t)) if (!TRIGGER_KEYS.includes(k)) e.push(`triggers[${i}]: unknown key "${k}" (allowed: ${TRIGGER_KEYS.join(', ')})`);
    if (t.severity && !SEVERITIES.includes(String(t.severity).toLowerCase())) e.push(`triggers[${i}].severity must be one of ${SEVERITIES.join(', ')}`);
    for (const k of ['cvss', 'epss']) if (t[k] !== undefined && !parseComparator(t[k])) e.push(`triggers[${i}].${k} must look like ">=9.0" or ">0.5"`);
  });
  (c.ignore || []).forEach((g, i) => {
    if (!g || !g.id) e.push(`ignore[${i}].id is required`);
    if (!g || !g.reason) e.push(`ignore[${i}].reason is required`);
    if (g && g.expires && isNaN(Date.parse(g.expires))) e.push(`ignore[${i}].expires must be a date (YYYY-MM-DD)`);
  });
  (c.actions || []).forEach((a, i) => {
    const keys = Object.keys(a || {}).filter((k) => k !== 'when');
    if (keys.length !== 1 || !ACTIONS.includes(keys[0])) return e.push(`actions[${i}] must have exactly one of: ${ACTIONS.join(', ')} (plus optional "when")`);
    const opts = a[keys[0]] || {};
    for (const k of Object.keys(opts)) if (k !== 'when' && !ACTION_KEYS[keys[0]].includes(k)) e.push(`actions[${i}].${keys[0]}: unknown key "${k}" (allowed: ${ACTION_KEYS[keys[0]].join(', ')})`);
    const when = a.when || opts.when;
    if (when) for (const k of Object.keys(when)) if (!TRIGGER_KEYS.includes(k)) e.push(`actions[${i}].when: unknown key "${k}"`);
  });
  return e;
}
function parseComparator(v) {
  const m = String(v).trim().match(/^(>=|<=|>|<|==|=)?\s*(\d+(?:\.\d+)?)$/);
  return m ? { op: m[1] || '>=', n: parseFloat(m[2]) } : null;
}

const TEMPLATE = `# patch.yml — patchnow response policy (schema version 1)
# Docs: README.md · Every action is a dry run until armed: true.
version: 1
armed: false

scan:
  paths: ["."]            # directories searched for lockfiles (depth: max_depth)
  include_dev: false       # include devDependencies / dev packages
  runtimes: auto           # auto: detect node, php, go on PATH · off
  epss: true               # enrich with FIRST EPSS scores when reachable
  max_depth: 4

# Global package filters (optional). Names match exactly.
packages:
  only: []                 # if non-empty, only these packages are considered
  exclude: []

# Suppress a finding until a date. id may be an OSV id, GHSA id or CVE.
ignore: []
#  - id: GHSA-xxxx-xxxx-xxxx
#    reason: "not reachable: only used in build tooling"
#    expires: 2026-12-31

# A finding fires if it matches ANY trigger. Keys inside one trigger are ANDed.
triggers:
  - kev: true              # listed in the CISA Known Exploited Vulnerabilities catalog
  - severity: critical     # low | moderate | high | critical (minimum)
  - epss: ">0.5"           # FIRST EPSS probability of exploitation in the next 30 days
#  - severity: high
#    has_fix: true
#    ecosystems: [npm]

# Executed in order for the findings that fired. "when" narrows an action with trigger syntax.
actions:
  - pin_patch:
      branch_prefix: patchnow/
      base: main
      push: true
      open_pr: true
  - notify:
      webhook: { url_env: PATCHNOW_WEBHOOK_URL }
#      slack: { url_env: SLACK_WEBHOOK_URL }
#      telegram: { token_env: TELEGRAM_BOT_TOKEN, chat_id: "123456" }
#      ntfy: { topic: my-oncall-topic, server: https://ntfy.sh }
#  - safe_mode:
#      when: { kev: true }
#      provider: render_deploy_hook     # render_deploy_hook | vercel_promote | webhook
#      url_env: RENDER_MAINTENANCE_DEPLOY_HOOK
#  - revoke:
#      when: { kev: true }
#      github_tokens_env: [DEPLOY_BOT_PAT]
#      npm_token_ids: []
#      confirm: false                   # must also be true for revocation to execute

state:
  path: .patchnow/state.json   # dedupe: a finding fires once per package@version+advisory
  refire_after_days: 0         # 0 = never re-fire the same finding
audit:
  path: .patchnow/audit.jsonl
`;
module.exports = { load, validate, merge, DEFAULTS, TEMPLATE, parseComparator, ACTIONS, ACTION_KEYS, TRIGGER_KEYS };
