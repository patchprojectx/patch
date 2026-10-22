'use strict';
/** Policy evaluation: global filters, ignores (with expiry), triggers (OR of AND-groups). Pure functions. */
const core = require('./core');
const { parseComparator } = require('./config');

const cmp = (val, spec) => { const c = parseComparator(spec); if (!c || val == null) return false; return { '>': val > c.n, '>=': val >= c.n, '<': val < c.n, '<=': val <= c.n, '==': val === c.n, '=': val === c.n }[c.op]; };

/** Does finding f satisfy every key of trigger t ? */
function matchTrigger(f, t) {
  if (t.kev !== undefined && !!f.kev !== !!t.kev) return false;
  if (t.severity && core.RANK[f.severity] < core.RANK[String(t.severity).toUpperCase() === 'MEDIUM' ? 'MODERATE' : String(t.severity).toUpperCase()]) return false;
  if (t.cvss !== undefined && !cmp(f.score, t.cvss)) return false;
  if (t.epss !== undefined && !cmp(f.epss, t.epss)) return false;
  if (t.ecosystems && !t.ecosystems.map((x) => x.toLowerCase()).includes(String(f.ecosystem).toLowerCase())) return false;
  if (t.packages && !t.packages.includes(f.name)) return false;
  if (t.include_dev === false && f.dev) return false;
  if (t.runtime !== undefined && (f.kind === 'runtime') !== !!t.runtime) return false;
  if (t.has_fix !== undefined && !!f.fixed !== !!t.has_fix) return false;
  return true;
}
function ignoredBy(f, ignores, now = new Date()) {
  const ids = new Set([f.id, ...(f.aliases || []), ...(f.cves || [])]);
  for (const g of ignores || []) {
    if (!ids.has(g.id)) continue;
    if (g.packages && !g.packages.includes(f.name)) continue;
    if (g.expires && new Date(g.expires + (String(g.expires).length <= 10 ? 'T23:59:59Z' : '')) < now) continue; // expired ignore no longer applies
    return g;
  }
  return null;
}
/** -> [{finding, decision: 'fire'|'ignored'|'filtered'|'no-trigger', trigger?, reason?}] */
function evaluate(findings, cfg, now = new Date()) {
  const only = (cfg.packages && cfg.packages.only) || [], exclude = (cfg.packages && cfg.packages.exclude) || [];
  return findings.map((f) => {
    if (only.length && !only.includes(f.name)) return { finding: f, decision: 'filtered', reason: 'not in packages.only' };
    if (exclude.includes(f.name)) return { finding: f, decision: 'filtered', reason: 'in packages.exclude' };
    const g = ignoredBy(f, cfg.ignore, now);
    if (g) return { finding: f, decision: 'ignored', reason: g.reason + (g.expires ? ' (until ' + g.expires + ')' : '') };
    const i = (cfg.triggers || []).findIndex((t) => matchTrigger(f, t));
    return i >= 0 ? { finding: f, decision: 'fire', trigger: i, triggerSpec: cfg.triggers[i] } : { finding: f, decision: 'no-trigger' };
  });
}
const keyOf = (f) => [f.ecosystem, f.name, f.version, f.id].join('|');
module.exports = { evaluate, matchTrigger, ignoredBy, keyOf };
