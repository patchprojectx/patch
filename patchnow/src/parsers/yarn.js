'use strict';
/** yarn.lock: classic v1 format and Berry (v2+, YAML with __metadata). */
const YAML = require('yaml');

const nameFromSpec = (spec) => {
  const s = spec.trim().replace(/^"|"$/g, '');
  const i = s.indexOf('@', 1);
  return i > 0 ? s.slice(0, i) : s;
};
function parseYarnLock(text) {
  const out = [], seen = new Set();
  const push = (name, version) => { const k = name + '@' + version; if (!seen.has(k) && /^\d/.test(version)) { seen.add(k); out.push({ ecosystem: 'npm', name, version }); } };
  if (/^__metadata:/m.test(text)) {
    const doc = YAML.parse(text) || {};
    for (const [key, v] of Object.entries(doc)) {
      if (key === '__metadata' || !v || !v.version) continue;
      const first = key.split(',')[0].trim();
      if (/@(workspace|link|portal|file|patch):/.test(first) && !/@patch:.*npm%3A/.test(first)) continue;
      push(nameFromSpec(first.replace(/@npm:.*/, '@x')), String(v.version));
    }
    return out;
  }
  let current = null;
  for (const line of text.split(/\r?\n/)) {
    if (!line || line.startsWith('#')) continue;
    if (!/^\s/.test(line) && line.endsWith(':')) { current = nameFromSpec(line.slice(0, -1).split(',')[0]); continue; }
    const m = line.match(/^\s+version:?\s+"?([^"\s]+)"?/);
    if (m && current) { push(current, m[1]); current = null; }
  }
  return out;
}
module.exports = { parseYarnLock };
