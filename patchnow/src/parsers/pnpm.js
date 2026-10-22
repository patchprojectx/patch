'use strict';
/** pnpm-lock.yaml: lockfile v5.x (/name/version), v6.x (/name@version), v9 (name@version + snapshots). */
const YAML = require('yaml');

function splitKey(key, v5) {
  let k = key.replace(/^\//, '').replace(/\(.*$/, '');            // drop peer-dependency suffix "(react@18.2.0)"
  if (v5) {                                                        // "@scope/name/1.2.3_peer" or "name/1.2.3"
    k = k.replace(/_.*$/, '');
    const i = k.lastIndexOf('/');
    return i > 0 ? [k.slice(0, i), k.slice(i + 1)] : [null, null];
  }
  const i = k.lastIndexOf('@');
  return i > 0 ? [k.slice(0, i), k.slice(i + 1)] : [null, null];
}
function parsePnpmLock(text) {
  const doc = YAML.parse(text) || {};
  const ver = parseFloat(String(doc.lockfileVersion || '0'));
  const v5 = ver > 0 && ver < 6;
  const out = [], seen = new Set();
  const devNames = new Set();
  const imp = doc.importers || { '.': doc };
  for (const i of Object.values(imp)) for (const n of Object.keys((i && i.devDependencies) || {})) devNames.add(n);
  for (const [key, val] of Object.entries(doc.packages || {})) {
    const [name, version] = splitKey(key, v5);
    if (!name || !version || !/^\d/.test(version)) continue;
    const id = name + '@' + version; if (seen.has(id)) continue; seen.add(id);
    const dev = val && typeof val.dev === 'boolean' ? val.dev : devNames.has(name) && !(val && val.dev === false);
    out.push({ ecosystem: 'npm', name, version, dev: !!dev });
  }
  return out;
}
module.exports = { parsePnpmLock, splitKey };
