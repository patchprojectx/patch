'use strict';
/** npm: package-lock.json / npm-shrinkwrap.json (lockfileVersion 1, 2, 3) and package.json (declared ranges). */

function parsePackageLock(text) {
  const j = JSON.parse(text);
  const out = [];
  if (j.packages && typeof j.packages === 'object') {
    for (const [key, v] of Object.entries(j.packages)) {
      if (!key || !v || v.link || !v.version) continue;            // root project or workspace link
      const i = key.lastIndexOf('node_modules/');
      const name = v.name || (i >= 0 ? key.slice(i + 13) : null);
      if (!name || /^(file:|link:|git[+:]|https?:|github:)/.test(v.version)) continue;
      out.push({ ecosystem: 'npm', name, version: v.version, dev: !!(v.dev || v.devOptional), direct: key.split('node_modules/').length === 2 });
    }
  } else if (j.dependencies) {
    const walk = (deps, depth) => {
      for (const [name, v] of Object.entries(deps || {})) {
        if (v && v.version && !/^(file:|link:|git[+:]|https?:|github:)/.test(v.version)) out.push({ ecosystem: 'npm', name, version: v.version, dev: !!v.dev, direct: depth === 0 });
        if (v && v.dependencies) walk(v.dependencies, depth + 1);
      }
    };
    walk(j.dependencies, 0);
  }
  return out;
}

/** Lowest version a declared range admits (best effort). Returns null for tags, URLs, workspaces. */
function rangeFloor(spec) {
  if (typeof spec !== 'string' || /^(npm:|file:|git|https?:|link:|workspace:|github:|catalog:)/.test(spec) || /^[a-z]/i.test(spec.trim()) && !/^v\d/.test(spec.trim())) return null;
  let m = spec.match(/\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?/); if (m) return m[0];
  m = spec.match(/\d+\.\d+/); if (m) return m[0] + '.0';
  m = spec.match(/\d+/); return m ? m[0] + '.0.0' : null;
}
function parsePackageJson(text) {
  const j = JSON.parse(text);
  const out = [];
  for (const [sec, dev] of [['dependencies', false], ['optionalDependencies', false], ['devDependencies', true]]) {
    for (const [name, spec] of Object.entries(j[sec] || {})) {
      const v = rangeFloor(spec);
      if (v) out.push({ ecosystem: 'npm', name, version: v, dev, direct: true, approximate: spec !== v });
    }
  }
  return out;
}
module.exports = { parsePackageLock, parsePackageJson, rangeFloor };
