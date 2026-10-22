'use strict';
/** Go modules: go.mod require directives (preferred) and go.sum (fallback, may over-report). */
function parseGoMod(text) {
  const out = []; let inReq = false, goVersion = null, toolchain = null;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\/\/(?!\s*indirect).*$/, '').trim();
    if (/^require\s*\($/.test(line)) { inReq = true; continue; }
    if (inReq && line === ')') { inReq = false; continue; }
    const m = inReq ? line.match(/^(\S+)\s+(v\S+)/) : line.match(/^require\s+(\S+)\s+(v\S+)/);
    if (m) { out.push({ ecosystem: 'Go', name: m[1], version: m[2], indirect: /\/\/\s*indirect/.test(raw) }); continue; }
    let g = line.match(/^go\s+(\d+\.\d+(?:\.\d+)?)/); if (g) goVersion = g[1];
    g = line.match(/^toolchain\s+go(\d+\.\d+(?:\.\d+)?)/); if (g) toolchain = g[1];
  }
  return { packages: out, goVersion, toolchain };
}
function parseGoSum(text) {
  const seen = new Map();
  for (const line of text.split(/\r?\n/)) {
    const m = line.trim().match(/^(\S+)\s+(v[^\s/]+)(\/go\.mod)?\s+h1:/);
    if (!m) continue;
    const k = m[1] + '@' + m[2];
    if (!seen.has(k)) seen.set(k, { ecosystem: 'Go', name: m[1], version: m[2], fromSum: true });
  }
  return [...seen.values()];
}
module.exports = { parseGoMod, parseGoSum };
