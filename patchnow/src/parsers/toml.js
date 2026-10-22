'use strict';
/** Minimal reader for [[package]] arrays in TOML lockfiles (poetry.lock, Cargo.lock). Not a general TOML parser. */
function readPackageTables(text) {
  const out = []; let cur = null;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '[[package]]') { cur = {}; out.push(cur); continue; }
    if (/^\[/.test(line)) { cur = line === '[[package]]' ? cur : null; continue; }
    if (!cur) continue;
    const m = line.match(/^([A-Za-z0-9_-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|(true|false))/);
    if (m) cur[m[1]] = m[2] !== undefined ? m[2] : m[3] === 'true';
  }
  return out;
}
module.exports = { readPackageTables };
