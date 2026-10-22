'use strict';
/** Cargo.lock: registry crates only (entries without `source` are local workspace crates). */
const { readPackageTables } = require('./toml');
function parseCargoLock(text) {
  return readPackageTables(text).filter((p) => p.name && p.version && p.source && /^registry\+/.test(p.source)).map((p) => ({ ecosystem: 'crates.io', name: p.name, version: p.version }));
}
module.exports = { parseCargoLock };
