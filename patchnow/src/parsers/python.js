'use strict';
/** PyPI: requirements.txt (pinned == lines only) and poetry.lock. */
const { readPackageTables } = require('./toml');
const norm = (n) => n.toLowerCase().replace(/[-_.]+/g, '-');

function parseRequirements(text) {
  const out = [], skipped = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, '').replace(/^#.*$/, '').trim();
    if (!line || line.startsWith('-')) continue;
    const m = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*===?\s*([^\s;,\\]+)/);
    if (m) out.push({ ecosystem: 'PyPI', name: norm(m[1]), version: m[3] });
    else skipped.push(line.split(/[<>=!~;\s\[]/)[0]);
  }
  return { packages: out, skipped };
}
function parsePoetryLock(text) {
  return readPackageTables(text).filter((p) => p.name && p.version).map((p) => ({ ecosystem: 'PyPI', name: norm(p.name), version: p.version, dev: p.category === 'dev' }));
}
module.exports = { parseRequirements, parsePoetryLock };
