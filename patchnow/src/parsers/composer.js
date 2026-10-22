'use strict';
/** composer.lock (Packagist). dev-* branches are skipped (no comparable version). */
function parseComposerLock(text) {
  const j = JSON.parse(text);
  const out = [];
  for (const [sec, dev] of [['packages', false], ['packages-dev', true]]) {
    for (const p of j[sec] || []) {
      if (!p.name || !p.version || /^dev-/.test(p.version) || /-dev$/.test(p.version)) continue;
      out.push({ ecosystem: 'Packagist', name: p.name, version: String(p.version).replace(/^v/, ''), dev });
    }
  }
  return out;
}
module.exports = { parseComposerLock };
