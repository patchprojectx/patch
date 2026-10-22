'use strict';
/** Lockfile discovery + dispatch. */
const fs = require('fs');
const path = require('path');
const npm = require('./npm'), pnpm = require('./pnpm'), yarn = require('./yarn'), composer = require('./composer');
const py = require('./python'), go = require('./go'), cargo = require('./cargo');

// Priority: when a directory has an exact lockfile, the declared-range manifest is not used.
const KINDS = [
  { file: 'package-lock.json', parse: (t) => npm.parsePackageLock(t) },
  { file: 'npm-shrinkwrap.json', parse: (t) => npm.parsePackageLock(t) },
  { file: 'pnpm-lock.yaml', parse: (t) => pnpm.parsePnpmLock(t) },
  { file: 'yarn.lock', parse: (t) => yarn.parseYarnLock(t) },
  { file: 'package.json', parse: (t) => npm.parsePackageJson(t), fallbackFor: ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock'] },
  { file: 'composer.lock', parse: (t) => composer.parseComposerLock(t) },
  { file: 'poetry.lock', parse: (t) => py.parsePoetryLock(t) },
  { file: 'requirements.txt', parse: (t) => py.parseRequirements(t).packages, fallbackFor: ['poetry.lock'] },
  { file: 'go.mod', parse: (t) => go.parseGoMod(t).packages },
  { file: 'go.sum', parse: (t) => go.parseGoSum(t), fallbackFor: ['go.mod'] },
  { file: 'Cargo.lock', parse: (t) => cargo.parseCargoLock(t) },
];
const SKIP_DIRS = new Set(['node_modules', '.git', 'vendor', 'target', '.venv', 'venv', '__pycache__', 'dist', 'build', '.patchnow']);

function detectKind(filename) {
  const base = path.basename(filename);
  return KINDS.find((k) => k.file === base) || null;
}
function parseFile(file, text) {
  const k = detectKind(file);
  if (!k) throw new Error('unsupported file: ' + file);
  return k.parse(text == null ? fs.readFileSync(file, 'utf8') : text);
}
/** Find supported manifests under `root` (depth-limited), skipping vendored / build dirs. */
function discover(root, { maxDepth = 4 } = {}) {
  const found = [];
  const walk = (dir, depth) => {
    let entries; try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    const names = new Set(entries.filter((e) => e.isFile()).map((e) => e.name));
    for (const k of KINDS) {
      if (!names.has(k.file)) continue;
      if (k.fallbackFor && k.fallbackFor.some((f) => names.has(f))) continue;
      found.push(path.join(dir, k.file));
    }
    if (depth >= maxDepth) return;
    for (const e of entries) if (e.isDirectory() && !SKIP_DIRS.has(e.name) && !e.name.startsWith('.')) walk(path.join(dir, e.name), depth + 1);
  };
  walk(root, 0);
  return found;
}
module.exports = { discover, parseFile, detectKind, KINDS };
