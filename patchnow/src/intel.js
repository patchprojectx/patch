'use strict';
/** Exploitation intelligence: CISA KEV catalog (cached) and FIRST EPSS scores. */
const fs = require('fs');
const path = require('path');
const { request } = require('./http');
const KEV_URL = () => process.env.PATCHNOW_KEV_URL || 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_API = () => (process.env.PATCHNOW_EPSS_API || 'https://api.first.org/data/v1/epss').replace(/\/+$/, '');

async function loadKev({ cacheDir, maxAgeMs = 6 * 3600e3 } = {}) {
  const file = cacheDir && path.join(cacheDir, 'kev.json');
  if (file && fs.existsSync(file) && Date.now() - fs.statSync(file).mtimeMs < maxAgeMs) {
    try { return index(JSON.parse(fs.readFileSync(file, 'utf8')), 'cache'); } catch {}
  }
  const r = await request(KEV_URL(), { expect: [200], timeout: 60000 });
  if (file) { fs.mkdirSync(cacheDir, { recursive: true }); fs.writeFileSync(file, JSON.stringify(r.data)); }
  return index(r.data, 'network');
}
function index(cat, from) {
  const byCve = new Map();
  for (const v of cat.vulnerabilities || []) byCve.set(v.cveID, { dateAdded: v.dateAdded, dueDate: v.dueDate, ransomware: v.knownRansomwareCampaignUse, name: v.vulnerabilityName });
  return { catalogVersion: cat.catalogVersion, count: cat.count || byCve.size, byCve, from };
}
/** EPSS scores for CVEs, in batches. Returns Map<cve,{epss,percentile,date}>; empty Map if the API is unreachable. */
async function loadEpss(cves) {
  const out = new Map(); const list = [...new Set(cves)];
  for (let i = 0; i < list.length; i += 80) {
    const r = await request(EPSS_API() + '?cve=' + list.slice(i, i + 80).join(','), { expect: [200], timeout: 30000, retries: 1 });
    for (const d of (r.data && r.data.data) || []) out.set(d.cve, { epss: Number(d.epss), percentile: Number(d.percentile), date: d.date });
  }
  return out;
}
module.exports = { loadKev, loadEpss, index };
