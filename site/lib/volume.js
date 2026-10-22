'use strict';
// NVD CVE volume per calendar year (records published to NVD, rejected records excluded).
// NVD limits pubStartDate/pubEndDate windows to 120 days, so each year is counted per quarter.
// Completed years are persisted to disk and never refetched; the current year refreshes daily.
const fs = require('fs');
const path = require('path');

const FIRST_YEAR = 2016;
function quarters(year, now) {
  const q = [];
  for (let m = 0; m < 12; m += 3) {
    const s = new Date(Date.UTC(year, m, 1)), e = new Date(Date.UTC(year, m + 3, 1) - 1000);
    if (s > now) break;
    q.push([s, e > now ? now : e]);
  }
  return q;
}
const iso = (d) => d.toISOString().replace(/\.\d{3}Z$/, '.000Z');

async function countYear(nvd, year, now) {
  let total = 0;
  for (const [s, e] of quarters(year, now)) {
    const j = await nvd({ pubStartDate: iso(s), pubEndDate: iso(e), resultsPerPage: 1, noRejected: '' });
    total += j.totalResults;
  }
  return total;
}
function load(file) { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return { years: {} }; } }
async function refresh(nvd, file, { now = new Date(), log = () => {} } = {}) {
  const data = load(file);
  const cur = now.getUTCFullYear();
  for (let y = FIRST_YEAR; y <= cur; y++) {
    const have = data.years[y];
    const fresh = have && (y < cur ? have.complete : Date.now() - Date.parse(have.fetchedAt) < 20 * 3600e3);
    if (fresh) continue;
    const count = await countYear(nvd, y, now);
    data.years[y] = { count, complete: y < cur, through: y < cur ? y + '-12-31' : now.toISOString().slice(0, 10), fetchedAt: new Date().toISOString() };
    log('volume ' + y + ': ' + count);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
  }
  return summarize(data, now);
}
function summarize(data, now = new Date()) {
  const cur = now.getUTCFullYear();
  const years = Object.entries(data.years).map(([y, v]) => ({ year: +y, ...v })).sort((a, b) => a.year - b.year);
  const ytd = years.find((y) => y.year === cur);
  let projection = null;
  if (ytd) {
    const start = Date.UTC(cur, 0, 1), end = Date.UTC(cur + 1, 0, 1);
    const frac = (Date.parse(ytd.through + 'T23:59:59Z') - start) / (end - start);
    projection = { method: 'linear (YTD / fraction of year elapsed)', value: Math.round(ytd.count / frac), fractionElapsed: +frac.toFixed(3) };
  }
  return { years, projection, source: 'NVD CVE API 2.0 · totalResults per quarter, pubStartDate/pubEndDate, noRejected', fetchedAt: years.length ? years.map((y) => y.fetchedAt).sort().pop() : null };
}
module.exports = { refresh, summarize, load, quarters };
