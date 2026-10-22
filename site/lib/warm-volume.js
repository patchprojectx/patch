// one-off: node lib/warm-volume.js  -> writes .cache/volume.json using the same NVD pacing as the server
'use strict';
const path = require('path');
const vol = require('./volume');
const KEY = process.env.NVD_API_KEY || '';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function nvd(params) {
  for (let i = 0; i < 4; i++) {
    const res = await fetch('https://services.nvd.nist.gov/rest/json/cves/2.0?' + new URLSearchParams(params), { headers: KEY ? { apiKey: KEY } : {}, signal: AbortSignal.timeout(60000) }).catch((e) => ({ ok: false, status: e.message }));
    if (res.ok) { const j = await res.json(); await sleep(KEY ? 1200 : 6500); return j; }
    console.error('retry', res.status); await sleep(13000);
  }
  throw new Error('NVD failed');
}
vol.refresh(nvd, path.join(__dirname, '..', '.cache', 'volume.json'), { log: console.log }).then((s) => console.log(JSON.stringify(s.projection)));
