'use strict';
/** OSV.dev client: /v1/querybatch (with pagination) + /v1/vulns/{id} details. */
const { request } = require('./http');
const base = () => (process.env.PATCHNOW_OSV_API || 'https://api.osv.dev').replace(/\/+$/, '');

async function queryBatch(pkgs) {
  const results = pkgs.map(() => []);
  for (let off = 0; off < pkgs.length; off += 1000) {
    const chunk = pkgs.slice(off, off + 1000);
    let queries = chunk.map((p, i) => ({ i, q: { package: { name: p.name, ecosystem: p.ecosystem }, version: p.version } }));
    while (queries.length) {
      const r = await request(base() + '/v1/querybatch', { method: 'POST', json: { queries: queries.map((x) => x.q) }, expect: [200], timeout: 60000 });
      const next = [];
      r.data.results.forEach((res, k) => {
        const idx = off + queries[k].i;
        for (const v of res.vulns || []) results[idx].push(v.id);
        if (res.next_page_token) next.push({ i: queries[k].i, q: { ...queries[k].q, page_token: res.next_page_token } });
      });
      queries = next;
    }
  }
  return results;
}
async function getVulns(ids, { concurrency = 12 } = {}) {
  const out = new Map(); let i = 0;
  const list = [...new Set(ids)];
  await Promise.all(Array.from({ length: Math.min(concurrency, list.length) }, async () => {
    while (i < list.length) {
      const id = list[i++];
      const r = await request(base() + '/v1/vulns/' + encodeURIComponent(id), { expect: [200, 404] });
      if (r.status === 200) out.set(id, r.data);
    }
  }));
  return out;
}
module.exports = { queryBatch, getVulns };
