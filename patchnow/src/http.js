'use strict';
/** fetch wrapper: timeout, retries with backoff on 429/5xx/network errors, JSON helpers. */
const UA = 'patchnow/' + require('../package.json').version + ' (+https://github.com/patchprojectx/patch)';
async function request(url, { method = 'GET', headers = {}, body, json, timeout = 30000, retries = 2, expect } = {}) {
  let last;
  for (let i = 0; i <= retries; i++) {
    try {
      const h = { 'User-Agent': UA, ...headers };
      let b = body;
      if (json !== undefined) { h['Content-Type'] = 'application/json'; b = JSON.stringify(json); }
      const res = await fetch(url, { method, headers: h, body: b, signal: AbortSignal.timeout(timeout) });
      if ((res.status === 429 || res.status >= 500) && i < retries) { last = new Error(method + ' ' + url + ' -> HTTP ' + res.status); await sleep(800 * 2 ** i); continue; }
      const text = await res.text();
      let data = null; try { data = text ? JSON.parse(text) : null; } catch { data = text; }
      if (expect && !expect.includes(res.status)) { const e = new Error(method + ' ' + redact(url) + ' -> HTTP ' + res.status + (typeof data === 'object' && data && data.message ? ': ' + data.message : '')); e.status = res.status; e.data = data; throw e; }
      return { status: res.status, ok: res.ok, data, headers: res.headers };
    } catch (e) {
      if (e.status) throw e;
      last = e; if (i < retries) await sleep(800 * 2 ** i);
    }
  }
  throw last;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
/** Strip secrets that appear in URLs (bot tokens, hook keys) before they reach logs. */
function redact(url) {
  return String(url).replace(/(bot)[0-9]+:[A-Za-z0-9_-]+/g, '$1***').replace(/([?&](key|token|access_token)=)[^&]+/gi, '$1***').replace(/(hooks\.slack\.com\/services\/)[^\s]+/, '$1***').replace(/(api\.render\.com\/deploy\/)[^\s?]+/, '$1***');
}
module.exports = { request, sleep, redact };
