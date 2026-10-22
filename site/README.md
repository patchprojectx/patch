# PATCH website

The landing page and documentation for `patchnow`. It also hosts live NVD and CISA KEV feeds and the in-browser
lockfile checker.

## Run

    cd site && node server.js     # Node >= 18, zero dependencies, no build step

| Variable | Purpose |
|---|---|
| `PORT` | Port to listen on (default 4970; Render sets it). |
| `HOST` | Bind address (default `0.0.0.0`). |
| `SITE_URL` | Canonical origin, no trailing slash (default `https://patchproject.xyz`). Fills og:url and the absolute og:image. |
| `NVD_API_KEY` | Optional. Raises the NVD rate limit. |

## Endpoints

| Path | Contents |
|---|---|
| `/api/pulse` | NVD CVEs published in the last 24 h (hourly histogram), the 30-day total and the newest CVE. |
| `/api/critical` | NVD CVEs with CVSS v3 or v4 severity CRITICAL from the last 7 days. |
| `/api/kev` | CISA KEV catalog version and count, recent additions, additions per year, the 30-day count, entries with known ransomware use, and every CVE ID (used by the checker). |
| `/api/volume` | CVE records published to NVD per year since 2016, rejected records excluded. Each year is counted per quarter because NVD limits date windows to 120 days. Completed years ship in `data/volume-seed.json` (copied to `.cache/volume.json` on first start), so a fresh deploy only fetches the current year, which is refreshed daily. `npm run warm:volume` refetches anything missing. |
| `/healthz` | Health check. |

## Why a server and not a static site

- **CISA KEV:** the KEV JSON sends no CORS headers, so a browser on another origin cannot read it. The server proxies
  it.
- **NVD:** the public rate limit is 5 requests per 30 s per IP, so the server fetches every 15 minutes and serves
  the result from cache.
- **OSV.dev:** it allows CORS, so the browser calls it directly. Only package names and versions are sent.

## Shared logic with the CLI

`public/js/patchnow-browser.js` is generated from `../patchnow`. It is built by `patchnow/scripts/build-browser.js`
and contains `src/core.js` verbatim, the lockfile parsers and the runtime advisory table. The checker therefore
gives the same answers as `patchnow scan`; `patchnow/test/browser-parity.test.js` enforces this. After changing
patchnow, run `npm run sync:patchnow` (CI fails if the bundle is out of date). Release tarballs are attached to
[GitHub releases](https://github.com/patchprojectx/patch/releases), not served by the site.

## Deploy

Deploy as a Render **Web Service**, not a Static Site. `render.yaml` at the repository root is a Blueprint for it:
root directory `site`, no build step, start command `node server.js`, health check `/healthz`.
