# PATCH

**Exploited-vulnerability response, automated.**

PATCH matches [OSV.dev](https://osv.dev), the
[CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog and
[FIRST EPSS](https://www.first.org/epss/) against the dependencies and runtimes you actually run, checks every
finding against a policy you write in `patch.yml`, and executes the response you approved in advance: a pull
request that pins the fixed version, a switch to safe mode, credential revocation and notifications. Every decision
is written to an append-only audit log.

Website: <https://patchproject.xyz>

| Directory | Contents |
|---|---|
| [`patchnow/`](patchnow/) | The CLI and library (Node.js 20+, MIT, one runtime dependency). Full documentation in [patchnow/README.md](patchnow/README.md). |
| [`site/`](site/) | The website: landing page, docs, live NVD / CISA KEV feeds and the in-browser lockfile checker. Zero-dependency Node server. |
| [`action.yml`](action.yml) | The GitHub Action (`patchprojectx/patch`), a composite action that runs `patchnow/`. |
| [`render.yaml`](render.yaml) | Render Blueprint for the website. |

## Install

patchnow is not on npm yet. Install the tarball attached to the
[v0.1.0 release](https://github.com/patchprojectx/patch/releases/tag/v0.1.0):

```
npm install -g https://github.com/patchprojectx/patch/releases/download/v0.1.0/patchnow-0.1.0.tgz
patchnow init        # writes patch.yml (dry run until armed: true)
patchnow scan        # report only
patchnow run         # scan + policy + actions
```

Or from a checkout: `cd patchnow && npm ci && node bin/patchnow.js <command>`.

## GitHub Action

```yaml
# .github/workflows/patchnow.yml
on:
  schedule: [{ cron: "*/15 * * * *" }]
  workflow_dispatch:
permissions: { contents: write, pull-requests: write, security-events: write }
jobs:
  patchnow:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: patchprojectx/patch@v0.1
        with: { config: patch.yml }
```

`@v0.1` moves with v0.1.x releases; pin `@v0.1.0` or a commit SHA for exact builds. Inputs: `config`,
`working-directory`, `dry-run`, `sarif`, `upload-sarif`, `github-token`, `persist-state`. A full example is in
[patchnow/examples/workflow.yml](patchnow/examples/workflow.yml).

## Run the website

```
cd site && node server.js     # http://localhost:4970 ; Node 18+, no npm install needed
```

Environment: `PORT` (Render sets it), `SITE_URL` (default `https://patchproject.xyz`), `NVD_API_KEY` (optional,
raises the NVD rate limit). See [site/README.md](site/README.md).

## Development

```
cd patchnow && npm ci && npm test   # unit + end-to-end (the e2e test uses live OSV / KEV / EPSS and skips offline)
```

CI runs the tests on Node 20 and 22, checks that the site's browser bundle matches `patchnow/src`, boots the site,
and runs the Action itself in dry-run mode.

## License

MIT, see [LICENSE](LICENSE).
