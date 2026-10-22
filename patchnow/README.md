# patchnow

**Exploited-vulnerability response, automated.**

`patchnow` scans your lockfiles and runtimes against [OSV.dev](https://osv.dev), the
[CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog and
[FIRST EPSS](https://www.first.org/epss/). It checks each finding against a policy you write in `patch.yml`. When a
finding matches, it runs the actions you approved in advance: a pull request that pins the fixed version, a switch
to safe mode, credential revocation and notifications. Every decision goes into an append-only audit log.

> Status: **v0.1, not published to npm yet.** Install the tarball from the
> [GitHub release](https://github.com/patchprojectx/patch/releases/tag/v0.1.0), run it from a checkout
> (`node bin/patchnow.js`), or use the GitHub Action `patchprojectx/patch@v0.1`.

```
npm install -g https://github.com/patchprojectx/patch/releases/download/v0.1.0/patchnow-0.1.0.tgz
                                        # or, from a checkout: node bin/patchnow.js <command>
patchnow init                           # writes patch.yml (dry run until armed: true)
patchnow scan                           # report only
patchnow run                            # scan + policy + actions
```

Requires Node.js 20 or newer. Its only runtime dependency is `yaml`.

## What it reads

| File | Ecosystem | Notes |
|---|---|---|
| `package-lock.json`, `npm-shrinkwrap.json` (lockfileVersion 1, 2, 3) | npm | exact versions; `dev` flags respected |
| `pnpm-lock.yaml` (v5, v6, v9) | npm | |
| `yarn.lock` (classic v1 and Berry) | npm | |
| `package.json` | npm | used only when no lockfile is present; lower bound of each declared range (approximate) |
| `composer.lock` | Packagist | `dev-*` branches skipped |
| `requirements.txt` | PyPI | exact `==` / `===` pins only; ranges are skipped |
| `poetry.lock` | PyPI | |
| `go.mod` (`go.sum` as a fallback) | Go | |
| `Cargo.lock` | crates.io | registry crates only |
| runtimes on `PATH` | node, php, go | `node -v`, `php -r 'echo PHP_VERSION;'`, `go env GOVERSION` |

Manifests are discovered up to `scan.max_depth` directories deep. `node_modules`, `vendor`, `.git`, `target`,
virtualenvs and build output are skipped. When a directory has a lockfile, its `package.json` (or
`requirements.txt` next to `poetry.lock`) is not used.

**Runtimes:** the Go toolchain is matched live against OSV (`Go/stdlib`). Node.js and PHP are compared against a
curated table of recent security releases, `src/data/runtime-advisories.json`, in which every entry links to its
vendor advisory. The table only covers the releases listed in it, so treat it as a supplement to your vendor's
security feed, not a substitute.

## Commands

```
patchnow init  [--dir <path>] [--force]
patchnow scan  [--dir <path>] [--format text|json|sarif] [--output <file>]
               [--include-dev] [--no-runtimes] [--no-epss] [--fail-on kev|critical|high|any|none]
patchnow run   [--dir <path>] [--config <file>] [--dry-run] [--sarif <file>] [--json]
patchnow watch [--dir <path>] [--config <file>] [--interval 15m] [--dry-run]
patchnow version | help
```

| Exit code | Meaning |
|---|---|
| 0 | OK |
| 1 | `scan --fail-on` threshold met |
| 2 | Usage or config error |
| 3 | `run`: an action failed |

- `scan` never changes anything. `--fail-on kev` makes it a CI gate.
- `run` loads `patch.yml` (or `patch.yaml`) from `--dir`. It is a dry run unless the file says `armed: true`.
  `--dry-run` forces a dry run even when the policy is armed. No command-line flag can arm the policy.
- `watch` repeats `run` every `--interval` (minimum 1m, default 15m) until it is stopped.

## patch.yml

`patchnow init` writes a commented starter file (`examples/patch.yml`). `examples/patch.full.yml` uses every key.
Unknown keys are rejected so a typo cannot silently weaken the policy.

```yaml
version: 1
armed: false                 # nothing destructive happens until this is true

scan:
  paths: ["."]
  include_dev: false
  runtimes: auto             # auto | off
  epss: true
  max_depth: 4

packages: { only: [], exclude: [] }

ignore:
  - id: CVE-2020-28500       # OSV id, GHSA id or CVE
    reason: "never called with user input"   # required
    expires: 2026-12-31      # optional; once past, the finding fires again
    packages: [lodash]       # optional scope

triggers:                    # a finding fires if it matches ANY entry; keys inside an entry are ANDed
  - kev: true
  - severity: critical       # minimum: low | moderate (medium) | high | critical
  - epss: ">0.5"             # >, >=, <, <=, ==
#   cvss: ">=9.0"
#   ecosystems: [npm, PyPI]
#   packages: [lodash]
#   include_dev: false
#   runtime: true
#   has_fix: true

actions:                     # run in order, once per run, on the findings that fired
  - pin_patch: { base: main }
  - notify: { webhook: { url_env: PATCHNOW_WEBHOOK_URL } }

state: { path: .patchnow/state.json, refire_after_days: 0 }
audit: { path: .patchnow/audit.jsonl }
cache: { path: .patchnow/cache }
```

Any action can carry `when:` with trigger syntax to narrow it further, for example
`safe_mode: { when: { kev: true }, ... }`.

**Severity:** the GitHub advisory label wins when OSV provides one. Otherwise patchnow buckets the CVSS v3 base
score, which it computes from the vector. **EPSS** is the highest score among the finding's CVE aliases.

**Dedupe:** a finding is keyed by `ecosystem|package|version|advisory`. After an armed run acts on a key, that key
does not fire again unless `refire_after_days` is above 0. Dry runs record nothing.

## Actions

**pin_patch**

Computes the smallest version that clears every fired advisory for each package, then edits the manifest:

| Manifest | How it is edited |
|---|---|
| npm, direct dependency | `npm install pkg@X --package-lock-only --ignore-scripts`, keeping exact or range style |
| npm, transitive dependency | an `overrides` entry, then `npm install --package-lock-only` |
| pnpm | `pnpm.overrides` + `pnpm install --lockfile-only` |
| requirements.txt | rewrites the pin; any stale `--hash` is dropped |
| go.mod | `go get` + `go mod tidy` |
| Cargo.lock | `cargo update --precise` |
| composer.lock | `composer require` / `composer update --no-install` |

After the edit it re-parses the lockfile to confirm the vulnerable versions are gone. For npm it also runs
`npm ls`. It then commits on `patchnow/<date>-<hash>` as `github-actions[bot]` inside GitHub Actions
(else `patchnow <patchnow@localhost>`; override with `author_name` / `author_email`), pushes,
opens a pull request through the GitHub REST API (`GITHUB_TOKEN`, `GITHUB_API_URL`; the repository comes from
`repo`, `GITHUB_REPOSITORY` or the remote URL) and returns to your original branch. It refuses to run on a dirty
working tree. `yarn.lock`, `poetry.lock` and runtimes are reported as manual work.

**safe_mode**

| `provider` | What it does |
|---|---|
| `render_deploy_hook` | POSTs a Render deploy hook, for example a maintenance build |
| `vercel_promote` | `POST /v10/projects/{project_id}/promote/{deployment_id}` promotes a known-good deployment |
| `webhook` | POSTs JSON to your feature-flag or kill-switch endpoint, with an optional HMAC `X-Patchnow-Signature: sha256=…` |

**revoke**

- GitHub tokens named in `github_tokens_env` (ghp_, github_pat_, gho_, ghu_, ghr_) go to GitHub's unauthenticated
  `POST /credentials/revoke` endpoint.
- `npm_token_ids` are revoked with `npm token revoke <id>`.
- It only executes when the policy is armed **and** `confirm: true`. Token values never appear in output or logs.

**notify**

- Channels: `webhook` (JSON, optional HMAC), `slack` (incoming webhook), `telegram` (Bot API), `ntfy` (ntfy.sh or
  self-hosted) and `email` (built-in SMTP client with implicit TLS or STARTTLS; it will not send credentials
  without TLS).
- The message includes the results of earlier actions, such as the PR link.
- A dry run sends nothing unless `send_in_dry_run: true`.

## GitHub Action

`patchprojectx/patch` is a composite action (`action.yml` at the repository root). It installs patchnow,
restores `.patchnow/` with `actions/cache`, runs `patchnow run --sarif`, and uploads the SARIF report to code
scanning. See `examples/workflow.yml` for a 15-minute cron with `contents: write`, `pull-requests: write` and
`security-events: write`.

```yaml
- uses: actions/checkout@v4
- uses: patchprojectx/patch@v0.1      # moving tag for v0.1.x; pin @v0.1.0 or a commit SHA for exact builds
  with:
    config: patch.yml
```

| Input | Default |
|---|---|
| `config` | `patch.yml` |
| `working-directory` | `.` |
| `dry-run` | `false` |
| `sarif` | `patchnow.sarif` |
| `upload-sarif` | `true` |
| `github-token` | `${{ github.token }}` |
| `persist-state` | `true` |

## Security model

- **What leaves your machine:** package names and versions (to `api.osv.dev`) and CVE ids (to `api.first.org`). The
  KEV catalog is downloaded from cisa.gov and cached for 6 hours. Source code, lockfile contents beyond
  name and version, and environment variables are never sent.
- **Secrets:** they are never stored in `patch.yml`. Fields ending in `_env` name an environment variable, and
  token values are redacted from URLs in errors.
- **Least surprise:** nothing is destructive until `armed: true`. Revocation also needs `confirm: true`. Lockfile
  updates use `--ignore-scripts`. The tool never merges anything; a human reviews the PR.
- **Audit:** every run writes `run.start`, `scan`, one `decision` per finding, one `action` per action and
  `run.end` to `.patchnow/audit.jsonl`.

## Limitations (v0.1)

- **Coverage:** findings are only as good as OSV coverage for your ecosystem. Matching is by package and version;
  there is no reachability analysis.
- **Approximate manifests:** a `package.json` without a lockfile and `go.sum`-only projects can over-report.
  `requirements.txt` ranges are skipped.
- **Version choice:** the minimum fixed version can still be a breaking change for a few packages. Run your tests
  on the PR.
- **Untested editors:** the pnpm, Go, Cargo and Composer editors call the native tools but are not covered by the
  end-to-end test. The npm path is. `yarn.lock` is not edited.
- **GitHub Actions behavior:** PRs opened with the default `GITHUB_TOKEN` do not trigger other workflows; use a
  GitHub App or PAT if your CI must run on them. `actions/cache` state is best-effort.
- **Runtime table:** the Node.js and PHP table is curated by hand. It is not a live feed.
- **Not built in:** Windows and SBOM inputs (CycloneDX/SPDX) are not supported yet.

## Development

```
npm test            # unit + e2e (the e2e test uses the live OSV/KEV/EPSS APIs and skips when offline)
npm run test:unit
npm run test:e2e
```

The e2e test builds a throwaway git repository containing `lodash@4.17.15` and `optimist@0.6.1` (which pulls in
`minimist@0.0.10`), a local bare `origin`, a local mock of the GitHub REST API and a local webhook receiver. It
then checks the whole loop:

- The dry run changes nothing.
- The armed run creates a branch, a commit that npm resolves (`lodash` as a direct dependency, `minimist` as an
  override), a push to `origin`, a PR request, a webhook alert and the audit and state records.
- A second run is deduplicated.

`src/core.js` holds the version, range and severity logic. It is shared byte-for-byte with the in-browser checker
on the PATCH site.

MIT License.
