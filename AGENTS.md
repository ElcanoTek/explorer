# AGENTS.md

Operating guide for AI coding agents in **Explorer**. Claude Code reads this
file directly, so there is no `CLAUDE.md` (and never a symlink alias: the
install refuses any symlink in the source tree). Humans: start with
`README.md`, `CONTRIBUTING.md`, `SECURITY.md` and `docs/DEPLOYMENT.md`; this is
the short version.

Do not add a `CLAUDE.md` or `CLAUDE.local.md` here (or above the checkout):
Claude Code then loads those instead and skips this file.

## What it is

One Go binary, `explorer`, that browses SES-delivered email stored in S3:
date-partitioned search, ranged header reads, message view, attachments.
`explorer serve` runs the web service on loopback behind Caddy
(`deploy/systemd/explorer.service`); every other verb is the operator CLI
installed at `/usr/local/bin/explorer` (`doctor`, `update`, `rebuild`,
`access`, `env`, `tls`, `provision`, `bootstrap`, service control).
`install.sh` → `scripts/bootstrap.sh` builds the binary from the root-owned
checkout and hands over to `explorer bootstrap` (which also removes Cockpit
and makes SSH key-only); `explorer update` fetches, builds a staged binary
and lets that new binary perform the swap, health check and rollback.
Licensed BSL 1.1; every first-party source file carries the SPDX header
(CONTRIBUTING.md).

| Package | What lives there |
|---|---|
| `cmd/explorer` | entry point: `serve`, `version`, `access`; hands the rest to `internal/ops` |
| `internal/web` | HTTP service, middleware, templates and static assets (embedded) |
| `internal/archive` | S3 listing, ranged header reads, search, message and attachment extraction |
| `internal/mailmsg` | lenient MIME parsing (the role Python's `email` package played) |
| `internal/htmlsafe` | the HTML sanitizer and linkifier — the XSS boundary |
| `internal/auth`, `internal/centralauth` | Elcano cookie verifier; central SSO client, token checks, SQLite access/session store |
| `internal/config`, `internal/dotenv` | settings and the python-dotenv-compatible `.env` parser |
| `internal/ops` | doctor, update/rebuild, bootstrap, provision, env, tls, service control |
| `deploy/` | systemd unit, tmpfiles rule, Caddy site, motd — embedded into the binary |

## Build · test · lint

```sh
make build                    # ./explorer, revision stamped from git
go vet ./... && golangci-lint run          # v2.14.0, .golangci.yml
go test -race ./...           # no AWS, no network
make test-root                # root-only install/update/rollback lifecycle
shellcheck -S warning $(git ls-files '*.sh')
```

CI (`.github/workflows/ci.yml`) runs exactly these (plus `gofmt -l`, a
`go mod tidy` diff check and govulncheck). CodeQL (Go + Actions) runs
separately. Fixtures stay synthetic (`.example` addresses only).

## Security notes (each is pinned by tests)

- **Email HTML is hostile.** `internal/htmlsafe` parses with
  `golang.org/x/net/html` and rebuilds the markup from an explicit
  tag/attribute/scheme allow-list; `data:`/`cid:` survive only on `<img>`,
  and a link's scheme must be http, https, mailto or relative. The output is
  emitted as `template.HTML`, so the sanitizer IS the boundary. The linkifier
  must only ever see that sanitized (or escaped) output. The tests hold an XSS
  corpus and the recorded golden output; widening the allow-list needs a very
  good reason.
- **CSP** (`internal/web/server.go`): one nonce'd inline script (the theme
  bootstrap), everything else same-origin files; `style-src 'self'`,
  `object-src 'none'` — defence in depth behind the sanitizer, not instead.
  Attachments are served with `sandbox` and active types as
  `application/octet-stream`.
- **`isAllowedS3Key`** is the S3 prefix boundary for the `s3_key` parameter; do
  not loosen it without a test proving the new bound.
- **Auth fails closed**: every verifier failure path in `internal/auth` /
  `internal/centralauth` returns "logged out" (nil / an error), never a
  partial identity.
- **Install trust boundary**: root owns the checkout, `/opt/explorer`, the
  binary and the build cache; the service user owns only the dotenv files and
  `/var/lib/explorer`. Root builds only from a checkout it has verified to be
  root-owned, non-writable and symlink-free, and installs privileged files
  only from the binary it just built (they are embedded).
- Never commit a dotenv file; only `.env.example` is tracked.

## Dependencies and in-housed code

Policy: prefer the standard library or a small piece of owned code; add a
module only when it clearly earns its keep. Direct dependencies today:
`aws-sdk-go-v2` (S3), `modernc.org/sqlite` (pure-Go SQLite, so the binary
stays CGO-free), `golang.org/x/net/html` (sanitizer parsing) and
`golang.org/x/text` (charsets, Unicode normalization). Dependabot proposes
updates (daily, cooldown of 7 days (3 for patch releases), grouped;
`.github/dependabot.yml`); a human merges them only when the bump earns it —
a security fix whose code path we use, or a specific commit we need. On a
CVE, check reachability first (govulncheck does this in CI).

| In-housed | Where | Upstream · version · license |
|---|---|---|
| dotenv parser and interpolation (Go port) | `internal/dotenv/` (+ `LICENSE`, listed in `NOTICE`) | python-dotenv 1.2.4 · BSD-3-Clause |
| HTML sanitizer and URL linkify | `internal/htmlsafe/` | — (BUSL-1.1) |
| flatpickr date picker (static asset) | `internal/web/static/vendor/flatpickr/` | flatpickr 4.6.13 · MIT |

Workflows pin every action by full commit SHA with a `# vX.Y.Z` comment
(the same SHAs fleet uses); Dependabot's `github-actions` entry moves them.
Checkouts use `persist-credentials: false`, permissions default to
`contents: read`, and PR runs cancel superseded ones.
