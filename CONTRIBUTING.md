# Contributing to Explorer

Thanks for taking the time. Explorer is one small Go binary, so the loop is
short: clone, build, run the tests.

## Licensing of contributions

Explorer is source-available under the [Business Source License
1.1](LICENSE) — **not** an open-source licence. By opening a pull request you
agree that your contribution is licensed under the same BSL 1.1 terms as the
rest of the project, and that ElcanoTek, Inc. may relicense it under the
Change License (MIT) when the Change Date for that version arrives, or under
a commercial licence.

If that does not work for you, please open an issue instead of a PR and we
will find another way to get the fix in. See
[docs/LICENSING.md](docs/LICENSING.md) for what BSL does and does not allow.

## Setup

Go, new enough to fetch the toolchain `go.mod` pins (any Go 1.21+ with
`GOTOOLCHAIN=auto`, which the Makefile sets).

```bash
git clone https://github.com/ElcanoTek/explorer.git
cd explorer
make build
```

Copy `.env.example` to `.env` if you want to run the app (`./explorer
serve`; set `EXPLORER_UI_COOKIE_SECURE=0` for plain-HTTP development).
**Never commit a dotenv file** — every `.env*` variant except `.env.example`
is gitignored, and a real one has been committed here before.

## Tests

```bash
go test -race ./...
make test-root      # the install lifecycle harness; needs sudo
```

The suite runs in seconds with **no AWS account and no network needed**.
Anything that would touch S3 goes through the in-memory fake store in
`internal/archive`, anything that talks to the central auth service uses an
`httptest` server, and anything that needs a signed-in browser mints a
throwaway Ed25519 key and its own session cookie. Please keep it that way: a
test that needs credentials is a test nobody runs.

The suite covers these areas, and a change in any of them should come with a
test:

| Package | Covers |
|---|---|
| `internal/auth` | The Elcano cookie verifier — valid, expired, tampered, foreign-key, malformed. |
| `internal/centralauth` | Token verification, JWKS rotation, the code exchange, the access list, opaque app sessions, expiry, revocation, CSRF, and compatibility with existing `access.db` files. |
| `internal/web` | Routes end to end via `httptest`, signed in and anonymous, both auth modes; date-range parsing, S3 key scoping, search jobs and cursors, security headers. |
| `internal/archive`, `internal/mailmsg` | Prefix expansion, header parsing, search, message rendering, attachments, MIME edge cases. |
| `internal/htmlsafe` | The sanitizer and linkifier: XSS corpus, golden output, linear-time behaviour on hostile input. |
| `internal/dotenv`, `internal/config` | `.env` parsing identical to python-dotenv, layering, bootstrap's in-place merge. |
| `internal/ops` | doctor checks, update/rollback, bootstrap helpers (Caddy, hostname, SSH, Cockpit), provision, env redaction. |

**Fixtures must be synthetic.** This app reads real people's mail; invented
senders and subjects only (`ada@example.com`, `reports@vendor.example`, the
reserved `.example` TLD). Never paste a real message, address, subject or
attachment name into a test, a template placeholder or a screenshot.

## Lint and format

```bash
gofmt -l .                       # must print nothing
go vet ./...
golangci-lint run                # v2.14.0; rules in .golangci.yml
shellcheck -S warning $(git ls-files '*.sh')
```

CI runs exactly these. Every `//nolint` names the linter and says why.

## Source headers

Every first-party source file carries:

```go
// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.
```

(`#` comments in shell, after the shebang; `/* */` in CSS; `//` in JS). New
files need it too. Vendored assets under `internal/web/static/vendor/` are
left alone; code ported from another project keeps its upstream license
header and LICENSE file instead (`internal/dotenv`, see `NOTICE`).

## Branches and pull requests

- Branch off `main`; `main` is protected and takes changes only via PR.
- Name branches by type: `feat/…`, `fix/…`, `chore/…`, `docs/…`,
  `audit/…` — matching the existing history.
- Keep commit subjects imperative and specific ("Harden S3 key scoping", not
  "updates"). Group related changes into one commit rather than one commit per
  file.
- One topic per PR. Say what breaks and how you tested it.
- CI (`.github/workflows/ci.yml`) must be green: format, vet, lint, race
  tests, the root lifecycle test, govulncheck and shellcheck.
  CodeQL (`.github/workflows/codeql.yml`) scans on every push and PR and
  weekly; a new alert on your branch is yours to look at.
- Use the issue and pull-request templates under `.github/`; they ask for
  exactly what a reviewer needs.
- Dependencies are pinned by `go.mod`/`go.sum`; run `go mod tidy` after
  changing imports (CI fails on an untidy module). Dependabot proposes bumps
  daily (grouped, after a cooldown of 7 days (3 for patch releases)); read
  AGENTS.md › Dependencies for when one is worth merging.

## Things worth knowing before you change them

- **`internal/auth` and `internal/centralauth` are security-critical.** Every
  failure path must come back as "logged out" (nil or an error), never a
  partial identity a caller might accept. Add a test for any new path.
- **`isAllowedS3Key` in `internal/web` is the prefix boundary.** It is what
  stops the `s3_key` query parameter being walked around the bucket. Do not
  loosen it without a test proving the new bound.
- **Search jobs run in goroutines** and share an in-memory store; every read
  and write goes through its mutex, and a job's context is how Cancel and the
  server-side timeout reach in-flight S3 calls.
- **HTML mail is hostile input.** Body rendering goes through
  `internal/htmlsafe` with an explicit allow-list, and `data:`/`cid:` URLs
  are permitted for inline images but rejected for links. Widening that list
  needs a very good reason. The linkifier runs only on sanitized (or escaped)
  output; the tests pin the whole pipeline, XSS corpus included.
- **Header reads are ranged GETs.** Keep the per-row cost proportional to
  `EMAIL_HEADER_FETCH_BYTES`; do not download whole objects to render a list.
- **The operator tooling runs as root.** Anything in `internal/ops` that
  touches the filesystem must refuse symlinks and hard links where the
  existing code does, and must never execute or install from a path the
  service account can write.

## Reporting security issues

Do **not** open a public issue. See [SECURITY.md](SECURITY.md).
