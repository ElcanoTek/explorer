# AGENTS.md

Operating guide for AI coding agents in **Explorer**. Claude Code reads this
file directly, so there is no `CLAUDE.md` (and never a symlink alias: the
install refuses any symlink in the source tree). Humans: start with
`README.md`, `CONTRIBUTING.md`, `SECURITY.md` and `docs/DEPLOYMENT.md`; this is
the short version.

Do not add a `CLAUDE.md` or `CLAUDE.local.md` here (or above the checkout):
Claude Code then loads those instead and skips this file.

<!-- BEGIN:elcano-frontend-standard v2 (shared verbatim by every Elcano repo; scripts/stack-check.sh pins its hash; change it everywhere or nowhere) -->
## Elcano frontend standard (v2)

Every Elcano web product follows one of two tiers. `stack.conf` at the repo
root declares which, and `scripts/stack-check.sh` (run by CI) enforces it.

**The server is Go and serves everything.** The browser talks to one origin:
the Go binary serves the HTML, the static assets and the JSON API, and it owns
sign-in (the `elcano_auth` cookie from the auth service), sessions, CSRF and
security headers. There is no Node, Python or other JavaScript server in
production. Static files ship inside the binary with `go:embed`; Caddy only
terminates TLS and reverse-proxies to Go.

**Tier A — server-rendered (the default).** Go `html/template` pages, plain
CSS that reads Flag tokens, and small plain-JavaScript modules (no framework,
no bundler, no transpiler, no npm runtime dependencies). npm may appear only
as a dev dependency for browser tests (Playwright, axe). Pick Tier A unless the
page is a long-lived, state-heavy application. Components use Flag's CSS
component classes, which mirror the names and states of Flag's shadcn/ui
components so both tiers look and behave alike.

**Tier B — interactive app.** React + TypeScript built by Vite into a static
bundle that the Go server embeds and serves (same origin, so no CORS). No
server-side rendering, no Next.js, no runtime server code in TypeScript; data
comes from the Go JSON API. Base UI components come from Flag's shadcn/ui
registry (React + Radix + Tailwind, themed by Flag tokens; registry URL in
Flag's README): `npx shadcn add` copies them into the app, where they live and
are reviewed like our own code. Build a component by hand only when the
registry lacks it, then upstream it to Flag. Keep other runtime npm
dependencies few and justified in AGENTS.md. Use Tier B only when Tier A would
mean re-implementing a client-side state framework by hand (streaming chat,
multi-step builders).

**Both tiers:**

- Design comes from Flag (`ElcanoTek/flag`). Vendored Flag files are listed in
  `flag.lock` with their hashes; `scripts/flag-sync.sh check` fails CI on any
  hand edit. Update with `scripts/flag-sync.sh sync`, never by editing in place.
  Product styling lives outside the vendored directories and reads tokens.
- No third-party CDNs: every script, stylesheet and font is served by our own
  binary. Fonts are Flag's Nebula Sans and Hack only.
- A strict Content-Security-Policy (no `unsafe-inline` scripts, no remote
  script hosts), `X-Content-Type-Options: nosniff`, and `frame-ancestors`.
- Hashed or versioned asset URLs with long-lived caching; HTML is `no-cache`.
- Accessibility is tested (Playwright + axe where a browser suite exists).
- Exceptions (a non-Go backend, an extra runtime dependency) are written down
  in this repo's AGENTS.md with the reason, not left implicit.
<!-- END:elcano-frontend-standard -->

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
| `internal/web` | HTTP service, middleware, templates and static assets (embedded); `jstest/` holds the Node unit tests for the plain-JS modules |
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
make test-js                  # node --test internal/web/jstest/*.test.js (no npm)
make stack-check              # scripts/stack-check.sh: frontend standard, flag.lock, no CDNs
make test-root                # root-only install/update/rollback lifecycle
shellcheck -S warning $(git ls-files '*.sh')
make ci                       # stack-check, vet, lint, race tests, JS tests, govulncheck
```

CI (`.github/workflows/ci.yml`) runs exactly these (plus `gofmt -l`, a
`go mod tidy` diff check and govulncheck). CodeQL (Go + Actions) runs
separately; `flag-drift.yml` runs weekly (below). Fixtures stay synthetic
(`.example` addresses only). In a Claude Code cloud session,
`.claude/hooks/session-start.sh` downloads modules and installs the pinned
golangci-lint first.

## Frontend (Tier A)

`stack.conf` declares Tier A, Go backend. Everything the browser gets is
served by the binary from `internal/web` via `go:embed`:

- `templates/*.html` — `html/template` pages (`base.html` + one per page).
  No inline styles or handlers; the only inline script is the nonce'd theme
  bootstrap in `base.html`.
- `static/styles.css` — product CSS; it reads Flag tokens and never hard-codes
  colours. `static/js/*.js` — small plain scripts, no build step, no npm:
  `base.js` (theme, loading bar), `inbox.js` (search form, results, detail
  panel), `email.js`, and two modules with Node unit tests:
  `datepicker.js` (the date field) and `date-ranges.js` (range-day
  arithmetic, mirroring `countDaysCovered` in `dates.go`).
- Components follow Flag's anatomy and class names (`.ds-app-header`,
  `.ds-checkbox`, `.btn`, … per Flag's COMPONENTS.md), implemented in
  `styles.css` today. When Flag ships a vendorable component stylesheet
  mirroring its shadcn/ui registry, vendor it with `flag-sync.sh add` and
  drop the matching product rules rather than keeping two copies.
- Asset URLs carry `?v=<content hash>` (`staticVersion` in `render.go`);
  pages are `no-store`.

**Date field.** In-house since flatpickr was removed (2026-10). The text input
is the source of truth and always submits `YYYY-MM-DD`; the server parses
only that (`parseDay`). We did not use native `<input type="date">`: its popup
cannot take Flag styling (it ignores tokens and themes), and the field needs
the old typed-entry and phone behaviour. The calendar follows the WAI-ARIA
date-picker dialog pattern (arrows, Home/End, PageUp/PageDown with Shift for
years, Enter/Space, Escape, Alt+Down from the field); on viewports up to
1023px the field is read-only so phones show the calendar, not a keyboard.
Its CSS is `.datepicker` / `.date-input-button` in `styles.css`. Rows added by
"Add range" are built by `inbox.js` with the same markup as the
`date_input` template (`TestAddedRangeRowsMatchTheTemplate`).

**Flag (design system).** `static/design-system/` is vendored from
ElcanoTek/flag and byte-identical to it; `flag.lock` lists each file with its
sha256 and the flag commit. Never edit those files: product styling goes in
`static/styles.css`. To update, with a flag checkout at `../flag`:

```sh
scripts/flag-sync.sh status     # what differs from ../flag (FLAG_DIR=... or pass a path)
scripts/flag-sync.sh sync       # re-copy every locked file, rewrite flag.lock
scripts/flag-sync.sh add ../flag icons/core-icons.svg internal/web/static/design-system/icons/core-icons.svg
```

Then check the icon ids the templates use (`core-icons.svg#…`) still exist,
render the pages in both themes, and commit files and lock together. The PR
gate is `scripts/stack-check.sh` (offline: hand edits and CDN use fail it);
`.github/workflows/flag-drift.yml` reports weekly whether flag `main` has
moved past `flag.lock`. Flag is MIT (NOTICE). A gap in Flag is fixed upstream
in ElcanoTek/flag, not patched here.

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
  bootstrap), everything else same-origin files; `style-src 'self'`;
  `object-src`, `frame-src`, `media-src`, `worker-src` and `base-uri` all
  `'none'` — defence in depth behind the sanitizer, not instead. No
  `form-action` (it would break Elcano logout's redirect). Scripts may set
  `element.style` (the date picker positions its calendar that way); markup
  may not carry `style=""`.
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
| Date picker and range arithmetic (plain JS) | `internal/web/static/js/datepicker.js`, `date-ranges.js` | — (BUSL-1.1; replaced flatpickr 4.6.13 in 2026-10) |
| Flag design system (vendored, not in-housed) | `internal/web/static/design-system/` (`flag.lock`) | ElcanoTek/flag · MIT |

Workflows pin every action by full commit SHA with a `# vX.Y.Z` comment
(the same SHAs fleet uses); Dependabot's `github-actions` entry moves them.
Checkouts use `persist-credentials: false`, permissions default to
`contents: read`, and PR runs cancel superseded ones.
