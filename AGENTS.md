# AGENTS.md

Operating guide for AI coding agents in **Explorer**. `CLAUDE.md` imports
this file with `@AGENTS.md` — a regular file, not a symlink, because the
install refuses any symlink in the source tree (`layout_require_trusted`).
Humans: start with `README.md`, `CONTRIBUTING.md`,
`SECURITY.md` and `docs/DEPLOYMENT.md`; this is the short version.

## What it is

A small FastAPI app (`app/`) that browses SES-delivered email stored in S3:
date-partitioned search, ranged header reads, message view, attachments. It
runs as one `python -m uvicorn app.main:app` process on loopback behind Caddy
(`deploy/systemd/explorer.service`), installed by `install.sh` →
`scripts/bootstrap.sh` and updated by `scripts/update.sh`, which build the
venv with `uv` through `scripts/lib/layout.sh`. Licensed BSL 1.1; every
first-party source file carries the SPDX header (CONTRIBUTING.md).

## Build · test · lint

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install --require-hashes -r requirements.txt -r requirements-dev.txt
ruff check app tests && ruff format --check app tests
python -m pytest -q                       # no AWS, no network
sudo env PATH="$PATH" bash scripts/test/layout_test.sh   # root-only install lifecycle
```

CI (`.github/workflows/ci.yml`) runs exactly these on Python 3.11 and 3.12,
plus a `dependencies` job: the locks must match their `.in` files and
`pip-audit` must find nothing. CodeQL runs separately. Fixtures stay
synthetic (`.example` addresses only).

## Security notes (each is pinned by tests)

- **Email HTML is hostile.** `S3EmailInbox._render_html_preview` sanitizes
  with `nh3` (Rust ammonia) against an explicit tag/attribute/scheme
  allow-list in `app/s3_email.py`; `data:`/`cid:` survive only on `<img>`,
  and a link's scheme must be http, https, mailto or relative. The output is
  rendered with `| safe`, so the sanitizer IS the boundary. `app/linkify.py`
  must only ever see that sanitized (or `html.escape`d) output.
  `tests/test_html_render.py` holds an XSS corpus and the bleach-era golden
  output; widening the allow-list needs a very good reason.
- **CSP** (`app/main.py`): nonce'd scripts only, `style-src 'self'`,
  `object-src 'none'` — defence in depth behind the sanitizer, not instead.
- **`is_allowed_s3_key`** is the S3 prefix boundary for the `s3_key`
  parameter; do not loosen it without a test proving the new bound.
- **Auth fails closed**: every verifier failure path in `app/auth.py` /
  `app/central_auth.py` returns "logged out", never an exception.
- **Install trust boundary**: root owns source and executables; the service
  user owns only `.venv`, `.tmp`, the dotenv files and `/var/lib/explorer`.
  Root never executes from a service-writable path (`scripts/lib/layout.sh`,
  `scripts/doctor.py` reads venv metadata instead of running it).
- Never commit a dotenv file; only `.env.example` is tracked.

## Dependencies and in-housed code

Policy: prefer the stdlib or a small piece of owned code; add a dependency
only when it clearly earns its keep. Update one only for a specific fix we
need or a CVE whose code path we actually reach — not on a schedule
(Dependabot opens **security** updates only for pip). On a CVE, check
reachability first; if the affected code is unused, delete it; if it is
used, bump or adapt the patch.

The tree is locked with hashes. Edit only `requirements.in` /
`requirements-dev.in`, then regenerate under **Python 3.11** with pip-tools
from `requirements-dev.txt`:

```sh
pip-compile --generate-hashes --strip-extras requirements.in
pip-compile --generate-hashes --strip-extras --allow-unsafe requirements-dev.in
```

Every install (CI, `layout.sh`, the manual steps in `docs/DEPLOYMENT.md`)
uses `--require-hashes`. `uvicorn` is installed without `[standard]`
(asyncio + h11; nothing needs websockets, uvloop or httptools).

| In-housed | Where | Upstream · version · license |
|---|---|---|
| dotenv parser, interpolation, `load_dotenv` (trimmed) | `app/_vendor/dotenv/` (+ `LICENSE`, listed in `NOTICE`) | python-dotenv 1.2.4 · BSD-3-Clause |
| URL linkify for sanitized markup (own code, replaces `bleach.linkify`) | `app/linkify.py` | — (BUSL-1.1) |
| flatpickr date picker (static asset) | `app/static/vendor/flatpickr/` | flatpickr 4.6.13 · MIT |

`bleach` was replaced by `nh3` (maintained, MIT). There are no data files to
refresh: the bare-domain TLD set in `app/linkify.py` is a short literal.
