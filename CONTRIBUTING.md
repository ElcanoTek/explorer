# Contributing to Explorer

Thanks for taking the time. Explorer is a small FastAPI app, so the loop is
short: clone, make a venv, run the tests.

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

Python 3.11 or newer (CI runs 3.12).

```bash
git clone https://github.com/ElcanoTek/explorer.git
cd explorer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install pytest httpx2 ruff
```

Copy `.env.example` to `.env` if you want to run the app. **Never commit a
dotenv file** — every `.env*` variant except `.env.example` is gitignored,
and a real one has been committed here before.

## Tests

```bash
python -m pytest -q
```

61 tests, under a second, **no AWS account and no network needed**. Anything
that would touch S3 goes through the fake client in `tests/test_s3_email.py`
(`FakeS3`), and anything that needs a signed-in browser mints a throwaway
Ed25519 key and its own session cookie (`tests/test_endpoints.py`). Please
keep it that way: a test that needs credentials is a test nobody runs.

The suite covers four areas, and a change in any of them should come with a
test:

| File | Covers |
|---|---|
| `tests/test_auth.py` | The cookie verifier — valid, expired, tampered, foreign-key, malformed. |
| `tests/test_date_parsing.py` | Date-range parsing, day counting, S3 key scoping, cursor cache. |
| `tests/test_s3_email.py` | Prefix expansion, header parsing, search, HTML sanitizing, attachments. |
| `tests/test_endpoints.py` | Routes end to end via `TestClient`, signed in and anonymous. |

**Fixtures must be synthetic.** This app reads real people's mail; invented
senders and subjects only (`ada@example.com`, `reports@vendor.example`, the
reserved `.example` TLD). Never paste a real message, address, subject or
attachment name into a test, a template placeholder or a screenshot.

## Lint and format

```bash
ruff check app tests
ruff format --check app tests
```

Rules live in `ruff.toml` (pinned selection, so your local Ruff matches CI).
`ruff check --fix` and `ruff format` apply the fixes. Both commands must be
clean; CI runs exactly these.

## Source headers

Every first-party source file carries:

```python
# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.
```

New files need it too — after the shebang, if there is one. Vendored code
under `app/static/vendor/` is left alone.

## Branches and pull requests

- Branch off `main`; `main` is protected and takes changes only via PR.
- Name branches by type: `feat/…`, `fix/…`, `chore/…`, `docs/…`,
  `audit/…` — matching the existing history.
- Keep commit subjects imperative and specific ("Harden S3 key scoping", not
  "updates"). Group related changes into one commit rather than one commit per
  file.
- One topic per PR. Say what breaks and how you tested it.
- CI (`.github/workflows/ci.yml`) must be green: lint, format check, tests.
- Dependency bumps arrive via Dependabot (`.github/dependabot.yml`); please
  don't hand-roll them.

## Things worth knowing before you change them

- **`app/auth.py` is security-critical.** Every failure path must return
  `None` (= logged out), never an exception that a caller might swallow into
  a success. Add a test for any new path.
- **`is_allowed_s3_key` in `app/main.py` is the prefix boundary.** It is what
  stops the `s3_key` query parameter being walked around the bucket. Do not
  loosen it without a test proving the new bound.
- **Search jobs run in worker threads** and mutate module-level caches;
  `CACHE_LOCK` guards them. Read-modify-write on those dicts without the lock
  loses updates.
- **HTML mail is hostile input.** Body rendering goes through `bleach` with an
  explicit allow-list, and `data:`/`cid:` URLs are permitted for inline
  images but rejected for links. Widening that list needs a very good reason.
- **Header reads are ranged GETs.** Keep the per-row cost proportional to
  `EMAIL_HEADER_FETCH_BYTES`; do not download whole objects to render a list.

## Reporting security issues

Do **not** open a public issue. See [SECURITY.md](SECURITY.md).
