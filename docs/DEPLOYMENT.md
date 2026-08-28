# Deploying Explorer

The authoritative deployment guide. Every path and command below is taken
from the scripts and unit files in this repository (`scripts/`, `deploy/`) —
if you change those, change this document too.

Explorer is a single-process FastAPI app. It stores nothing durable: no
database, no queue, no cache server. All state is the S3 archive it reads,
plus a handful of in-memory caches and a temp directory for attachments in
flight. That makes deployment simple and makes rollback almost free.

- [Prerequisites](#prerequisites)
- [Install](#install)
- [Service user and directory layout](#service-user-and-directory-layout)
- [Environment variables](#environment-variables)
- [AWS IAM policy](#aws-iam-policy)
- [Attachment cleanup timer](#attachment-cleanup-timer)
- [TLS and the reverse proxy](#tls-and-the-reverse-proxy)
- [Managing the service](#managing-the-service)
- [Updating and rolling back](#updating-and-rolling-back)
- [Health checks](#health-checks)
- [Troubleshooting](#troubleshooting)
- [Manual install](#manual-install-without-bootstrapsh)

## Prerequisites

**Supported OS.** `scripts/bootstrap.sh` installs packages with `dnf` and is
written for **Fedora 39+, RHEL 9+, AlmaLinux/Rocky 9+**. It also assumes
`systemd`, and handles SELinux (it stages builds next to `/opt/explorer`
rather than in `/tmp`, and runs `restorecon` after swapping files in). It
will not run on Debian/Ubuntu without translating the package step; see
[Manual install](#manual-install-without-bootstrapsh).

**Packages** (installed for you by bootstrap): `git curl jq python3
python3-devel gcc uv ripgrep rsync openssl`. Python dependency installation
uses [`uv`](https://docs.astral.sh/uv/) rather than `pip` — on current Fedora,
`pip` hits PEP 668 restrictions and resolver limits with this dependency
graph. `uv` is in the Fedora repositories.

**You also need:**

- Root (the installer creates a system user and writes to `/etc/systemd/system`).
- An S3 bucket holding SES-delivered MIME objects, and read-only credentials
  for it — see [AWS IAM policy](#aws-iam-policy).
- The base64 Ed25519 **public** key of your magic-link auth service
  (`AUTH_SIGNING_PUBKEY`). Without it Explorer redirects every request to
  sign-in and nobody can get in.
- For automatic TLS: a public DNS `A` record pointing at the box, and
  inbound 80/443.

## Install

```bash
sudo dnf install -y git
sudo git clone https://github.com/ElcanoTek/explorer.git /opt/explorer-src
sudo bash /opt/explorer-src/scripts/bootstrap.sh
```

`bootstrap.sh` is interactive and **safe to re-run** — it re-reads the
existing `/opt/explorer/.env` and only prompts for values that are still
missing. In order it:

1. Installs the dnf packages above.
2. Creates the `explorer` system user and `/opt/explorer`.
3. Seeds `/opt/explorer-src` (with `.git`, so updates can `git fetch`) and
   rsyncs the source into `/opt/explorer`.
4. Builds `/opt/explorer/.venv` with `uv` and installs `requirements.txt`.
5. Prompts for `AUTH_SIGNING_PUBKEY`, a TLS hostname, `EMAIL_S3_BUCKET` and
   `AWS_REGION`; generates `EXPLORER_SESSION_SECRET`; writes
   `/opt/explorer/.env` mode `0640`, owned by `explorer`.
6. Installs the systemd units, the tmpfiles rule and
   `/usr/local/bin/explorer`.
7. Enables and starts `explorer.service` and the cleanup timer, then health
   checks `http://127.0.0.1:8080/`.
8. Optionally installs Caddy with Let's Encrypt or `tls internal`.
9. Installs `deploy/motd` to `/etc/motd`.

**AWS keys are deliberately not prompted for.** Bootstrap leaves
`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` commented out in the generated
`.env`. Add them with `sudo explorer env edit`, or skip them entirely and
attach an instance role — `boto3` falls back to the ambient credential chain
when both are blank.

### Scripted installs

Set `EXPLORER_BOOTSTRAP_NON_INTERACTIVE=1` plus the values you want; any
prompt with no value and no default aborts the run.

```bash
sudo EXPLORER_BOOTSTRAP_NON_INTERACTIVE=1 \
     AUTH_SIGNING_PUBKEY='...' \
     EMAIL_S3_BUCKET='my-email-archive' \
     AWS_REGION='us-east-1' \
     EXPLORER_BOOTSTRAP_HOSTNAME='explorer.example.com' \
     EXPLORER_BOOTSTRAP_SETUP_CADDY=Y \
     EXPLORER_BOOTSTRAP_USE_LETSENCRYPT=Y \
     EXPLORER_BOOTSTRAP_LE_EMAIL='ops@example.com' \
     bash /opt/explorer-src/scripts/bootstrap.sh
```

Leave `EXPLORER_BOOTSTRAP_HOSTNAME` empty to skip the proxy entirely and
front Explorer with your own.

### Optional: encrypted config bundles

`scripts/provision.sh` (`sudo explorer provision`) decrypts
`provision/clients/<name>.env.enc` with `openssl enc -aes-256-cbc -pbkdf2
-iter 600000` and merges the `KEY=VALUE` pairs into `/opt/explorer/.env`
inside a marked block, leaving everything outside that block untouched. It is
a convenience for pushing one shared config to several hosts and is entirely
optional — a hand-written `.env` is equally valid.

**No bundle ships in this repository**, by design: an encrypted blob of live
credentials in a public tree is a credential leak waiting for a passphrase
guess. Create your own from `provision/clients/_template.env`, keep it in
private infrastructure, and see `provision/README.md`. With no `*.env.enc`
present, bootstrap silently skips this step.

## Service user and directory layout

| Path | Owner | What it is |
|---|---|---|
| `/opt/explorer-src` | root | Git checkout. `explorer update` fetches here. |
| `/opt/explorer` | `explorer:explorer` | The running install (rsynced from the checkout, minus `.git`). |
| `/opt/explorer/.venv` | `explorer:explorer` | Virtualenv built by `uv`. |
| `/opt/explorer/.venv.old` | `explorer:explorer` | Previous venv, kept for one successful update cycle as a rollback window. |
| `/opt/explorer/.env` | `explorer:explorer`, `0640` | Configuration and secrets. Never overwritten by an update. |
| `/opt/explorer/.tmp/email_attachments` | `explorer:explorer`, `0750` | Attachments in flight. The only writable path the unit grants. |
| `/etc/systemd/system/explorer*.{service,timer}` | root | Units, reinstalled on every update. |
| `/etc/tmpfiles.d/explorer.conf` | root | Creates the attachment dir on boot. |
| `/usr/local/bin/explorer` | root, `0755` | Operator CLI (`deploy/explorer-cli`). |
| `/etc/caddy/conf.d/explorer.caddy` | root | Site block, if Caddy was installed. |

The service runs as the unprivileged `explorer` user (`nologin` shell) under
a hardened unit (`deploy/systemd/explorer.service`): `NoNewPrivileges`,
`PrivateTmp`, `PrivateDevices`, `ProtectHome`, `ProtectSystem=full`,
`ProtectKernelModules`, `ProtectKernelTunables`, `ProtectControlGroups`,
`LockPersonality`, `UMask=027`, `RestrictAddressFamilies=AF_UNIX AF_INET
AF_INET6`, and `ReadWritePaths=/opt/explorer/.tmp` — so the process can write
exactly one directory.

Uvicorn binds **`127.0.0.1:8080`** with `--proxy-headers
--forwarded-allow-ips=127.0.0.1`. It is not reachable off-box without a
reverse proxy, which is intentional; see
[TLS and the reverse proxy](#tls-and-the-reverse-proxy).

## Environment variables

Written to `/opt/explorer/.env` (mode `0640`). Edit with `sudo explorer env
edit`, then `sudo explorer restart` — values are read once at import.
`sudo explorer env` prints the file with anything matching
`TOKEN|KEY|SECRET|PASSWORD` redacted.

`app/config.py` reads `/opt/explorer/.env.shared` first and then `.env` on
top of it, so a fleet-wide file plus per-host overrides works. Values already
in the process environment (a systemd `Environment=` line) beat `.env.shared`
but lose to `.env`.

### Authentication

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `AUTH_SIGNING_PUBKEY` | **yes** | *(empty)* | Base64-encoded 32-byte Ed25519 **public** key of the auth service. Explorer verifies the session cookie's signature with it. Any parse failure is treated as "no key", which means "everyone is logged out". Safe to store in plaintext config — a public key cannot mint sessions. |
| `AUTH_LOGIN_URL` | no | `https://auth.elcanotek.com` | Where unauthenticated browsers are redirected, as `<url>/?return_to=<escaped current url>`. Set it to your own auth service. Trailing slashes are stripped. |
| `AUTH_COOKIE_NAME` | no | `elcano_auth` | Cookie the auth service mints. Must match. |

### AWS and S3

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `EMAIL_S3_BUCKET` | **yes** | *(empty)* | Bucket holding SES-written MIME objects. Empty ⇒ every S3 call fails. |
| `EMAIL_S3_PREFIX` | no | `emails/` | Archive prefix. Also a security boundary: `is_allowed_s3_key` refuses any key not under it (or under the literal head of the date format). Keep the trailing slash. |
| `EMAIL_S3_DATE_PREFIX_FORMAT` | no | `emails/%Y/%m/%d/` | `strftime` pattern expanded to one prefix per day of the requested range. Must be a *key prefix* — normally starts with `EMAIL_S3_PREFIX` and ends with `/`. Empty string disables per-day scanning and lists the whole prefix on every search. |
| `EMAIL_S3_MAX_DATE_PREFIX_DAYS` | no | `62` | Widest span still expanded per day. Wider spans fall back to one LIST of the root prefix, and also cap what the UI accepts in one search. |
| `EMAIL_S3_MAX_BODY_SEARCH_DAYS` | no | `14` | Extra cap for a fuzzy search with **Body** ticked, which downloads whole objects instead of header ranges. |
| `EMAIL_HEADER_FETCH_BYTES` | no | `65536` | Bytes per ranged `GET` when reading headers for a result row. Raise only if messages in your archive carry unusually large header blocks (long `Received:` chains, big DKIM sets); every extra byte is paid on every row. A zero-byte object answers `InvalidRange` and is treated as headerless rather than failing the page. |
| `EMAIL_SEARCH_JOB_MAX_SECONDS` | no | `120` | A search job that exceeds this cancels itself server-side, so one wide query cannot pin a worker thread. |
| `AWS_REGION` | no | `us-east-2` | Region of the bucket. |
| `AWS_ACCESS_KEY_ID` | no | *(empty)* | Read-only access key. Leave **both** key variables blank to use the ambient chain (instance role, `~/.aws/credentials`, `AWS_PROFILE`) — preferred on EC2. |
| `AWS_SECRET_ACCESS_KEY` | no | *(empty)* | Secret for the above. |

### Session cookie

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `EXPLORER_SESSION_SECRET` | strongly recommended | `explorer-dev-session-secret` | Signs the Starlette session cookie holding a per-browser `search_owner_id`, which scopes search jobs and pagination cursors to the browser that started them. **Not** the auth boundary — but leaving it at the built-in default lets anyone forge that id and read another browser's in-flight results. Bootstrap generates one; to rotate: |

```bash
openssl rand -hex 32
sudo explorer env edit          # set EXPLORER_SESSION_SECRET
sudo explorer restart           # invalidates in-flight searches only
```

## AWS IAM policy

Explorer makes exactly two S3 calls: `ListObjectsV2` (to enumerate day
prefixes) and `GetObject` (ranged, for headers; whole, for a message or an
attachment). Nothing else. Grant nothing else:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListArchivePrefix",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::my-email-archive",
      "Condition": {
        "StringLike": { "s3:prefix": ["emails/*"] }
      }
    },
    {
      "Sid": "ReadArchiveObjects",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-email-archive/emails/*"
    }
  ]
}
```

Notes:

- Replace `my-email-archive` and `emails/` with your bucket and
  `EMAIL_S3_PREFIX`.
- The `s3:prefix` condition means a stolen key cannot list the rest of the
  bucket. Drop the condition only if you must list the bucket root.
- SSE-KMS bucket? Add `kms:Decrypt` on that key, or `GetObject` returns
  `AccessDenied`.
- Prefer an EC2 instance profile over a long-lived key. With no keys in
  `.env`, `boto3` picks the role up automatically.
- Do **not** grant `s3:PutObject` or `s3:DeleteObject`. Explorer never
  writes to S3, and a read-only key limits the damage if the box is lost.

## Attachment cleanup timer

Opening an attachment makes Explorer download that MIME part, write it to
`/opt/explorer/.tmp/email_attachments/`, and stream it to the browser. A
Starlette background task deletes the file right after the response
completes, and `prune_attachment_cache()` sweeps anything older than 10
minutes on startup and on each attachment request.

`explorer-attachment-cleanup.timer` is the third line of defence: every 15
minutes (`OnBootSec=5m`, `OnUnitActiveSec=15m`, `Persistent=true`) it deletes
files in that directory older than 60 minutes.

This exists because **the files are excerpts of private correspondence.** An
aborted download, a crashed worker or a killed process can leave one behind,
and a spreadsheet from someone's inbox sitting indefinitely on a server disk
is exactly the kind of quiet accumulation that turns one compromised host
into a data-breach notification. The timer bounds how long any fragment can
live. `explorer.tmpfiles.conf` sets the directory to `0750
explorer:explorer` with a 1-hour age policy so `systemd-tmpfiles` enforces
the same bound.

```bash
systemctl list-timers explorer-attachment-cleanup.timer
sudo systemctl start explorer-attachment-cleanup.service   # sweep now
sudo ls -la /opt/explorer/.tmp/email_attachments            # should be ~empty
```

If you handle regulated data, shorten `OnUnitActiveSec` and the `-mmin +60`
in `deploy/systemd/explorer-attachment-cleanup.service` to match your
retention rules.

## TLS and the reverse proxy

**Explorer must run on loopback behind a proxy.** Two reasons:

1. It speaks plain HTTP. Session cookies over plain HTTP on a routable
   interface is not acceptable for a mail archive.
2. The session cookie is issued by the auth service for the **parent
   domain** (e.g. `.example.com`) so several services can share one sign-in.
   The browser only sends it to a host under that domain, so Explorer has to
   be served from one — `https://explorer.example.com`, not an IP.

### Caddy (what bootstrap installs)

Answer the hostname prompt and bootstrap will `dnf install caddy`, render
`deploy/explorer.caddy` with your hostname into
`/etc/caddy/conf.d/explorer.caddy`, ensure `/etc/caddy/Caddyfile` contains
`import conf.d/*.caddy` (so several services can coexist on one box), add a
global `{ email ... }` block for Let's Encrypt if you supplied one, open
80/443 in `firewalld` when it is active, and reload Caddy.

The rendered site block reverse-proxies to `127.0.0.1:8080` and sets HSTS,
`X-Content-Type-Options`, `X-Frame-Options: DENY` and `Referrer-Policy`.
Certificates renew automatically about 30 days before expiry — no cron.

Bootstrap pre-checks DNS (comparing `dig +short <host> A` against the box's
public IP) and warns rather than aborting, so you can still choose
`tls internal` (a self-signed cert) on a host with no public reachability.

```bash
explorer tls status     # hostname, cert subject/issuer/dates, Caddy state
explorer tls reload     # graceful reload, validates before applying
explorer tls restart
```

### Your own proxy

Answer "no" to the Caddy prompt and point nginx, HAProxy, an ALB or anything
else at `127.0.0.1:8080`. Requirements: terminate TLS, serve from a hostname
under the auth cookie's domain, and forward `X-Forwarded-*` (the unit already
trusts `127.0.0.1`). nginx equivalent:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Attachments can be large; raise `proxy_read_timeout` and
`client_max_body_size` if you see truncated downloads.

## Managing the service

`/usr/local/bin/explorer` (source: `deploy/explorer-cli`) is a thin
dispatcher over `systemctl`, `journalctl` and the update scripts. Everything
it does is also doable by hand.

| Command | Equivalent |
|---|---|
| `explorer start` / `stop` / `restart` / `status` | `sudo systemctl <verb> explorer.service` |
| `explorer logs` | `sudo journalctl -fu explorer.service` |
| `explorer logs -n 200 --since '1 hour ago'` | extra args pass straight through to `journalctl` |
| `explorer update` | `sudo bash /opt/explorer-src/scripts/update.sh` |
| `explorer rebuild` | rebuild + restart the current checkout, no fetch |
| `explorer provision [--client=NAME]` | `sudo bash /opt/explorer-src/scripts/provision.sh` |
| `explorer env` | print `/opt/explorer/.env`, secrets redacted |
| `explorer env edit` | `$EDITOR /opt/explorer/.env` (creates it if missing) |
| `explorer tls status` / `reload` / `restart` | Caddy controls |
| `explorer --help` | full usage |

The cleanup timer is managed with plain systemd:
`systemctl status explorer-attachment-cleanup.timer`.

## Updating and rolling back

```bash
sudo explorer update                      # shows incoming commits, asks to confirm
sudo EXPLORER_UPDATE_YES=1 explorer update  # unattended
```

`scripts/update.sh` is a **staged** update — the live service keeps serving
on the old revision if the build fails:

1. `git fetch` in `/opt/explorer-src`, resolve the target branch (following
   the attached branch; recovering or defaulting to `origin/HEAD` if HEAD is
   detached), print the incoming commits, and confirm. Fast-forward only — a
   diverged branch aborts rather than merging. HEAD is never detached.
2. If this update changed `update.sh` itself, re-exec the new copy in
   rebuild-only mode, because the running shell still holds the old inode.
3. Verify `AUTH_SIGNING_PUBKEY` is set in `.env.shared` or `.env`, offering to
   paste it if not — without it the service comes back in a redirect loop
   that the health check below cannot detect.
4. Build a fresh venv in `/opt/explorer.staging.XXXXXX` (deliberately beside
   `/opt/explorer`, not in `/tmp`: a venv built under `/tmp` keeps its
   SELinux `tmp_t` label after `mv` and systemd refuses to exec it with
   `203/EXEC`). A failed `uv pip install` aborts here, untouched live install.
5. Stop the service, rsync the staged tree in (preserving `.env`, `.tmp`,
   `.git`), move the old `.venv` aside to `.venv.old`, move the new one into
   place, reinstall the units, CLI and motd, `restorecon`, `daemon-reload`,
   start.
6. Health check `http://127.0.0.1:8080/` for up to 10s. On success, delete
   `.venv.old`. On failure, print the rollback command and exit non-zero.

### Rollback

If the new revision starts but misbehaves, check out the previous commit and
rebuild **without** fetching (`explorer update` would fast-forward you
straight back to the tip):

```bash
cd /opt/explorer-src
git log --oneline -5
sudo git checkout -B rollback <previous-sha>
sudo explorer rebuild
```

If the venv itself is the problem and `.venv.old` still exists — it survives
until the next *successful* health check:

```bash
sudo systemctl stop explorer.service
sudo rm -rf /opt/explorer/.venv
sudo mv /opt/explorer/.venv.old /opt/explorer/.venv
sudo systemctl start explorer.service
```

`/opt/explorer/.env` is excluded from every rsync, so no update or rollback
can lose your configuration.

## Health checks

Explorer has no dedicated `/health` route: the app is stateless and `/` is
the cheapest honest probe. An **unauthenticated** `GET /` returns **303** to
the auth service, which proves the process is up, the templates render and
the auth gate is wired.

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/    # expect 303
curl -sI https://explorer.example.com/ | head -1                    # through the proxy
systemctl is-active explorer.service
```

Treat `200` or `303` as healthy (a browser with a valid cookie gets `200`).
`000`/connection refused means the process is down; `502` from the proxy
means the proxy is up but Explorer is not.

**A 303 does not prove sign-in works** — a missing `AUTH_SIGNING_PUBKEY`
produces exactly the same 303. To verify end to end, sign in with a browser.

## Troubleshooting

### Infinite redirect loop between Explorer and the login page

Sign-in bounces you to auth, auth bounces you back, forever. Almost always
`AUTH_SIGNING_PUBKEY` is missing or wrong, so Explorer treats a perfectly
good cookie as "logged out" and redirects again.

```bash
sudo explorer env | grep AUTH_        # SIGNING_PUBKEY shows as [REDACTED] if set at all
```

Check, in order:

- **Set at all?** If the line is absent, `verify_session` returns `None` for
  every request.
- **Right key?** It must be the public key of the service at
  `AUTH_LOGIN_URL`. A key from a different environment (staging vs
  production) verifies nothing.
- **Valid encoding?** Standard base64 of exactly 32 raw bytes. Anything else
  is silently discarded. Verify:
  ```bash
  echo -n '<pubkey>' | base64 -d | wc -c    # must print 32
  ```
- **Cookie name?** `AUTH_COOKIE_NAME` must match what auth mints
  (default `elcano_auth`).
- **Cookie domain?** The cookie is scoped to the parent domain. Reaching
  Explorer by IP or by a hostname outside that domain means the browser never
  sends it. Use the proper hostname.
- **Restarted?** Config is read at import. `sudo explorer restart`.

The public key is cached and re-parsed only when the environment value
changes, so a rotation needs a restart to be picked up from `.env`.

### `AccessDenied` / `NoSuchBucket` from S3

Symptom: searching shows an error banner, or `explorer logs` shows a
`botocore` `ClientError`.

```bash
sudo -u explorer /opt/explorer/.venv/bin/python - <<'PY'
import boto3
from app.config import settings
s3 = boto3.client("s3", region_name=settings.aws_region)
print(s3.list_objects_v2(Bucket=settings.email_s3_bucket,
                         Prefix=settings.email_s3_prefix,
                         MaxKeys=3))
PY
```

(Run it from `/opt/explorer`.) Then check:

- `AccessDenied` on **list** — the policy lacks `s3:ListBucket` on the
  *bucket* ARN, or your `s3:prefix` condition does not cover
  `EMAIL_S3_PREFIX`.
- `AccessDenied` on **get** — `s3:GetObject` is missing on the *object* ARN
  (`arn:aws:s3:::bucket/emails/*`), or the bucket is SSE-KMS encrypted and
  the key policy denies `kms:Decrypt`.
- `NoSuchBucket` / `PermanentRedirect` — wrong `AWS_REGION` for the bucket.
- `InvalidAccessKeyId` / `SignatureDoesNotMatch` — stale key, or a partly
  pasted secret. Rotate and re-enter.
- Nothing in `.env` and no instance role — `boto3` finds no credentials and
  fails on the first call.

### Search returns zero results but the archive is not empty

Nearly always the date-prefix pattern. Explorer lists
`EMAIL_S3_DATE_PREFIX_FORMAT` expanded per day; if that does not match your
real layout, it lists prefixes that do not exist and finds nothing — with no
error, because "no objects under this prefix" is a perfectly valid answer.

Compare a real key with a rendered prefix:

```bash
aws s3 ls s3://my-email-archive/emails/ --recursive | head -3
python3 -c "import datetime; print(datetime.date.today().strftime('emails/%Y/%m/%d/'))"
```

Things that bite:

- Layout is `emails/2026-08-27/` but the format says `emails/%Y/%m/%d/`.
- No date partitioning at all — set `EMAIL_S3_DATE_PREFIX_FORMAT=""`.
- Missing trailing `/`, so the prefix matches nothing.
- The format does not start with `EMAIL_S3_PREFIX`, so keys that *are* found
  get rejected by the prefix confinement check when you click them.
- SES writes objects at the bucket root with `EMAIL_S3_PREFIX="emails/"`
  configured.
- The range is wider than `EMAIL_S3_MAX_DATE_PREFIX_DAYS`, silently falling
  back to a root LIST — which may be slow but should still return results.

Remember the second filter: objects also have to fall inside the requested
window by **`LastModified`**. If the archive was bulk-copied into S3, every
object's `LastModified` is the copy date, so searching by original mail date
finds nothing. Search the copy date, or re-derive your partitioning.

### Clock skew

Session tokens carry `exp`, compared against the server's clock. A box that
has drifted fast rejects valid cookies as expired (redirect loop); drifted
slow, it honours cookies past their expiry.

```bash
timedatectl status              # want: "System clock synchronized: yes"
sudo systemctl enable --now chronyd
chronyc tracking
```

Skew also skews dates: `date.today()` picks the default day for a search, and
day prefixes are computed in **UTC**. A box on a non-UTC timezone with a
correct clock is fine; a box with a wrong *date* searches the wrong partition.

### Service will not start

```bash
sudo explorer status
sudo explorer logs -n 100
```

- `203/EXEC` — the venv or interpreter is not executable by the unit,
  typically an SELinux label from building under `/tmp`. Re-run
  `sudo explorer rebuild` (it stages beside `/opt/explorer` and runs
  `restorecon`).
- `ModuleNotFoundError` on boot — the venv is incomplete; `sudo explorer
  rebuild`.
- `Address already in use` — something else holds 8080:
  `sudo ss -ltnp | grep 8080`.
- Permission errors writing attachments — `ReadWritePaths` grants only
  `/opt/explorer/.tmp`; restore ownership with
  `sudo chown -R explorer:explorer /opt/explorer/.tmp` and
  `sudo systemd-tmpfiles --create /etc/tmpfiles.d/explorer.conf`.

### Searches time out or feel slow

Wide ranges mean many LISTs plus one ranged GET per candidate object.

- Narrow the range, or raise `EMAIL_SEARCH_JOB_MAX_SECONDS` if 120s truly is
  not enough.
- Untick **Body** in fuzzy search — body matching downloads whole objects.
- Deploy in the **same region** as the bucket. Cross-region round-trips
  dominate at thousands of objects.
- Check `EMAIL_HEADER_FETCH_BYTES` has not been raised far above 64 KB; it is
  paid per result row.

### "This search session expired"

Search jobs and pagination cursors are held in memory, keyed to a
`search_owner_id` in the signed session cookie, and expire after 15 minutes.
A restart, or changing `EXPLORER_SESSION_SECRET`, invalidates them. Run the
search again. Note that these caches are per process — do not run Explorer
with multiple uvicorn workers, or a poll can land on a worker that has never
heard of the job.

## Manual install (without bootstrap.sh)

On a non-dnf distribution, reproduce what bootstrap does:

```bash
sudo useradd --system --home-dir /opt/explorer --shell /usr/sbin/nologin explorer
sudo git clone https://github.com/ElcanoTek/explorer.git /opt/explorer-src
sudo rsync -a --exclude='/.git' /opt/explorer-src/ /opt/explorer/
sudo mkdir -p /opt/explorer/.tmp/email_attachments
sudo chown -R explorer:explorer /opt/explorer

sudo -u explorer python3 -m venv /opt/explorer/.venv
sudo -u explorer /opt/explorer/.venv/bin/pip install -r /opt/explorer/requirements.txt

sudo install -o explorer -g explorer -m 0640 /dev/null /opt/explorer/.env
sudo "$EDITOR" /opt/explorer/.env          # see .env.example

sudo install -m 0644 /opt/explorer/deploy/systemd/explorer.service /etc/systemd/system/
sudo install -m 0644 /opt/explorer/deploy/systemd/explorer-attachment-cleanup.service /etc/systemd/system/
sudo install -m 0644 /opt/explorer/deploy/systemd/explorer-attachment-cleanup.timer /etc/systemd/system/
sudo install -m 0644 /opt/explorer/deploy/systemd/explorer.tmpfiles.conf /etc/tmpfiles.d/explorer.conf
sudo install -m 0755 /opt/explorer/deploy/explorer-cli /usr/local/bin/explorer
sudo systemd-tmpfiles --create /etc/tmpfiles.d/explorer.conf
sudo systemctl daemon-reload
sudo systemctl enable --now explorer.service explorer-attachment-cleanup.timer
```

Then front it with a TLS-terminating proxy as above. Note that
`explorer-attachment-cleanup.service` calls `/usr/bin/bash` and
`/usr/bin/find`; on Debian-family systems these live at `/bin/bash` and
`/usr/bin/find`, so adjust `ExecStart`. `scripts/update.sh` assumes `uv`,
`rsync` and `runuser`; on other distributions rebuild the venv by hand and
restart.
