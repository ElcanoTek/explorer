# Deploying Explorer

The authoritative deployment guide. Every path and command below is taken
from the scripts and unit files in this repository (`scripts/`, `deploy/`) —
if you change those, change this document too.

Explorer is one Go binary, `/opt/explorer/bin/explorer`, run as a single
process. The email archive remains in S3. Elcano deployments keep only
in-memory caches (attachments are streamed from memory and never written to
disk); central-auth deployments additionally keep a small SQLite
access/session database under `/var/lib/explorer`. There is no queue or cache
server.

- [Prerequisites](#prerequisites)
- [Install](#install)
- [Service user and directory layout](#service-user-and-directory-layout)
- [Environment variables](#environment-variables)
- [Explorer access database and backups](#explorer-access-database-and-backups)
- [AWS IAM policy](#aws-iam-policy)
- [Attachments](#attachments)
- [TLS and the reverse proxy](#tls-and-the-reverse-proxy)
- [Managing the service](#managing-the-service)
- [Updating and rolling back](#updating-and-rolling-back)
- [Health checks](#health-checks)
- [Troubleshooting](#troubleshooting)
- [Upgrading from the Python release](#upgrading-from-the-python-release)
- [Manual install](#manual-install-without-bootstrapsh)

## Prerequisites

**Supported OS.** `scripts/bootstrap.sh` installs packages with `dnf` and is
written for **Fedora 39+, RHEL 9+, AlmaLinux/Rocky 9+**. It also assumes
`systemd`, and handles SELinux (it stages builds next to `/opt/explorer`
rather than in `/tmp`, and runs `restorecon` after swapping files in). It
will not run on Debian/Ubuntu without translating the package step; see
[Manual install](#manual-install-without-bootstrapsh).

**Packages** (installed for you by bootstrap): `git` and `golang`. The box
builds Explorer from its own verified checkout. Fedora's `golang` is usually
older than the release `go.mod` pins; the build sets `GOTOOLCHAIN=auto`, so
Go downloads the pinned toolchain (checksum-verified against the Go
checksum database) into Explorer's root-owned build cache.

**You also need:**

- Root (the installer creates a system user and writes to `/etc/systemd/system`).
- An S3 bucket holding SES-delivered MIME objects, and read-only credentials
  for it — see [AWS IAM policy](#aws-iam-policy).
- An authentication choice: Elcano's base64 Ed25519 magic-link public key, or
  a registered client ID/secret from the new central auth service.
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
missing. On a re-run it updates only the settings it manages, in place
(`internal/dotenv`, the same parser the service uses), and keeps every
other line exactly as it was: AWS keys added with `explorer env edit`, tuning
knobs, custom keys and the `explorer provision` block. In order it:

1. Installs the dnf packages above. Then, when `cockpit-ws` is installed, it
   removes Cockpit with `dnf -y remove 'cockpit*'`: the Vultr Fedora image
   ships Cockpit's root-capable web login on :9090, and Explorer hosts are
   administered over ssh only. `EXPLORER_KEEP_COCKPIT=1` keeps it; a failed
   removal only warns.
   It also makes SSH key-only: Vultr's cloud-init writes
   `/etc/ssh/sshd_config.d/50-cloud-init.conf` with `PasswordAuthentication
   yes`, so bootstrap installs `/etc/ssh/sshd_config.d/01-no-password-login.conf`
   (`PasswordAuthentication no`, `KbdInteractiveAuthentication no`,
   `PermitRootLogin prohibit-password`; it sorts first and sshd keeps the first
   value it reads), checks it with `sshd -t` and reloads sshd. It skips with a
   warning when no authorized key is installed for root or a `/home` user (so
   nobody is locked out), removes the file again if `sshd -t` rejects it, and
   warns when an earlier directive in `sshd_config` still allows passwords.
   `EXPLORER_KEEP_SSH_PASSWORDS=1` skips the step; it never fails the install,
   and `explorer update` never touches sshd. `explorer doctor` warns (as root)
   when `sshd -T` still reports `passwordauthentication yes` or
   `permitrootlogin yes`.
2. Creates the `explorer` system user and `/opt/explorer`.
3. Seeds `/opt/explorer-src` (with `.git`, so updates can `git fetch`).
4. Builds the binary from that checkout (`scripts/bootstrap.sh` does this
   before handing over to `explorer bootstrap`) and installs it as
   `/opt/explorer/bin/explorer`, with the commit it was built from recorded
   in `/opt/explorer/.explorer-revision`. Anything else in `/opt/explorer`
   that is not the env files (a Python-era install's source copy and
   `.venv`, an env backup, your own files, other files in `bin/`) is moved
   to `/opt/explorer-preserved/<time>/`, never deleted. Remove that folder
   yourself once you have looked at it.
5. Prompts for an authentication mode and its required values, a TLS hostname,
   `EMAIL_S3_BUCKET`, and `AWS_REGION`; generates
   `EXPLORER_SESSION_SECRET`; writes `/opt/explorer/.env` mode `0600`, owned
   by `explorer`.
6. Installs the systemd unit, the tmpfiles rule and `/usr/local/bin/explorer`
   (a copy of the binary), all from the files compiled into it.
7. Enables and starts `explorer.service`, then health checks
   `http://127.0.0.1:8080/health`.
8. Optionally installs Caddy with Let's Encrypt or `tls internal`.
9. Installs `deploy/motd` to `/etc/motd`.

Given a public hostname, bootstrap also names the box after it, so prompts stop
reading `root@vultr`. It renames only when the current static hostname is an
unset cloud-image default (`vultr.guest`, `localhost`, `localhost.localdomain`);
any other name, short ones included, is left alone and bootstrap prints the
`hostnamectl set-hostname <fqdn>` to run. `EXPLORER_SET_HOSTNAME=1` forces the
rename, `EXPLORER_SET_HOSTNAME=0` skips the step. A rename runs `hostnamectl
set-hostname`, writes `/etc/cloud/cloud.cfg.d/99-preserve-hostname.cfg`
(`preserve_hostname: true`, `manage_etc_hosts: false`) when `/etc/cloud`
exists, and replaces the old hostname on the `127.0.0.1`/`::1` lines in `/etc/hosts`
with `<fqdn> <short>`, keeping every other alias on the line (localhost names
are never replaced). When no line names the FQDN, it appends both loopback lines. It is idempotent, never
fails the install, and `explorer update` never renames a box
(`internal/ops/hostsetup.go`).

**AWS keys are deliberately not prompted for.** Bootstrap leaves
`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` commented out in the generated
`.env`. Add them with `sudo explorer env edit`, or skip them entirely and
attach an instance role — the AWS SDK falls back to the ambient credential
chain when both are blank.

### Scripted installs

Set `EXPLORER_BOOTSTRAP_NON_INTERACTIVE=1` plus the values you want; any
prompt with no value and no default aborts the run.

```bash
sudo EXPLORER_BOOTSTRAP_NON_INTERACTIVE=1 \
     EXPLORER_AUTH_MODE='elcano' \
     AUTH_SIGNING_PUBKEY='...' \
     EMAIL_S3_BUCKET='my-email-archive' \
     AWS_REGION='us-east-1' \
     EXPLORER_BOOTSTRAP_HOSTNAME='explorer.example.com' \
     EXPLORER_BOOTSTRAP_SETUP_CADDY=Y \
     EXPLORER_BOOTSTRAP_USE_LETSENCRYPT=Y \
     EXPLORER_BOOTSTRAP_LE_EMAIL='ops@example.com' \
     bash /opt/explorer-src/scripts/bootstrap.sh
```

For a client deployment, use `EXPLORER_AUTH_MODE='central'` and also provide
`AUTH_ISSUER_URL`, `EXPLORER_PUBLIC_URL`, `AUTH_CLIENT_ID`, and the registered
`AUTH_CLIENT_SECRET`. After bootstrap, grant the first user access with
`sudo explorer access grant user@example.com`.

Leave `EXPLORER_BOOTSTRAP_HOSTNAME` empty to skip the proxy entirely and
front Explorer with your own.
Set `EXPLORER_SET_HOSTNAME=0` to keep bootstrap from renaming the box, or `1`
to rename it to `EXPLORER_BOOTSTRAP_HOSTNAME` whatever its current name.

### Optional: encrypted config bundles

`sudo explorer provision` decrypts `provision/clients/<name>.env.enc` (the
format `openssl enc -aes-256-cbc -pbkdf2 -iter 600000` writes; Explorer
decrypts it natively) and merges the `KEY=VALUE` pairs into `/opt/explorer/.env`
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
| `/opt/explorer-src` | `root:root`, not group/other-writable | Trusted Git checkout. `explorer update` fetches here. Root refuses symlinks or non-root-owned content before building from it. |
| `/opt/explorer` | `root:root`, `0755` | Application directory. Holds only the binary, the revision marker and the dotenv files. |
| `/opt/explorer/bin/explorer` | `root:root`, `0755` | The service binary. Templates, static assets, the systemd unit, the Caddy template and the motd are compiled into it. |
| `/opt/explorer/.explorer-revision` | `root:root`, `0644` | Commit the installed binary was built from; prevents a rolled-back install being mistaken for current. |
| `/opt/explorer/.env` | `explorer:explorer`, `0600` | Configuration and secrets. Never overwritten by an update. |
| `/var/cache/explorer-build` | `root:root`, `0700` | Go module, build and toolchain cache used by `bootstrap`/`update`. |
| `/var/lib/explorer/access.db` | `explorer:explorer`, `0600` | Central-mode email access list and app-scoped session hashes. Contains no passwords. |
| `/etc/systemd/system/explorer.service` | root | Unit, reinstalled on every update. |
| `/etc/tmpfiles.d/explorer.conf` | root | Creates `/var/lib/explorer` on boot. |
| `/usr/local/bin/explorer` | root, `0755` | Operator CLI: a copy of the same binary. |
| Caddy's imported snippet directory | root | Explorer site block, if Caddy was installed (for example, Fedora uses `/etc/caddy/Caddyfile.d/explorer.caddyfile`). |

The service runs as the unprivileged `explorer` user (`nologin` shell) under
a hardened unit (`deploy/systemd/explorer.service`): `NoNewPrivileges`, an
empty capability bounding set, `PrivateTmp`, `PrivateDevices`,
`ProtectSystem=strict`, `ProtectHome`, `ProtectKernel*`, `ProtectClock`,
`ProtectHostname`, `ProtectProc=invisible`, `RestrictNamespaces`,
`RestrictSUIDSGID`, `MemoryDenyWriteExecute`, `LockPersonality`,
`SystemCallArchitectures=native`, `UMask=027` and
`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`. The only writable path
is its `StateDirectory`, `/var/lib/explorer`: the process cannot write its
own binary, its configuration, or anywhere else on disk.

`explorer serve` binds **`127.0.0.1:8080`** (`EXPLORER_LISTEN_ADDR`). It
trusts `X-Forwarded-Proto` only from a loopback peer (the local proxy). It is
not reachable off-box without a reverse proxy, which is intentional; see
[TLS and the reverse proxy](#tls-and-the-reverse-proxy).

## Environment variables

Written to `/opt/explorer/.env` (mode `0600`). Edit with `sudo explorer env
edit`, then `sudo explorer restart` — values are read once at startup.
`sudo explorer env` prints the file with anything matching
`TOKEN|KEY|SECRET|PASSWORD` redacted.

`explorer serve` reads `/opt/explorer/.env.shared` first and then `.env` on
top of it, so a fleet-wide file plus per-host overrides works. Values already
in the process environment (a systemd `Environment=` line) beat `.env.shared`
but lose to `.env`. The merged values are exported to the process, so AWS SDK
settings such as `AWS_PROFILE` or `AWS_ENDPOINT_URL_S3` work from `.env` too.

### Authentication

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `EXPLORER_AUTH_MODE` | no | `elcano` | Selects exactly one provider. `elcano` preserves Elcano's external magic-link cookie; `central` delegates login to the new auth service. Any other value fails startup. |
| `AUTH_SIGNING_PUBKEY` | yes | *(empty)* | Base64-encoded 32-byte Ed25519 **public** key of the auth service. Elcano mode verifies the session cookie's signature with it (a parse failure means "everyone is logged out"). Central mode verifies the sign-in `id_token` and signed back-channel tokens with it (plus keys Auth publishes at `/jwks.json`) and refuses to start without a valid key. Safe to store in plaintext config — a public key cannot mint sessions. |
| `AUTH_LOGIN_URL` | no | `https://auth.elcanotek.com` | Where unauthenticated browsers are redirected, as `<url>/?return_to=<escaped current url>`. Set it to your own auth service. Trailing slashes are stripped. |
| `AUTH_COOKIE_NAME` | no | `elcano_auth` | Cookie the auth service mints. Must match. |
| `AUTH_ISSUER_URL` | central mode | *(empty)* | HTTPS origin of the client's central auth service, without a path or query. |
| `EXPLORER_PUBLIC_URL` | central mode | *(empty)* | Explorer's public HTTPS origin. The callback is exactly `<origin>/auth/callback`. |
| `AUTH_CLIENT_ID` | central mode | `explorer` | Client identifier registered at the auth service. |
| `AUTH_CLIENT_SECRET` | central mode | *(empty)* | Unique per-deployment client secret, at least 32 bytes. |
| `AUTH_HTTP_TIMEOUT_SECONDS` | no | `10` | Backchannel code-exchange timeout; must be greater than 0 and no more than 60 seconds. |
| `AUTH_SIGNING_PREVIOUS_PUBKEYS` | no | *(empty)* | Comma-separated prior Ed25519 public keys. Rarely needed now: in central mode Explorer also reads Auth's published `/jwks.json` (cached 10 minutes, refreshed once when a token names an unknown key), so an Auth key rotation needs no env edit here. |
| `EXPLORER_ACCESS_DB` | central mode | `/var/lib/explorer/access.db` | SQLite email access list and Explorer session hashes. Keep it outside the application tree and mode `0600`. |
| `EXPLORER_AUTH_COOKIE_SECURE` | central mode | `1` | Controls `Secure` on `__Host-explorer_session`. Central mode refuses an insecure setting in production. |
| `EXPLORER_SESSION_IDLE_SECONDS` | no | `43200` | Explorer app-session idle lifetime. Activity refreshes this deadline but never extends the absolute deadline. |
| `EXPLORER_SESSION_ABSOLUTE_SECONDS` | no | `86400` | Explorer app-session absolute lifetime. |

Central mode owns no passwords. Auth is the normal source of application
membership: granting or revoking Explorer in Auth asynchronously updates this
local authorization list. The CLI remains available for recovery and manual
deployments:

```bash
sudo explorer access grant user@example.com
sudo explorer access list
sudo explorer access revoke user@example.com
```

Granting access creates no credential; the user signs in with the central auth
service. Revoking access immediately invalidates all Explorer sessions for
that email.

#### Central auth service contract

Explorer expects an OAuth-style authorization-code handoff with exact
redirect-URI matching, state, nonce, and S256 PKCE:

1. `GET <AUTH_ISSUER_URL>/authorize` receives `response_type=code`,
   `client_id`, `redirect_uri`, `scope=email`, `state`, `nonce`,
   `code_challenge`, and `code_challenge_method=S256`.
2. After central authentication, auth redirects to the registered Explorer
   callback with `code` and the unchanged `state`. The code must be random,
   single-use, short-lived, and bound to the client ID, exact callback,
   central account/session, nonce, and PKCE challenge.
3. Explorer sends `POST <AUTH_ISSUER_URL>/token` as
   `application/x-www-form-urlencoded` with `grant_type=authorization_code`,
   `code`, `client_id`, exact `redirect_uri`, and `code_verifier`. It
   authenticates with HTTP Basic using the client ID and secret.
4. A successful exchange returns JSON with an `id_token`: an EdDSA-signed
   JWT (`typ` `JWT`, a `kid` naming one of Auth's keys) whose claims carry
   `sub`, `email`, `nonce`, the exact issuer and audience, and a live
   `iat`/`exp`. Explorer takes identity only from that signed token, requires
   the nonce to match, then applies its local allowlist and issues an app
   session. A `400` means the code was rejected (the user retries); any other
   failure is reported as an outage. Errors must not return identity data.

Auth also delivers signed, durable application-access and back-channel logout
events to the same endpoint. Register this deployment's exact endpoint after
creating the application:

```bash
auth app set-backchannel explorer \
  https://explorer.example.com/auth/backchannel-logout
```

Explorer validates each token's Ed25519 signature, issuer, audience, event
type, subject, and replay/version data. A newer access grant enables the email;
a newer revoke disables it and ends its Explorer sessions. Per-subject versions
make delayed and replayed deliveries harmless, and Auth retains the latest
desired state until Explorer acknowledges it, so an outage converges after
recovery. Logout delivery remains idempotent and subject-scoped.
Account disablement, password replacement, and an explicit central
sign-out-everywhere take effect without waiting for Explorer's idle timeout.
Explorer's own logout is that sign-out-everywhere: it revokes the local
session, clears the cookie, and redirects to
`<AUTH_ISSUER_URL>/logout?client_id=<AUTH_CLIENT_ID>`, where Auth ends every
central session of the account and fans the logout out to every application.
The browser lands on Auth's login page.

#### Replacing the removed local-password mode

An existing `EXPLORER_AUTH_MODE=local` configuration now fails closed at
startup; it is never silently converted. Create the matching user in the
central auth service, register Explorer's client and exact callback, replace
the auth variables in `/opt/explorer/.env`, and grant the same email locally:

```bash
sudo explorer env edit
# EXPLORER_AUTH_MODE="central"
# AUTH_ISSUER_URL="https://auth.client.example"
# EXPLORER_PUBLIC_URL="https://explorer.client.example"
# AUTH_CLIENT_ID="explorer"
# AUTH_CLIENT_SECRET="<registered per-deployment secret>"
# EXPLORER_ACCESS_DB="/var/lib/explorer/access.db"
sudo explorer restart
sudo explorer access grant user@example.com
```

The old `/var/lib/explorer/auth.db` is not read or migrated because central
auth—not Explorer—now owns credentials. Keep that file only until the new flow
has been verified and your retention policy allows its secure disposal.

### AWS and S3

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `EMAIL_S3_BUCKET` | **yes** | *(empty)* | Bucket holding SES-written MIME objects. Empty ⇒ the service starts, but every search shows "EMAIL_S3_BUCKET is not set". |
| `EMAIL_S3_PREFIX` | no | `emails/` | Archive prefix. Also a security boundary: `is_allowed_s3_key` refuses any key not under it (or under the literal head of the date format). Keep the trailing slash. |
| `EMAIL_S3_DATE_PREFIX_FORMAT` | no | `emails/%Y/%m/%d/` | `strftime` pattern expanded to one prefix per day of the requested range. Must be a *key prefix* — normally starts with `EMAIL_S3_PREFIX` and ends with `/`. Empty string disables per-day scanning and lists the whole prefix on every search. |
| `EMAIL_S3_MAX_DATE_PREFIX_DAYS` | no | `62` | Widest span still expanded per day. Wider spans fall back to one LIST of the root prefix, and also cap what the UI accepts in one search. |
| `EMAIL_S3_MAX_BODY_SEARCH_DAYS` | no | `14` | Extra cap for a fuzzy search with **Body** ticked, which downloads whole objects instead of header ranges. |
| `EMAIL_HEADER_FETCH_BYTES` | no | `65536` | Bytes per ranged `GET` when reading headers for a result row. Raise only if messages in your archive carry unusually large header blocks (long `Received:` chains, big DKIM sets); every extra byte is paid on every row. A zero-byte object answers `InvalidRange` and is treated as headerless rather than failing the page. |
| `EMAIL_SEARCH_JOB_MAX_SECONDS` | no | `120` | A search job that exceeds this cancels itself server-side (in-flight S3 calls included), so one wide query cannot run on unbounded. |
| `EMAIL_S3_FORCE_PATH_STYLE` | no | `0` | Path-style bucket addressing, for S3-compatible stores (MinIO, LocalStack) reached through `AWS_ENDPOINT_URL_S3`. |
| `AWS_REGION` | no | `us-east-2` | Region of the bucket. |
| `AWS_ACCESS_KEY_ID` | no | *(empty)* | Read-only access key. Leave **both** key variables blank to use the ambient chain (instance role, `~/.aws/credentials`, `AWS_PROFILE`) — preferred on EC2. |
| `AWS_SECRET_ACCESS_KEY` | no | *(empty)* | Secret for the above. |

### Agent API and MCP (`/mcp`, `/api/v1/`)

Fleet's agents search the archive through `POST /mcp` with a bearer token from
`sudo explorer token create --label fleet-<deployment>` (shown once; set
`EXPLORER_MCP_URL=https://<host>/mcp` and `EXPLORER_API_TOKEN` in Fleet's
`.env`). Caddy needs no change: these are ordinary routes on the same origin.
The contract, the tools and their failure behaviour are in
[API.md](API.md). These settings apply to the API only; the web UI ignores
them.

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `EMAIL_SENDER_AUTH` | no | `required` | Return only mail whose From domain the receiver authenticated (DMARC, or aligned SPF/DKIM). `off` restores the forgeable header-text sender match; every result then carries a warning. |
| `EMAIL_AUTHSERV_ID` | no | `amazonses.com` | The receiver's authserv-id; only the topmost `Authentication-Results` carrying it is read. |
| `EMAIL_S3_ARCHIVE_PREFIX` | no | `emails/attachments/` | The link archiver's cached payloads and manifests (production-support `ses-s3`). Never returned as mail; `get_download_link` serves cached copies from it. |
| `EXPLORER_API_TOKEN_DB` | no | `/var/lib/explorer/api_tokens.db` | Token database (hashes only), private to the service user. Back it up with the access database. |
| `EXPLORER_API_MAX_SECONDS` | no | `240` | One API/MCP call is stopped after this (below the server's 5-minute write timeout). |

### Session and CSRF cookie

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `EXPLORER_SESSION_SECRET` | central: **required**; Elcano: strongly recommended | `explorer-dev-session-secret` | Signs central login state/PKCE data and the `explorer_ui` cookie holding a per-browser `search_owner_id`. Central mode refuses the placeholder. Bootstrap generates one; to rotate: |
| `EXPLORER_UI_COOKIE_SECURE` | no | `1` | Adds `Secure` to `explorer_ui`. Keep enabled behind production HTTPS. |

```bash
openssl rand -hex 32
sudo explorer env edit          # set EXPLORER_SESSION_SECRET
sudo explorer restart           # invalidates login state and in-flight searches
```

## Explorer access database and backups

The central-mode database contains the service-specific email access list and
SHA-256 hashes of Explorer session identifiers. It contains no password hashes
and no central auth cookie, but its identity data is still sensitive. Vultr
instance backups are useful disaster recovery; keep a separate, regularly
tested database backup as well.

`explorer access backup` makes a transactionally consistent copy (SQLite's
`VACUUM INTO`) while Explorer is running, owner-only:

```bash
sudo install -d -m 0700 -o explorer -g explorer /var/backups/explorer
sudo explorer access backup          # prints /var/backups/explorer/access-<UTC time>.db
sudo explorer access backup /var/backups/explorer/before-migration.db
```

Copy that file to access-controlled storage outside the VM and test restoration
periodically. Restoring an old database can otherwise resurrect a session that
was valid at backup time: stop Explorer, replace `access.db`, delete every row
from `sessions`, verify `PRAGMA integrity_check`, restore owner/mode, and only
then start the service.

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
  `.env`, the AWS SDK picks the role up automatically.
- Do **not** grant `s3:PutObject` or `s3:DeleteObject`. Explorer never
  writes to S3, and a read-only key limits the damage if the box is lost.

## Attachments

Opening an attachment makes Explorer read the message, extract that MIME part
in memory and stream it to the browser. **Nothing is written to disk**, so
there is no scratch directory to sweep and no cleanup timer: an excerpt of
private correspondence cannot be left behind by an aborted download or a
crashed process.

Attachment responses carry `Content-Disposition: attachment`,
`Content-Security-Policy: default-src 'none'; sandbox`,
`X-Content-Type-Options: nosniff` and `Cache-Control: private, no-store`.
Images (so `cid:` inline images render), plain text, CSV and PDF keep their
type; anything a browser would execute (HTML, SVG, XML, JavaScript) is sent
as `application/octet-stream`.

Boxes upgraded from the Python release had an
`explorer-attachment-cleanup.timer`; `explorer update` disables and removes
it, and `explorer doctor` warns if it is still installed.

## TLS and the reverse proxy

**Explorer must run on loopback behind a proxy.** Two reasons:

1. It speaks plain HTTP. Session cookies over plain HTTP on a routable
   interface is not acceptable for a mail archive.
2. Authentication is origin-sensitive. Elcano mode receives its shared cookie
   only below the configured parent domain. Central mode uses a host-only
   Explorer cookie and an exact registered HTTPS callback. In either mode,
   serve Explorer as `https://explorer.example.com`, not by IP.

### Caddy (what bootstrap installs)

Answer the hostname prompt and bootstrap will `dnf install caddy`, render
`deploy/explorer.caddy` with your hostname into a directory already imported
by `/etc/caddy/Caddyfile` (or add `import conf.d/*.caddy` when none exists), add a
global `{ email ... }` block for Let's Encrypt if you supplied one, open
80/443 in `firewalld` when it is active, and reload Caddy.

The rendered site block reverse-proxies to `127.0.0.1:8080` and sets HSTS,
`X-Content-Type-Options`, `X-Frame-Options: DENY` and `Referrer-Policy`.
Certificates renew automatically about 30 days before expiry — no cron.

Bootstrap pre-checks DNS (comparing the host's A record against the box's
public IP) and warns rather than aborting, so you can still choose
`tls internal` (a self-signed cert) on a host with no public reachability.

```bash
explorer tls status     # hostname, cert subject/issuer/dates, Caddy state
explorer tls reload     # graceful reload, validates before applying
explorer tls restart
```

### Your own proxy

Caddy is the default on single-box installs (`explorer bootstrap`), or you can
answer "no" to the Caddy prompt and point your own reverse proxy (or a
same-pod sidecar proxy in Kubernetes) at `127.0.0.1:8080`. Requirements:
terminate TLS, use the hostname in `EXPLORER_PUBLIC_URL` (and, in Elcano mode,
one under the auth cookie's domain), and forward `Host` and
`X-Forwarded-Proto` from a loopback peer (Explorer believes `X-Forwarded-Proto`
only from loopback). Attachments can be large; raise your proxy's read timeout
and max body size if you see truncated downloads.

## Managing the service

`/usr/local/bin/explorer` is the same binary as the service, so the operator
CLI and the server always agree on paths and configuration. Verbs that need
root re-run themselves through `sudo`. Everything it does is also doable by
hand.

| Command | Equivalent |
|---|---|
| `explorer start` / `stop` / `restart` / `status` | `sudo systemctl <verb> explorer.service` |
| `explorer logs` | `sudo journalctl -fu explorer.service` |
| `explorer logs -n 200 --since '1 hour ago'` | extra args pass straight through to `journalctl` |
| `explorer update` | fetch, build, staged swap, health check, automatic rollback |
| `explorer rebuild` | the same for the current checkout, no fetch |
| `explorer doctor [--json] [--strict]` | read-only diagnostics; exits 1 when a check fails (`--strict`: or warns). `--check` is accepted and means the same |
| `explorer bootstrap` | re-run the installer (safe; keeps every setting it does not manage) |
| `explorer provision [--client=NAME]` | merge an encrypted config bundle into `.env` |
| `explorer env` | print `/opt/explorer/.env`, secrets redacted |
| `explorer env edit` | `$EDITOR /opt/explorer/.env` (creates it if missing) |
| `explorer access grant\|list\|revoke\|backup` | manage the central-mode email access list |
| `explorer tls status` / `reload` / `restart` | Caddy controls |
| `explorer version` | the commit the binary was built from |
| `explorer --help` | full usage |

## Updating and rolling back

```bash
sudo explorer update                        # shows incoming commits, asks to confirm
sudo explorer update --yes                  # unattended
echo y | sudo explorer update               # also works over a non-interactive ssh
sudo EXPLORER_UPDATE_YES=1 explorer update
```

The update is **staged and automatically rolled back**. It first verifies
that `/opt/explorer-src`, all of its ancestors and every file inside it are
root-owned, not group/other-writable and symlink-free, and takes
`/run/lock/explorer-update.lock` so two updates cannot interleave. Do not run
bootstrap, update or provision from a checkout writable by the service
account.

1. `git fetch` in `/opt/explorer-src`, resolve the target branch (following
   the attached branch or defaulting to `origin/HEAD` if HEAD is detached),
   print the incoming commits, and confirm. Fast-forward only — a diverged
   branch aborts rather than merging. HEAD is never detached.
2. Parse `.env.shared` and `.env` as data (never shell source) and check that
   `AUTH_SIGNING_PUBKEY` is present; on a terminal it offers to add it.
3. Build the new binary from the verified checkout into
   `/opt/.explorer-build.XXXXXX` — beside `/opt/explorer`, not in `/tmp`, so
   no `tmp_t` SELinux label follows it — with a clean environment
   (`CGO_ENABLED=0`, `-trimpath`, `-mod=readonly`, root-owned caches, the
   commit stamped in). A failed build aborts here; the live install is
   untouched.
4. Hand over to the **new** binary's apply step, so a release's own update
   logic always performs its swap. It snapshots the installed binary, unit,
   tmpfiles rule, CLI and MOTD in a root-private directory, stops the
   service, installs the binary and revision marker, installs every
   privileged file from the copies compiled into that binary, runs
   `systemd-tmpfiles`, `restorecon` and `daemon-reload`, and starts the
   service.
5. Health check `http://127.0.0.1:8080/health` (10 attempts) and verify the
   ownership layout. Any failure after the swap restores the snapshot and
   restarts the previous version; an incomplete restore leaves the path to
   the root-only backup in the error output.

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

`/opt/explorer/.env` is never touched by an update, a rebuild or a rollback.
Neither is anything else in `/opt/explorer`: an update replaces only the
binary and the revision marker, and moves any other entry there (Python-era
leftovers included) to `/opt/explorer-preserved/<time>/` first, so the
directory passes its root-owned layout check without losing it. A rolled-back
update moves those entries back.
Rolling back to a commit from before the Go rewrite works the same way:
`explorer rebuild` sees a checkout without `go.mod` and hands over to that
commit's own `scripts/update.sh`.

## Health checks

Explorer exposes a deliberately public, data-free `/health` route. It returns
`200` only after application startup succeeds, including access-store and
central-client configuration in central mode.

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/health  # expect 200
curl -sI https://explorer.example.com/health | head -1                 # through proxy
systemctl is-active explorer.service
```

`000`/connection refused means the process is down; `502` from the proxy means
the proxy is up but Explorer is not. The health route deliberately does not
prove credentials work; verify sign-in separately with a browser.

## Troubleshooting

### Infinite redirect loop between Explorer and the login page

This section applies to `EXPLORER_AUTH_MODE=elcano`.

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

### Central sign-in returns 400, 403, or 502

This section applies to `EXPLORER_AUTH_MODE=central`.

- `400` means the callback lacked a matching live state transaction, was
  replayed, expired after ten minutes, or auth returned an error. Start again
  at `/auth/login`; do not reuse a callback URL.
- `403` means central authentication succeeded but the returned email is not
  currently enabled. Run `sudo explorer access list`, then grant the exact
  email if appropriate.
- `502` means the server-to-server `/token` exchange failed or returned an
  invalid subject/email/nonce. Confirm the issuer URL, exact callback, client
  ID/secret, TLS certificate, and that the auth service implements the
  documented contract.

The auth service must be reachable from the Explorer box, not only from the
operator's browser. Use `sudo explorer logs -n 100` for startup errors; secrets
remain redacted in `sudo explorer env`.

### `AccessDenied` / `NoSuchBucket` from S3

Symptom: searching shows an error banner (the S3 error code is in it), or
`explorer logs` shows the same `api error` line.

Check from the box with the AWS CLI, using the same credentials Explorer has
(or the instance role):

```bash
aws s3api list-objects-v2 --bucket my-email-archive --prefix emails/ --max-items 3
```

Then check:

- `AccessDenied` on **list** — the policy lacks `s3:ListBucket` on the
  *bucket* ARN, or your `s3:prefix` condition does not cover
  `EMAIL_S3_PREFIX`.
- `AccessDenied` on **get** — `s3:GetObject` is missing on the *object* ARN
  (`arn:aws:s3:::bucket/emails/*`), or the bucket is SSE-KMS encrypted and
  the key policy denies `kms:Decrypt`.
- `NoSuchBucket` / `PermanentRedirect` — wrong `AWS_REGION` for the bucket.
- `InvalidAccessKeyId` / `SignatureDoesNotMatch` — stale key, or a partly
  pasted secret. Rotate and re-enter.
- Nothing in `.env` and no instance role — the AWS SDK finds no credentials
  and fails on the first call.

### Search returns zero results but the archive is not empty

Nearly always the date-prefix pattern. Explorer lists
`EMAIL_S3_DATE_PREFIX_FORMAT` expanded per day; if that does not match your
real layout, it lists prefixes that do not exist and finds nothing — with no
error, because "no objects under this prefix" is a perfectly valid answer.

Compare a real key with a rendered prefix:

```bash
aws s3 ls s3://my-email-archive/emails/ --recursive | head -3
date -u +'emails/%Y/%m/%d/'
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

Elcano session tokens carry `exp`, and central login transactions plus local
Explorer sessions use server timestamps. A fast clock can reject valid state
or sessions; a slow clock can honor them longer than intended.

```bash
timedatectl status              # want: "System clock synchronized: yes"
sudo systemctl enable --now chronyd
chronyc tracking
```

Skew also skews dates: the host's local date picks the default day for a search, and
day prefixes are computed in **UTC**. A box on a non-UTC timezone with a
correct clock is fine; a box with a wrong *date* searches the wrong partition.

### Service will not start

```bash
sudo explorer status
sudo explorer logs -n 100
```

- `203/EXEC` — the binary is not executable by the unit, typically an
  SELinux label. Re-run `sudo explorer rebuild` (it stages beside
  `/opt/explorer` and runs `restorecon`).
- `startup refused` in the log — configuration the service will not run
  with (central mode without `AUTH_SIGNING_PUBKEY`, a placeholder session
  secret, an `http://` issuer, a short client secret, an unknown
  `EXPLORER_AUTH_MODE`, a non-numeric setting). The message names the key;
  `sudo explorer doctor` reports the same problems without restarting.
- `Address already in use` — something else holds 8080:
  `sudo ss -ltnp | grep 8080`.
- `open access database` errors — `/var/lib/explorer` is not owned by
  `explorer`; `sudo systemd-tmpfiles --create /etc/tmpfiles.d/explorer.conf`.

### Searches time out or feel slow

Wide ranges mean many LISTs plus one ranged GET per candidate object.

- Narrow the range, or raise `EMAIL_SEARCH_JOB_MAX_SECONDS` if 120s truly is
  not enough. Header reads run twelve at a time, so latency to the bucket's
  region matters more than object count.
- Untick **Body** in fuzzy search — body matching downloads whole objects.
- Deploy in the **same region** as the bucket. Cross-region round-trips
  dominate at thousands of objects.
- Check `EMAIL_HEADER_FETCH_BYTES` has not been raised far above 64 KB; it is
  paid per result row.

### "This search session expired"

Search jobs and pagination cursors are held in memory, keyed to a
`search_owner_id` in the signed session cookie, and expire after 15 minutes.
A restart, or changing `EXPLORER_SESSION_SECRET`, invalidates them. Run the
search again. These caches are per process — do not run several Explorer
processes behind one load balancer, or a poll can land on a process that has
never heard of the job.

## Upgrading from the Python release

Run the usual command on the box:

```bash
echo y | sudo explorer update
```

The Python-era `explorer update` fetches the new commits, sees that
`scripts/update.sh` changed, and re-runs the new one. That script installs
`golang` if needed, builds the binary from the verified checkout and hands
over to `explorer update` in rebuild mode, which swaps it in exactly as
above. On top of the normal update it:

- moves the old Python tree (`app/`, `.venv`, `.tmp`, scripts) out of
  `/opt/explorer` — into the rollback snapshot while the update runs, then
  deletes it once the new version is healthy;
- disables and removes `explorer-attachment-cleanup.timer` and its service;
- replaces the bash `/usr/local/bin/explorer` with the binary.

`/opt/explorer/.env`, `.env.shared` and `/var/lib/explorer/access.db` are
kept as they are: the configuration format, the variable names and the
database schema are unchanged, so existing sessions and the access list
carry over. If the new version fails its health check, the Python install,
its venv, the bash CLI and the cleanup timer are all restored.

Afterwards, `sudo explorer doctor` should come back clean.

## Manual install (without bootstrap.sh)

On a non-dnf distribution, reproduce what bootstrap does (Go from your
distribution or go.dev; `GOTOOLCHAIN=auto` fetches the exact release
`go.mod` pins):

```bash
sudo useradd --system --home-dir /opt/explorer --shell /usr/sbin/nologin explorer
sudo git clone https://github.com/ElcanoTek/explorer.git /opt/explorer-src
sudo install -d -o root -g root -m 0755 /opt/explorer /opt/explorer/bin
sudo install -d -m 0700 -o explorer -g explorer /var/lib/explorer

cd /opt/explorer-src
sudo env GOTOOLCHAIN=auto CGO_ENABLED=0 go build -trimpath \
  -ldflags "-X github.com/ElcanoTek/explorer/internal/version.revision=$(git rev-parse HEAD)" \
  -o /opt/explorer/bin/explorer ./cmd/explorer
sudo install -m 0755 /opt/explorer/bin/explorer /usr/local/bin/explorer

sudo install -o explorer -g explorer -m 0600 /dev/null /opt/explorer/.env
sudo "$EDITOR" /opt/explorer/.env          # see .env.example

sudo install -m 0644 deploy/systemd/explorer.service /etc/systemd/system/
sudo install -m 0644 deploy/systemd/explorer.tmpfiles.conf /etc/tmpfiles.d/explorer.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/explorer.conf
sudo systemctl daemon-reload
sudo systemctl enable --now explorer.service
```

Then front it with a TLS-terminating proxy as above. `explorer update` and
`explorer bootstrap` assume `dnf` only for package installs; `explorer
rebuild` works anywhere the trusted-checkout rules hold.
