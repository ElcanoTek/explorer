# Security Policy

## Reporting a vulnerability

Email **security@elcanotek.com**. Please do not open a public issue, PR, or
discussion for a security problem.

Include what you have: affected version or commit, how to reproduce,
the impact you believe it has, and any proof-of-concept. If you would like a
reply encrypted, say so and we will exchange keys.

**Response targets**

| Stage | Target |
|---|---|
| Acknowledgement | within 3 business days |
| Initial assessment (severity, whether we can reproduce) | within 10 business days |
| Fix or documented mitigation for a confirmed high-severity issue | within 30 days |

We will keep you updated as we go, credit you when the fix ships if you want
credit, and tell you plainly if we decide not to act and why. Please give us
90 days before public disclosure, or less if we ship sooner.

## Handling private email data responsibly

Explorer exists to search a private email archive, so a report about it may
involve real correspondence. **Please do not send us anyone's actual email
content, addresses, headers or attachments** — not in the report, not in a
screenshot, not in a log excerpt. Reproduce with synthetic messages
(`ada@example.com`, invented subjects); the test suite in `tests/` shows how
to build them without touching AWS. If a finding genuinely cannot be
demonstrated without real data, say so and we will arrange a private channel
rather than have it sit in an inbox.

The same rule binds us: we will not ask you for real mail, and we redact any
that reaches us anyway.

If you believe an actual archive has been exposed — not just that a bug
exists — say so in the subject line so it is triaged as an incident rather
than a code report.

## Scope

**In scope**

- The application code in `app/` — authentication and cookie verification,
  the S3 key confinement in `is_allowed_s3_key`, HTML sanitizing of message
  bodies, the attachment endpoint and path handling, search-job and cursor
  ownership.
- The deployment surface in `deploy/`, `scripts/` and `provision/` —
  file permissions, the systemd hardening, secret handling, the temp-file
  lifecycle.
- Documented configuration that is insecure by default, or a default that
  fails open where it should fail closed.
- Anything in this repository that leaks a credential or personal data.

**Out of scope**

- ElcanoTek's own hosted deployments and infrastructure (report those to the
  same address, but they are not this repository).
- The external magic-link auth service that mints the session cookie.
- Findings that require an attacker to already hold the AWS credentials, the
  signing key, or root on the host.
- Missing hardening that the documentation explicitly tells the operator to
  supply — e.g. Explorer serves plain HTTP on loopback on purpose and
  requires a TLS-terminating proxy in front.
- Third-party dependency CVEs with no demonstrated path through Explorer;
  those are handled by Dependabot.
- Automated-scanner output with no analysis attached.

## Known operational expectations

Explorer is designed to be deployed a specific way, and skipping any of these
turns a supported configuration into an insecure one:

- **Behind authentication.** With `AUTH_SIGNING_PUBKEY` unset, every request
  redirects to sign-in — that is the intended fail-closed behaviour, not a
  bug to work around.
- **Behind a TLS-terminating reverse proxy**, bound to `127.0.0.1`.
- **With read-only AWS credentials scoped to one bucket prefix**
  (`s3:ListBucket` + `s3:GetObject`). See the policy in
  [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).
- **With a generated `EXPLORER_SESSION_SECRET`** — the built-in default is a
  placeholder.
- **With the attachment-cleanup timer enabled**, so downloaded attachments do
  not accumulate on disk.

## A note on this repository's history

Explorer was developed privately before it was published; this public
repository begins at its first public commit and does not carry the private
development history. No credentials are committed here, and any credential
used during private development is treated as compromised and rotated out of
service, so nothing you might come across in older material is expected to
work against any ElcanoTek system.

We would still rather hear from you than not. If you have reason to believe
a credential connected to this project is still *live*, that is an incident:
put "live credential" in the subject line and we will treat it as one.
