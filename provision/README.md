# Encrypted config bundles (optional)

This is a convenience for pushing one shared configuration to several
Explorer hosts. It is entirely optional — a hand-written
`/opt/explorer/.env` is equally valid, and most single-host deployments should
just do that. See [../docs/DEPLOYMENT.md](../docs/DEPLOYMENT.md).

`provision/clients/<name>.env.enc` is an encrypted `KEY=VALUE` bundle. On a
deployed host, `sudo explorer provision` (`scripts/provision.sh`) decrypts it
and merges the values into `/opt/explorer/.env` inside a marked block, leaving
everything outside that block — including the bootstrap-generated session
secret and any operator overrides — untouched.

Encryption is `openssl enc -aes-256-cbc -pbkdf2 -iter 600000` with a single
passphrase. Keep that passphrase in your team's password manager, never in
this repository, and never in shell history.

## No bundle ships here

**No `*.env.enc` file is committed to this repository, and none should be.**
`.gitignore` blocks them. A public repository containing an encrypted blob of
live credentials is a credential leak waiting on one passphrase guess: the
ciphertext is permanent, offline, and downloadable by anyone, while the
passphrase is something a human chose and typed.

Keep bundles in private infrastructure instead — a private overlay repo, your
secret manager, or a file you copy to the host out of band. `provision.sh`
looks in `provision/clients/` on the host, so place the file there before
running it (mode `0600`, owned by root):

```bash
sudo install -m 0600 acme.env.enc /opt/explorer-src/provision/clients/
sudo explorer provision --client=acme
```

With no `*.env.enc` present, `bootstrap.sh` silently skips this step and
`explorer provision` exits with a clear message.

Better still on cloud hosts: skip bundles entirely, attach an instance role
for S3 access, and keep the handful of remaining settings in
`systemd` `Environment=` lines or a plain `.env`.

## Operator workflows

```bash
# During install: bootstrap.sh offers to provision if a bundle is present.
sudo bash scripts/bootstrap.sh

# Re-provision later (e.g. after rotating a key):
sudo explorer provision                          # interactive picker
sudo explorer provision --client=acme            # skip the picker
sudo explorer provision --client=acme --no-restart

# Non-interactive (CI / Ansible):
sudo EXPLORER_PROVISION_CLIENT=acme \
     EXPLORER_PROVISION_PASSPHRASE='...' \
     bash scripts/provision.sh --non-interactive --no-restart
```

The passphrase is read from `EXPLORER_PROVISION_PASSPHRASE`, else from
`/etc/elcano/passphrase` (mode `0600`; override the path with
`ELCANO_PASSPHRASE_FILE`), else prompted for.

## Creating a bundle

```bash
cp provision/clients/_template.env /tmp/acme.env
$EDITOR /tmp/acme.env               # fill in the values
openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt \
  -in /tmp/acme.env \
  -out acme.env.enc \
  -pass stdin
shred -u /tmp/acme.env              # never leave plaintext behind
```

Store `acme.env.enc` privately. Never `git add` it here.

## Rotating a value

```bash
openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 \
  -in acme.env.enc -pass stdin > /tmp/acme.env
$EDITOR /tmp/acme.env
openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt \
  -in /tmp/acme.env -out acme.env.enc -pass stdin
shred -u /tmp/acme.env
# distribute the new bundle to each host, then: sudo explorer provision
```

## What does NOT belong in a bundle

These are generated or entered per host by `bootstrap.sh`:

- `EXPLORER_SESSION_SECRET` — must be unique per host.
- `AUTH_SIGNING_PUBKEY` — the auth service's Ed25519 public key. It is a
  *public* key, so it needs no encryption; keeping it out of the bundle also
  means a key rotation does not require re-encrypting anything.
