#!/usr/bin/env bash

# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

# scripts/bootstrap.sh — interactive installer for Elcano Explorer.
#
# What this does:
#   1. Installs system deps via dnf (python3, uv, ripgrep, etc.)
#   2. Creates 'explorer' system user + /opt/explorer
#   3. Syncs source to /opt/explorer-src, then rsyncs into /opt/explorer
#   4. Builds the venv via uv and installs Python deps
#   5. Writes /opt/explorer/.env with session secret + AUTH_SIGNING_PUBKEY
#   6. Installs the explorer + attachment-cleanup systemd units + timer
#   7. Installs /usr/local/bin/explorer operator CLI
#   8. Enables and starts the service; health-checks /
#
# Usage:
#   sudo bash scripts/bootstrap.sh
#
# Re-run safe — existing .env values and DB state are preserved. For
# scripted installs set EXPLORER_BOOTSTRAP_NON_INTERACTIVE=1 and the
# env overrides below.
#
# Targets Fedora 39+ / RHEL 9+ / AlmaLinux 9+. Patterned after
# chat/gig/moc.

set -euo pipefail

if [[ ! -t 0 && -t 1 ]]; then exec </dev/tty; fi

APP_DIR="${APP_DIR:-/opt/explorer}"
APP_USER="${APP_USER:-explorer}"
SRC_DIR="${SRC_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
INSTALL_SRC_DIR="${EXPLORER_SRC_DIR:-/opt/explorer-src}"
ENV_FILE="$APP_DIR/.env"
CLI_TARGET="/usr/local/bin/explorer"

if [[ -t 1 && "${TERM:-}" != "dumb" ]]; then
  c_reset=$'\033[0m' c_dim=$'\033[2m' c_red=$'\033[0;31m'
  c_green=$'\033[0;32m' c_yellow=$'\033[0;33m' c_cyan=$'\033[0;36m' c_bold=$'\033[1m'
else
  c_reset='' c_dim='' c_red='' c_green='' c_yellow='' c_cyan='' c_bold=''
fi
say()  { printf '%s\n' "$*"; }
info() { printf '%s» %s%s\n' "$c_dim" "$*" "$c_reset"; }
step() { printf '\n%s▸ %s%s\n' "$c_bold" "$*" "$c_reset"; }
ok()   { printf '%s✓ %s%s\n' "$c_green" "$*" "$c_reset"; }
warn() { printf '%s! %s%s\n' "$c_yellow" "$*" "$c_reset" >&2; }
die()  { printf '%s✗ %s%s\n' "$c_red" "$*" "$c_reset" >&2; exit 1; }
ask()  { printf '%s?%s %s ' "$c_cyan" "$c_reset" "$*" >&2; }

NON_INTERACTIVE="${EXPLORER_BOOTSTRAP_NON_INTERACTIVE:-0}"
prompt() {
  local varname="$1" label="$2" default="${3:-}" answer=""
  if [[ -n "${!varname:-}" ]]; then printf '%s' "${!varname}"; return; fi
  if [[ "$NON_INTERACTIVE" == "1" ]]; then
    [[ -n "$default" ]] || die "non-interactive + missing: set $varname"
    printf '%s' "$default"; return
  fi
  if [[ -n "$default" ]]; then ask "$label ${c_dim}[$default]${c_reset}:"
  else ask "$label:"; fi
  read -r answer
  [[ -z "$answer" ]] && answer="$default"
  printf '%s' "$answer"
}
genbase64() { openssl rand -base64 "$1" | tr -d '=\n' | tr '/+' '_-'; }
genhex()    { openssl rand -hex "$1"; }

[[ $EUID -eq 0 ]] || die "run as root: sudo bash scripts/bootstrap.sh"
[[ -f "$SRC_DIR/requirements.txt" ]] || die "not an Explorer checkout at $SRC_DIR"

cat <<EOF
${c_bold}Elcano Explorer — bootstrap${c_reset}
${c_dim}Fedora / RHEL 9+  •  systemd  •  FastAPI email-archive UI${c_reset}

Safe to re-run: existing .env is preserved; only missing values are prompted.

EOF

# ── step 1: system packages ──────────────────────────────────────────────
step "1/7  Installing system dependencies via dnf"
PKGS=(git curl jq python3 python3-devel gcc uv ripgrep rsync openssl)
dnf install -y "${PKGS[@]}" >/dev/null
command -v uv >/dev/null 2>&1 || die "uv missing after dnf install"
ok "installed: ${PKGS[*]}"

# ── step 2: source checkout + system user ───────────────────────────────
step "2/7  Preparing $APP_DIR + '$APP_USER' user"
if ! id -u "$APP_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin "$APP_USER"
fi
mkdir -p "$APP_DIR/.tmp/email_attachments"
chown -R "$APP_USER:$APP_USER" "$APP_DIR"

if [[ ! -d "$INSTALL_SRC_DIR/.git" ]]; then
  # Seed WITH /.git so `explorer update` can git fetch/merge later.
  # /.venv stays excluded — we rebuild it into APP_DIR below.
  [[ -d "$SRC_DIR/.git" ]] || die "bootstrap must run from a git checkout (no .git at $SRC_DIR)"
  mkdir -p "$INSTALL_SRC_DIR"
  rsync -a --exclude='/.venv' "$SRC_DIR/" "$INSTALL_SRC_DIR/"
  ok "copied $SRC_DIR → $INSTALL_SRC_DIR"
else
  info "$INSTALL_SRC_DIR already exists — leaving it in place"
fi

# Sync source from the canonical checkout into the app dir. --delete
# keeps the install in sync with the repo layout, but we exclude
# .venv (built below) and .tmp (runtime state).
rsync -a --delete \
  --exclude='/.git' \
  --exclude='/.venv' \
  --exclude='/.tmp' \
  --exclude='/.env' \
  "$INSTALL_SRC_DIR/" "$APP_DIR/"
chown -R "$APP_USER:$APP_USER" "$APP_DIR"

# ── step 3: Python env via uv ────────────────────────────────────────────
step "3/7  Building venv + installing Python deps via uv"
# uv-only: the chat deploy lessons learned apply here too — pip on
# modern Fedora hits PEP 668 and resolution-depth walls with these
# transitive graphs. uv is in the Fedora repos.
runuser -u "$APP_USER" -- uv venv "$APP_DIR/.venv" >/dev/null
runuser -u "$APP_USER" -- uv pip install --python "$APP_DIR/.venv/bin/python" \
  --reinstall -r "$APP_DIR/requirements.txt" \
  || die "uv pip install failed — service will not boot"
ok "venv + deps ready at $APP_DIR/.venv"

# ── step 4: prompts + env file ──────────────────────────────────────────
step "4/7  Configuring the instance"
if [[ -f "$ENV_FILE" ]]; then
  info "found existing $ENV_FILE — re-using values, only asking for what's missing"
  # shellcheck disable=SC1090
  set -a; . "$ENV_FILE"; set +a
fi

EXPLORER_SESSION_SECRET="${EXPLORER_SESSION_SECRET:-$(genbase64 32)}"

# Explorer verifies the session cookie minted by an external magic-link auth
# service, using that service's Ed25519 PUBLIC key (base64, 32 raw bytes).
# Safe to paste — a public key can only verify, never mint, sessions. Without
# it the app redirects every request to the login URL.
AUTH_SIGNING_PUBKEY="$(prompt AUTH_SIGNING_PUBKEY "auth service AUTH_SIGNING_PUBKEY, base64 (blank to set later)" "${AUTH_SIGNING_PUBKEY:-}")"

# ── Caddy / TLS intent (actual install happens in step 7) ────────
# Collect answers now so the rest of the run has no surprise prompts.
HOSTNAME_FOR_TLS="$(prompt EXPLORER_BOOTSTRAP_HOSTNAME "Public hostname for TLS (e.g. explorer.example.com, blank to skip Caddy)" "${EXPLORER_BOOTSTRAP_HOSTNAME:-}")"
SETUP_CADDY="n"; USE_LETSENCRYPT="n"; LE_EMAIL=""
if [[ -n "$HOSTNAME_FOR_TLS" && "$HOSTNAME_FOR_TLS" != "localhost" ]]; then
  SETUP_CADDY_ANS="$(prompt EXPLORER_BOOTSTRAP_SETUP_CADDY "Set up Caddy + auto-TLS for $HOSTNAME_FOR_TLS? (Y/n)" Y)"
  case "${SETUP_CADDY_ANS,,}" in y|yes) SETUP_CADDY="y" ;; esac
  if [[ "$SETUP_CADDY" == "y" ]]; then
    LE_ANS="$(prompt EXPLORER_BOOTSTRAP_USE_LETSENCRYPT "Use Let's Encrypt (needs public 80/443)? (Y/n)" Y)"
    case "${LE_ANS,,}" in y|yes) USE_LETSENCRYPT="y" ;; esac
    if [[ "$USE_LETSENCRYPT" == "y" ]]; then
      LE_EMAIL="$(prompt EXPLORER_BOOTSTRAP_LE_EMAIL "LE contact email (blank to skip)" "${EXPLORER_BOOTSTRAP_LE_EMAIL:-}")"
    fi
  fi
fi

# AWS creds for S3 email archive reads. We don't auto-generate anything
# here — blank values are passed through and the operator can edit
# /opt/explorer/.env later. Services won't crash without them but
# S3-backed features will error.
EMAIL_S3_BUCKET="$(prompt EMAIL_S3_BUCKET "S3 bucket for email archive (blank to fill in later)" "${EMAIL_S3_BUCKET:-}")"
AWS_REGION="$(prompt AWS_REGION "AWS region" "${AWS_REGION:-us-east-2}")"

umask 077
cat > "$ENV_FILE" <<EOF
# Auto-generated by Explorer bootstrap.sh on $(date -Iseconds)

EXPLORER_SESSION_SECRET="$EXPLORER_SESSION_SECRET"

# Auth service's Ed25519 public key — verifies the session cookie.
AUTH_SIGNING_PUBKEY="$AUTH_SIGNING_PUBKEY"
# Where unauthenticated browsers are sent to sign in.
# AUTH_LOGIN_URL="https://auth.elcanotek.com"

# ── AWS / S3 (optional) ──
AWS_REGION="$AWS_REGION"
EMAIL_S3_BUCKET="$EMAIL_S3_BUCKET"
# AWS_ACCESS_KEY_ID=
# AWS_SECRET_ACCESS_KEY=
EOF
chown "$APP_USER:$APP_USER" "$ENV_FILE"
chmod 0640 "$ENV_FILE"
ok "env seeded at $ENV_FILE"

# ── step 4b: optional encrypted config bundle ───────────────────────────
# Run BEFORE the systemd start step so the service sees the merged values
# on its first boot. provision.sh is also runnable standalone post-install
# via `sudo explorer provision`.
PROVISION_DIR="$APP_DIR/provision/clients"
if compgen -G "$PROVISION_DIR/*.env.enc" >/dev/null 2>&1; then
  step "Encrypted config bundle (optional)"
  do_provision_ans="$(prompt EXPLORER_BOOTSTRAP_PROVISION "Provision config from the encrypted bundle now? (Y/n)" Y)"
  if [[ "${do_provision_ans,,}" == y* ]]; then
    mapfile -t _clients < <(find "$PROVISION_DIR" -maxdepth 1 -name '*.env.enc' -printf '%f\n' \
                              | sed 's/\.env\.enc$//' | sort)
    if [[ ${#_clients[@]} -eq 1 ]]; then
      _client="${_clients[0]}"
    else
      say "  Available clients:"
      for _c in "${_clients[@]}"; do say "    • $_c"; done
      _default="elcano"
      [[ " ${_clients[*]} " == *" elcano "* ]] || _default="${_clients[0]}"
      _client="$(prompt EXPLORER_BOOTSTRAP_PROVISION_CLIENT "Which client?" "$_default")"
    fi
    if bash "$APP_DIR/scripts/provision.sh" --client="$_client" --no-restart; then
      ok "config bundle provisioned ($_client)"
    else
      warn "provision failed — continuing install. Retry later with: sudo explorer provision"
    fi
  else
    info "skipping provision — run 'sudo explorer provision' later if you change your mind"
  fi
fi

# ── step 5: systemd units + CLI ─────────────────────────────────────────
step "5/7  Installing systemd units + operator CLI"
install -m 0644 "$APP_DIR/deploy/systemd/explorer.service" /etc/systemd/system/
install -m 0644 "$APP_DIR/deploy/systemd/explorer-attachment-cleanup.service" /etc/systemd/system/
install -m 0644 "$APP_DIR/deploy/systemd/explorer-attachment-cleanup.timer" /etc/systemd/system/
install -m 0644 "$APP_DIR/deploy/systemd/explorer.tmpfiles.conf" /etc/tmpfiles.d/explorer.conf
install -m 0755 "$APP_DIR/deploy/explorer-cli" "$CLI_TARGET"
systemd-tmpfiles --create /etc/tmpfiles.d/explorer.conf >/dev/null
systemctl daemon-reload
ok "systemd units + CLI installed"

# ── step 6: enable + start + health check ───────────────────────────────
step "6/7  Starting explorer"
systemctl enable --now explorer-attachment-cleanup.timer >/dev/null 2>&1 || true
systemctl enable explorer.service >/dev/null 2>&1 || true
systemctl restart explorer.service
ok "explorer.service restarted"

# Health check — probe /. With no elcano_auth cookie the app redirects (303)
# to the auth service, which proves it's up and the auth gate is wired.
healthy=0
for _ in $(seq 1 15); do
  code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/ 2>/dev/null || echo 000)
  if [[ "$code" == "200" || "$code" == "303" || "$code" == "302" ]]; then healthy=1; break; fi
  sleep 1
done
if [[ "$healthy" == "1" ]]; then
  ok "health check / → ${code} (app up; unauthenticated requests redirect to auth)"
else
  warn "explorer didn't answer / in 15s — check: explorer logs"
fi

# ── step 7: Caddy / TLS (optional) ──────────────────────────────────────
step "7/7  Reverse proxy / TLS"
if [[ "$SETUP_CADDY" == "y" ]]; then
  # DNS pre-check before asking LE for a cert. Warning-only so the
  # operator can still proceed with `tls internal` on a box without
  # public reachability.
  resolved_ip=""
  if command -v dig >/dev/null 2>&1; then
    resolved_ip=$(dig +short "$HOSTNAME_FOR_TLS" A 2>/dev/null | tail -n1 || true)
  fi
  public_ip=$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)
  if [[ -n "$resolved_ip" && -n "$public_ip" && "$resolved_ip" != "$public_ip" ]]; then
    warn "DNS mismatch: $HOSTNAME_FOR_TLS → $resolved_ip, this box → $public_ip"
    warn "  LE will fail the HTTP-01 challenge until the A record is updated."
  elif [[ -z "$resolved_ip" ]]; then
    warn "$HOSTNAME_FOR_TLS doesn't resolve yet — challenge will fail until DNS lands."
  elif [[ -n "$resolved_ip" && "$resolved_ip" == "$public_ip" ]]; then
    ok "DNS resolves correctly ($resolved_ip)"
  fi

  dnf install -y caddy >/dev/null
  install -d /etc/caddy/conf.d

  # Ensure main /etc/caddy/Caddyfile imports our conf.d/. We only add
  # the import if no import line exists at all — so the first service
  # installed sets it up and subsequent services drop snippets into
  # /etc/caddy/conf.d/ without overwriting each other.
  if [[ ! -f /etc/caddy/Caddyfile ]] || ! grep -qE '^[[:space:]]*import[[:space:]]' /etc/caddy/Caddyfile; then
    {
      echo ""
      echo "# Managed by Elcano service bootstraps — each service drops"
      echo "# its own site block at /etc/caddy/conf.d/<service>.caddy."
      echo "import conf.d/*.caddy"
    } >> /etc/caddy/Caddyfile
  fi

  # Inject an LE contact email as a global block at the top of
  # /etc/caddy/Caddyfile if one was given and there isn't one already.
  # Only one global block is allowed per Caddyfile set.
  if [[ -n "$LE_EMAIL" ]] && ! grep -qE '^[[:space:]]*email[[:space:]]' /etc/caddy/Caddyfile; then
    tmp=$(mktemp)
    printf '{\n\temail %s\n}\n\n' "$LE_EMAIL" > "$tmp"
    cat /etc/caddy/Caddyfile >> "$tmp"
    install -m 0644 "$tmp" /etc/caddy/Caddyfile
    rm -f "$tmp"
  fi

  # Render the per-service snippet with hostname substituted. If the
  # operator said no to Let's Encrypt, inject `tls internal` right
  # after the opening brace of the site block. awk over sed because
  # BSD/GNU sed differ on `a\` syntax.
  tmp=$(mktemp)
  sed "s/{{HOSTNAME}}/$HOSTNAME_FOR_TLS/g" "$APP_DIR/deploy/explorer.caddy" > "$tmp"
  if [[ "$USE_LETSENCRYPT" != "y" ]]; then
    awk -v host="$HOSTNAME_FOR_TLS" '
      $0 == host " {" { print; print "\ttls internal"; next }
      { print }
    ' "$tmp" > "$tmp.2" && mv "$tmp.2" "$tmp"
  fi
  install -m 0644 "$tmp" /etc/caddy/conf.d/explorer.caddy
  rm -f "$tmp"

  # Open 80/443 if firewalld is active. Soft-fail: some boxes run pf
  # or no firewall at all — don't abort the install on an unusual host.
  if systemctl is-active --quiet firewalld 2>/dev/null; then
    firewall-cmd --add-service=http --permanent >/dev/null 2>&1 || true
    firewall-cmd --add-service=https --permanent >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    ok "firewalld: http + https opened"
  fi

  systemctl enable caddy >/dev/null 2>&1 || true
  # `caddy reload` is graceful and validates before applying; only fall
  # back to `restart` if the service wasn't already running.
  if systemctl is-active --quiet caddy; then
    systemctl reload caddy || die "caddy reload failed — run 'caddy validate' to debug"
  else
    systemctl start caddy || die "caddy failed to start — check: journalctl -u caddy"
  fi
  ok "Caddy running — auto-renews ~30 days before expiry, no cron needed"

  if [[ "$USE_LETSENCRYPT" == "y" ]]; then
    info "waiting for TLS at https://${HOSTNAME_FOR_TLS} (up to 45s)"
    tls_ok=0
    for _ in $(seq 1 45); do
      if curl -fsS --max-time 5 "https://${HOSTNAME_FOR_TLS}/" -o /dev/null 2>/dev/null; then
        tls_ok=1; break
      fi
      sleep 1
    done
    if [[ "$tls_ok" == "1" ]]; then
      expiry=$(echo | openssl s_client -servername "$HOSTNAME_FOR_TLS" \
        -connect "${HOSTNAME_FOR_TLS}:443" 2>/dev/null \
        | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
      ok "TLS live — cert valid until ${expiry:-unknown}"
    else
      warn "https://${HOSTNAME_FOR_TLS} didn't come up in 45s — check: journalctl -u caddy"
    fi
  fi
else
  info "skipping Caddy — reach explorer at http://127.0.0.1:8080 (or via your own proxy)"
fi

# ── motd ─────────────────────────────────────────────────────────────────
# Single source of truth is deploy/motd; update.sh keeps it in sync on
# existing boxes.
install -m 0644 "$APP_DIR/deploy/motd" /etc/motd

say
printf '%s═══════════════════════════════════════════════%s\n' "$c_green" "$c_reset"
printf '%s ✓ Explorer installed%s\n' "$c_bold" "$c_reset"
printf '%s═══════════════════════════════════════════════%s\n' "$c_green" "$c_reset"
say
if [[ "$SETUP_CADDY" == "y" ]]; then
  say "  URL         ${c_bold}https://$HOSTNAME_FOR_TLS${c_reset}"
else
  say "  URL         ${c_bold}http://127.0.0.1:8080${c_reset}  (front with your reverse proxy for HTTPS)"
fi
say "  Logs        ${c_dim}explorer logs${c_reset}"
say "  CLI         ${c_dim}explorer start|stop|restart|status|update|env|tls${c_reset}"
say
say "  Sign-in     ${c_dim}via the external magic-link auth service — no local password${c_reset}"
if [[ -z "$AUTH_SIGNING_PUBKEY" ]]; then
  printf '  %s! AUTH_SIGNING_PUBKEY is unset — every request will redirect to sign-in.%s\n' "$c_yellow" "$c_reset"
  printf '  %s  Set it with: explorer env edit  (paste the auth service public key), then: explorer restart%s\n' "$c_yellow" "$c_reset"
fi
say
