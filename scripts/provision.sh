#!/usr/bin/env bash

# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

# scripts/provision.sh — merge an encrypted config bundle into an Explorer host.
#
# Decrypts provision/clients/<client>.env.enc and merges KEY=VALUE pairs
# into /opt/explorer/.env. Lines outside the marker block are never
# touched, so bootstrap-managed keys (EXPLORER_SESSION_SECRET) and any
# operator overrides are preserved.
#
# Usage:
#   sudo bash scripts/provision.sh                       # interactive
#   sudo explorer provision                              # via the operator CLI
#   sudo explorer provision --client=elcano --no-restart
#
# Env overrides (skip prompts):
#   EXPLORER_PROVISION_CLIENT=elcano
#   EXPLORER_PROVISION_PASSPHRASE=...      # or write to /etc/elcano/passphrase

set -euo pipefail

if [[ ! -t 0 && -t 1 ]]; then exec </dev/tty; fi

APP_DIR="${APP_DIR:-/opt/explorer}"
APP_USER="${APP_USER:-explorer}"
ENV_FILE="$APP_DIR/.env"
PASSPHRASE_FILE="${ELCANO_PASSPHRASE_FILE:-/etc/elcano/passphrase}"
SERVICE="explorer.service"

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CLIENTS_DIR="$SRC_DIR/provision/clients"

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

CLIENT="${EXPLORER_PROVISION_CLIENT:-}"
RESTART=1
NON_INTERACTIVE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --client=*)         CLIENT="${1#*=}" ;;
    --client)           shift; CLIENT="$1" ;;
    --no-restart)       RESTART=0 ;;
    --restart)          RESTART=1 ;;
    --non-interactive)  NON_INTERACTIVE=1 ;;
    # Print the leading doc comment block (anchored on its first line, so
    # the SPDX/copyright header above it never shows up in --help).
    -h|--help)          sed -n '/^# scripts\/provision\.sh/,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown flag: $1" ;;
  esac
  shift
done

[[ $EUID -eq 0 ]] || die "run as root: sudo bash scripts/provision.sh"
[[ -d "$CLIENTS_DIR" ]] || die "no $CLIENTS_DIR — is this a checkout? ($SRC_DIR)"

mapfile -t available < <(find "$CLIENTS_DIR" -maxdepth 1 -name '*.env.enc' -printf '%f\n' 2>/dev/null \
                          | sed 's/\.env\.enc$//' | sort)
[[ ${#available[@]} -gt 0 ]] || die "no encrypted client files in $CLIENTS_DIR (looked for *.env.enc)"

if [[ -z "$CLIENT" ]]; then
  if [[ "$NON_INTERACTIVE" == "1" ]]; then
    [[ ${#available[@]} -eq 1 ]] || die "non-interactive + multiple clients: pass --client=NAME"
    CLIENT="${available[0]}"
  else
    say
    say "${c_bold}Available clients:${c_reset}"
    for c in "${available[@]}"; do say "  • $c"; done
    default="elcano"
    [[ " ${available[*]} " == *" elcano "* ]] || default="${available[0]}"
    ask "Which client? ${c_dim}[${default}]${c_reset}:"
    read -r CLIENT
    CLIENT="${CLIENT:-$default}"
  fi
fi

ENC_FILE="$CLIENTS_DIR/${CLIENT}.env.enc"
[[ -f "$ENC_FILE" ]] || die "no encrypted bundle for client '$CLIENT' at $ENC_FILE"

PASSPHRASE=""
PASSPHRASE_SOURCE=""
if [[ -n "${EXPLORER_PROVISION_PASSPHRASE:-}" ]]; then
  PASSPHRASE="$EXPLORER_PROVISION_PASSPHRASE"
  PASSPHRASE_SOURCE="env"
elif [[ -f "$PASSPHRASE_FILE" ]]; then
  PASSPHRASE="$(<"$PASSPHRASE_FILE")"
  PASSPHRASE_SOURCE="$PASSPHRASE_FILE"
elif [[ "$NON_INTERACTIVE" == "1" ]]; then
  die "non-interactive + no passphrase: set EXPLORER_PROVISION_PASSPHRASE or write one to $PASSPHRASE_FILE"
else
  ask "Passphrase for ${CLIENT}.env.enc:"
  read -rs PASSPHRASE
  echo >&2
  PASSPHRASE_SOURCE="prompt"
  [[ -n "$PASSPHRASE" ]] || die "passphrase is required"
  ask "Save passphrase to ${PASSPHRASE_FILE} for future runs? ${c_dim}(y/N)${c_reset}"
  read -r save_ans
  if [[ "${save_ans,,}" == "y" || "${save_ans,,}" == "yes" ]]; then
    install -d -m 0700 "$(dirname "$PASSPHRASE_FILE")"
    umask 077
    printf '%s' "$PASSPHRASE" > "$PASSPHRASE_FILE"
    chmod 0600 "$PASSPHRASE_FILE"
    ok "saved → $PASSPHRASE_FILE (mode 0600)"
  fi
fi

step "Decrypting ${CLIENT}.env.enc (passphrase from ${PASSPHRASE_SOURCE})"
TMP_PLAIN="$(mktemp)"
trap 'rm -f "$TMP_PLAIN"' EXIT
if ! openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 \
      -in "$ENC_FILE" -out "$TMP_PLAIN" -pass stdin <<<"$PASSPHRASE" 2>/dev/null; then
  die "decryption failed — wrong passphrase?"
fi
ok "decrypted $(wc -l <"$TMP_PLAIN") line(s)"

step "Merging into $ENV_FILE"
if [[ ! -f "$ENV_FILE" ]]; then
  install -d -m 0755 "$APP_DIR"
  : > "$ENV_FILE"
  if id -u "$APP_USER" >/dev/null 2>&1; then
    chown "$APP_USER:$APP_USER" "$ENV_FILE"
  fi
  chmod 0640 "$ENV_FILE"
  info "created empty $ENV_FILE — bootstrap.sh will fill in the rest"
fi

MARKER_BEGIN="# ── managed by explorer provision (${CLIENT}) — do not edit, run \`explorer provision\` to refresh ──"
MARKER_END="# ── end explorer provision (${CLIENT}) ──"

if grep -qF "$MARKER_BEGIN" "$ENV_FILE"; then
  awk -v b="$MARKER_BEGIN" -v e="$MARKER_END" '
    BEGIN { blank=0 }
    $0 == b { skip=1; blank=0; next }
    skip && $0 == e { skip=0; next }
    !skip {
      if ($0 == "") { blank++; next }
      while (blank > 0) { print ""; blank-- }
      print
    }
  ' "$ENV_FILE" > "${ENV_FILE}.tmp" && mv "${ENV_FILE}.tmp" "$ENV_FILE"
  sed -i -e :a -e '/^$/{$d;N;ba' -e '}' "$ENV_FILE"
fi

new_count=0
collide_count=0
declare -a managed_block collisions
managed_block=("$MARKER_BEGIN")
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ "$line" =~ ^[[:space:]]*# || -z "${line//[[:space:]]/}" ]] && continue
  [[ "$line" == *=* ]] || continue
  key="${line%%=*}"
  key="${key//[[:space:]]/}"
  [[ -n "$key" ]] || continue
  managed_block+=("$line")
  if grep -qE "^[[:space:]]*${key}=" "$ENV_FILE"; then
    collide_count=$((collide_count + 1))
    collisions+=("$key")
  else
    new_count=$((new_count + 1))
  fi
done <"$TMP_PLAIN"
managed_block+=("$MARKER_END")

{
  printf '\n'
  for l in "${managed_block[@]}"; do printf '%s\n' "$l"; done
} >> "$ENV_FILE"

chmod 0640 "$ENV_FILE"
if id -u "$APP_USER" >/dev/null 2>&1; then
  chown "$APP_USER:$APP_USER" "$ENV_FILE" 2>/dev/null || true
fi

ok "merged: ${new_count} key(s) provisioned"
if [[ $collide_count -gt 0 ]]; then
  warn "${collide_count} bundle key(s) also set outside the managed block:"
  for k in "${collisions[@]}"; do warn "    • $k"; done
fi

if [[ "$RESTART" == "1" ]]; then
  if systemctl list-unit-files "$SERVICE" >/dev/null 2>&1; then
    step "Restarting $SERVICE"
    systemctl restart "$SERVICE" \
      && ok "$SERVICE restarted" \
      || warn "restart failed — check: journalctl -u $SERVICE -n 50"
  else
    info "$SERVICE not installed yet — skipping restart"
  fi
else
  info "skipping restart (--no-restart). Apply with: sudo systemctl restart $SERVICE"
fi

say
ok "provision complete (client=${CLIENT})"
