#!/usr/bin/env bash

# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

# scripts/update.sh — staged update for an Explorer install.
#
# Build in a staging dir, swap atomically, restart. If the build fails
# (uv resolve failure, missing system dep), the live service keeps
# running on the previous revision.
#
# Invoked by `explorer update`. Runnable directly on the host.
#
# Env overrides:
#   SRC_DIR                   source checkout (default: /opt/explorer-src)
#   APP_DIR                   install dir      (default: /opt/explorer)
#   EXPLORER_UPDATE_YES=1     skip confirm
#   EXPLORER_UPDATE_BRANCH    override branch in SRC_DIR

set -euo pipefail

SRC_DIR="${SRC_DIR:-/opt/explorer-src}"
APP_DIR="${APP_DIR:-/opt/explorer}"
APP_USER="${APP_USER:-explorer}"
CLI_TARGET="/usr/local/bin/explorer"
SERVICE="explorer.service"

if [[ -t 1 && "${TERM:-}" != "dumb" ]]; then
  c_reset=$'\033[0m' c_dim=$'\033[2m' c_red=$'\033[0;31m'
  c_green=$'\033[0;32m' c_yellow=$'\033[0;33m' c_cyan=$'\033[0;36m' c_bold=$'\033[1m'
else
  c_reset='' c_dim='' c_red='' c_green='' c_yellow='' c_cyan='' c_bold=''
fi
say()  { printf '%s\n' "$*"; }
step() { printf '\n%s▸ %s%s\n' "$c_bold" "$*" "$c_reset"; }
ok()   { printf '%s✓ %s%s\n' "$c_green" "$*" "$c_reset"; }
warn() { printf '%s! %s%s\n' "$c_yellow" "$*" "$c_reset" >&2; }
die()  { printf '%s✗ %s%s\n' "$c_red" "$*" "$c_reset" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root: sudo explorer update"
[[ -d "$SRC_DIR/.git" ]] || die "no source checkout at $SRC_DIR"
[[ -d "$APP_DIR" ]]      || die "no existing install at $APP_DIR (run bootstrap.sh)"

# ── 1. fetch ────────────────────────────────────────────────────────────
step "1/4  Fetching latest"
cd "$SRC_DIR"
git config --global --add safe.directory "$SRC_DIR" 2>/dev/null || true
before_sha="$(git rev-parse HEAD)"

if [[ "${EXPLORER_UPDATE_NO_PULL:-0}" == "1" ]]; then
  after_sha="$before_sha"
  # Set when a pull re-execs the fresh script (below) so the final
  # summary still shows the real old → new range.
  before_sha="${EXPLORER_UPDATE_BASE_SHA:-$before_sha}"
  ok "rebuild-only mode — skipping fetch, building ${after_sha:0:12}"
  say
else
  git fetch --quiet origin

  # Resolve target branch.  If HEAD is attached we simply follow it.
  # If detached, try to recover from a local branch at this commit;
  # otherwise fall back to the repo's default branch (origin/HEAD).
  current_branch="$(git rev-parse --abbrev-ref HEAD)"
  if [[ -n "${EXPLORER_UPDATE_BRANCH:-}" ]]; then
    target_branch="$EXPLORER_UPDATE_BRANCH"
  elif [[ "$current_branch" != "HEAD" ]]; then
    target_branch="$current_branch"
  else
    mapfile -t matching < <(git branch --points-at HEAD --format='%(refname:short)')
    if [[ ${#matching[@]} -eq 1 ]]; then
      target_branch="${matching[0]}"
      warn "HEAD is detached — recovering tracked branch '$target_branch'"
    elif [[ ${#matching[@]} -gt 1 ]]; then
      target_branch="${matching[0]}"
      warn "HEAD is detached — multiple local branches match; using '$target_branch'"
    else
      target_branch="$(git rev-parse --abbrev-ref origin/HEAD | sed 's|^origin/||')"
      warn "HEAD is detached — defaulting to '$target_branch'"
      warn "  (set EXPLORER_UPDATE_BRANCH to override)"
    fi
  fi
  target_ref="origin/$target_branch"
  after_sha="$(git rev-parse "$target_ref")"

  if [[ "$before_sha" == "$after_sha" ]]; then
    ok "already on ${after_sha:0:12} — nothing to update"
    exit 0
  fi

  say
  printf '%s  incoming commits:%s\n' "$c_dim" "$c_reset"
  git --no-pager log --oneline --no-decorate "${before_sha}..${after_sha}" | sed 's/^/    /'
  say

  if [[ "${EXPLORER_UPDATE_YES:-0}" != "1" ]]; then
    count="$(git rev-list --count "${before_sha}..${after_sha}")"
    printf '%s?%s Apply %s%d%s commits — %s..%s? %s(y/N)%s ' \
      "$c_cyan" "$c_reset" "$c_bold" "$count" "$c_reset" \
      "${before_sha:0:12}" "${after_sha:0:12}" "$c_dim" "$c_reset"
    read -r answer
    case "${answer,,}" in y|yes) ;; *) warn "cancelled"; exit 1 ;; esac
  fi

  # Stay on a local branch — never detach HEAD.  If the branch already
  # exists, fast-forward it; otherwise create it from the fetched ref.
  if git show-ref --quiet --verify "refs/heads/$target_branch"; then
    git checkout --quiet "$target_branch"
    git merge --ff-only "$target_ref" || die "$target_branch has diverged from $target_ref — resolve manually"
  else
    git checkout --quiet -b "$target_branch" "$target_ref"
  fi

  # The shell running this script read the PRE-update file (bash holds the
  # old inode across the checkout above), so a fix to update.sh itself
  # would otherwise only take effect on the NEXT update. If this update
  # changed update.sh, re-exec the fresh copy in rebuild-only mode.
  if ! git diff --quiet "$before_sha" "$after_sha" -- scripts/update.sh; then
    warn "update.sh changed in this update — re-executing the new version"
    exec env EXPLORER_UPDATE_NO_PULL=1 EXPLORER_UPDATE_YES=1 \
      EXPLORER_UPDATE_BASE_SHA="$before_sha" bash "$SRC_DIR/scripts/update.sh"
  fi
fi

# ── 1b. auth public key ──────────────────────────────────────────────────
# Explorer verifies the session cookie with the auth service's PUBLIC key
# (AUTH_SIGNING_PUBKEY). Without it every request bounces to the login URL in
# a redirect loop — and the health check below still passes on that 303, so
# the breakage would otherwise be silent. Make sure it's set before restarting.
ensure_auth_pubkey() {
  local found="" f v
  for f in "$APP_DIR/.env.shared" "$APP_DIR/.env"; do
    [[ -f "$f" ]] || continue
    v="$(sed -n 's/^[[:space:]]*AUTH_SIGNING_PUBKEY[[:space:]]*=[[:space:]]*//p' "$f" | tail -n1)"
    v="${v%[\"\']}"; v="${v#[\"\']}"
    [[ -n "$v" ]] && found="$v"
  done
  [[ -n "$found" ]] && return 0

  warn "AUTH_SIGNING_PUBKEY is not set — Explorer can't verify the session"
  warn "cookie, so every request will redirect to sign-in in a loop until it is."
  if [[ -t 0 ]]; then
    printf '%s?%s Paste the auth service public key now (blank to skip): ' "$c_cyan" "$c_reset"
    local pubkey_in; read -r pubkey_in
    if [[ -n "$pubkey_in" ]]; then
      [[ -f "$APP_DIR/.env" ]] || install -o "$APP_USER" -g "$APP_USER" -m 0640 /dev/null "$APP_DIR/.env"
      printf 'AUTH_SIGNING_PUBKEY="%s"\n' "$pubkey_in" >> "$APP_DIR/.env"
      chown "$APP_USER:$APP_USER" "$APP_DIR/.env"; chmod 0640 "$APP_DIR/.env"
      ok "AUTH_SIGNING_PUBKEY written to $APP_DIR/.env"
    else
      warn "skipped — set it later with: explorer env edit   (then: explorer restart)"
    fi
  else
    warn "non-interactive — set it with: explorer env edit   (then: explorer restart)"
  fi
}
ensure_auth_pubkey

# ── 2. staging build ────────────────────────────────────────────────────
step "2/4  Building new venv in staging"
# Stage beside $APP_DIR, not in /tmp: a venv built under /tmp keeps its
# SELinux tmp_t label across mv, and systemd refuses to exec tmp_t
# (203/EXEC Permission denied). Same filesystem also makes the final mv
# atomic and lets uv hardlink from its cache. /opt has no tmp reaper, so
# sweep leftovers from any previous run that died before its EXIT trap.
rm -rf "${APP_DIR}".staging.* 2>/dev/null || true
STAGING="$(mktemp -d "${APP_DIR}.staging.XXXXXX")"
trap 'rm -rf "$STAGING"' EXIT

rsync -a --exclude='/.git' --exclude='/.venv' --exclude='/.tmp' "$SRC_DIR/" "$STAGING/"
chown -R "$APP_USER:$APP_USER" "$STAGING"

# Build the new venv under $STAGING/.venv so a failed resolve leaves
# the live /opt/explorer/.venv untouched.
runuser -u "$APP_USER" -- uv venv "$STAGING/.venv" >/dev/null
runuser -u "$APP_USER" -- uv pip install --python "$STAGING/.venv/bin/python" \
  --reinstall -r "$STAGING/requirements.txt" \
  || die "uv pip install failed — live install untouched"
ok "staging venv ready"

# ── 3. atomic swap + restart ────────────────────────────────────────────
step "3/4  Swapping in + restarting"
systemctl stop "$SERVICE" || true

# Swap the source tree. Keep the live .env and .tmp runtime dir.
rsync -a --delete \
  --exclude='/.git' \
  --exclude='/.venv' \
  --exclude='/.tmp' \
  --exclude='/.env' \
  "$STAGING/" "$APP_DIR/"

# Replace the .venv atomically by moving-aside the old one first. If
# this partial-renames, the OLD venv survives as .venv.old for rollback.
if [[ -d "$APP_DIR/.venv" ]]; then
  rm -rf "$APP_DIR/.venv.old"
  mv "$APP_DIR/.venv" "$APP_DIR/.venv.old"
fi
mv "$STAGING/.venv" "$APP_DIR/.venv"
chown -R "$APP_USER:$APP_USER" "$APP_DIR/.venv"

# Reinstall systemd units + CLI in case they changed between versions.
install -m 0644 "$APP_DIR/deploy/systemd/explorer.service" /etc/systemd/system/
install -m 0644 "$APP_DIR/deploy/systemd/explorer-attachment-cleanup.service" /etc/systemd/system/
install -m 0644 "$APP_DIR/deploy/systemd/explorer-attachment-cleanup.timer" /etc/systemd/system/
install -m 0644 "$APP_DIR/deploy/systemd/explorer.tmpfiles.conf" /etc/tmpfiles.d/explorer.conf
install -m 0755 "$APP_DIR/deploy/explorer-cli" "$CLI_TARGET"
# Keep /etc/motd in sync with deploy/motd — boxes bootstrapped before the
# banner existed never got one, and this heals drift on every update.
if [[ -f "$APP_DIR/deploy/motd" ]] && ! cmp -s "$APP_DIR/deploy/motd" /etc/motd; then
  install -m 0644 "$APP_DIR/deploy/motd" /etc/motd
  ok "motd installed/refreshed"
fi
if command -v restorecon >/dev/null 2>&1; then
  restorecon -RF "$APP_DIR" "$SRC_DIR" "$CLI_TARGET" /etc/systemd/system/explorer.service /etc/systemd/system/explorer-attachment-cleanup.service /etc/systemd/system/explorer-attachment-cleanup.timer /etc/tmpfiles.d/explorer.conf 2>/dev/null || true
fi
systemctl daemon-reload
systemctl start "$SERVICE"
ok "service restarted"

# ── 4. health check ─────────────────────────────────────────────────────
step "4/4  Health check"
# Explorer owns no /login route anymore — login is the unified elcano_auth
# cookie. An unauthenticated GET / 303-redirects to the auth service (the
# healthy signal); GET /login would 404. Probe / and accept 2xx/3xx.
for i in 1 2 3 4 5 6 7 8 9 10; do
  code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/ 2>/dev/null || echo 000)
  if [[ "$code" == "200" || "$code" == "302" || "$code" == "303" ]]; then
    ok "explorer / → $code (server up, redirecting to auth)"
    # Drop the old venv only after we know the new install is live;
    # keeping it around for one successful cycle gives operators a
    # trivial rollback window.
    rm -rf "$APP_DIR/.venv.old" 2>/dev/null || true
    break
  fi
  sleep 1
  if [[ "$i" == "10" ]]; then
    warn "explorer didn't answer / within 10s"
    warn "  Rollback: systemctl stop $SERVICE && rm -rf $APP_DIR/.venv && mv $APP_DIR/.venv.old $APP_DIR/.venv && systemctl start $SERVICE"
    exit 1
  fi
done

say
printf '%s═══════════════════════════════════════════════%s\n' "$c_green" "$c_reset"
printf '%s ✓ Updated %s → %s%s\n' "$c_bold" "${before_sha:0:12}" "${after_sha:0:12}" "$c_reset"
printf '%s═══════════════════════════════════════════════%s\n' "$c_green" "$c_reset"
say
say "  Logs:      ${c_dim}explorer logs${c_reset}"
# `explorer update` would fast-forward straight back to the tip, so a
# rollback has to rebuild the older checkout WITHOUT fetching. Use a named
# branch so the checkout never ends up detached.
say "  Roll back: ${c_dim}cd $SRC_DIR && sudo git checkout -B rollback $before_sha && sudo explorer rebuild${c_reset}"
