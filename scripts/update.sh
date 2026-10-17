#!/usr/bin/env bash

# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

# Staged update for an Explorer install. The checkout and installed source are
# root-owned. Only the virtualenv and runtime state are writable by the service
# account, and root never installs executable material from those paths.

set -euo pipefail

SRC_DIR="${SRC_DIR:-/opt/explorer-src}"
APP_DIR="${APP_DIR:-/opt/explorer}"
APP_USER="${APP_USER:-explorer}"
BUILD_CACHE="${EXPLORER_BUILD_CACHE:-/var/cache/explorer-build}"
SYSTEMD_DIR="${EXPLORER_SYSTEMD_DIR:-/etc/systemd/system}"
TMPFILES_DIR="${EXPLORER_TMPFILES_DIR:-/etc/tmpfiles.d}"
CLI_TARGET="${EXPLORER_CLI_TARGET:-/usr/local/bin/explorer}"
MOTD_TARGET="${EXPLORER_MOTD_TARGET:-/etc/motd}"
LOCK_FILE="${EXPLORER_UPDATE_LOCK:-/run/lock/explorer-update.lock}"
HEALTH_URL="${EXPLORER_HEALTH_URL:-http://127.0.0.1:8080/health}"
HEALTH_ATTEMPTS="${EXPLORER_HEALTH_ATTEMPTS:-10}"
SERVICE="${EXPLORER_SERVICE:-explorer.service}"

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
[[ -d $SRC_DIR/.git && ! -L $SRC_DIR ]] || die "no real source checkout at $SRC_DIR"
[[ -d $APP_DIR && ! -L $APP_DIR ]] || die "no existing install at $APP_DIR (run bootstrap.sh)"

# This must stay inline. Sourcing a helper before proving the checkout is
# trusted would itself execute checkout-controlled code as root.
require_trusted_checkout() {
  local dir=$1 path owner mode stray
  [[ -d $dir && ! -L $dir ]] || return 1
  path=$(readlink -f -- "$dir") || return 1
  while :; do
    owner=$(stat -c %U "$path") || return 1
    mode=$(stat -c %a "$path") || return 1
    [[ $owner == root ]] || return 1
    (( (8#$mode & 8#022) == 0 )) || return 1
    [[ $path == / ]] && break
    path=$(dirname -- "$path")
  done
  stray=$(find "$(readlink -f -- "$dir")" \
    \( ! -user root -o -perm -g+w -o -perm -o+w -o -type l \) \
    -print -quit 2>/dev/null)
  [[ -z $stray ]]
}
require_trusted_checkout "$SRC_DIR" \
  || die "$SRC_DIR is not exclusively root-owned, non-writable and symlink-free"
# shellcheck disable=SC1091
source "$SRC_DIR/scripts/lib/layout.sh"
layout_require_trusted "$SRC_DIR" || die "untrusted update checkout"

install -d -o root -g root -m 0755 "$(dirname -- "$LOCK_FILE")"
exec 9>"$LOCK_FILE"
flock -n 9 || die "another Explorer update is already running"

trusted_git() {
  git -c safe.directory="$SRC_DIR" -c core.hooksPath=/dev/null \
    -c core.fsmonitor=false -C "$SRC_DIR" "$@"
}

# ── 1. fetch ────────────────────────────────────────────────────────────
step "1/4  Fetching latest"
before_sha=$(trusted_git rev-parse HEAD)

if [[ ${EXPLORER_UPDATE_NO_PULL:-0} == 1 ]]; then
  after_sha=$before_sha
  before_sha=${EXPLORER_UPDATE_BASE_SHA:-$before_sha}
  ok "rebuild-only mode — skipping fetch, building ${after_sha:0:12}"
  say
else
  GIT_TERMINAL_PROMPT=0 trusted_git fetch --quiet origin
  current_branch=$(trusted_git symbolic-ref --quiet --short HEAD || true)
  if [[ -n ${EXPLORER_UPDATE_BRANCH:-} ]]; then
    target_branch=$EXPLORER_UPDATE_BRANCH
  elif [[ -n $current_branch ]]; then
    target_branch=$current_branch
  else
    target_branch=$(trusted_git symbolic-ref --quiet --short refs/remotes/origin/HEAD || true)
    target_branch=${target_branch#origin/}
    [[ -n $target_branch ]] || die "detached checkout has no origin/HEAD; set EXPLORER_UPDATE_BRANCH"
    warn "HEAD is detached — defaulting to '$target_branch'"
  fi
  trusted_git check-ref-format --branch "$target_branch" >/dev/null \
    || die "invalid update branch: $target_branch"
  target_ref="refs/remotes/origin/$target_branch"
  trusted_git show-ref --quiet --verify "$target_ref" \
    || die "origin has no branch named $target_branch"
  after_sha=$(trusted_git rev-parse "$target_ref^{commit}")

  if [[ $before_sha == "$after_sha" ]] \
    && layout_check >/dev/null 2>&1 \
    && layout_revision_matches "$after_sha"; then
    ok "already on ${after_sha:0:12}; installed ownership is healthy"
    exit 0
  fi
  if [[ $before_sha != "$after_sha" ]]; then
    say
    printf '%s  incoming commits:%s\n' "$c_dim" "$c_reset"
    trusted_git --no-pager log --oneline --no-decorate "${before_sha}..${after_sha}" | sed 's/^/    /'
    say
    if [[ ${EXPLORER_UPDATE_YES:-0} != 1 ]]; then
      count=$(trusted_git rev-list --count "${before_sha}..${after_sha}")
      printf '%s?%s Apply %s%d%s commits — %s..%s? %s(y/N)%s ' \
        "$c_cyan" "$c_reset" "$c_bold" "$count" "$c_reset" \
        "${before_sha:0:12}" "${after_sha:0:12}" "$c_dim" "$c_reset"
      read -r answer
      case ${answer,,} in y|yes) ;; *) warn "cancelled"; exit 1 ;; esac
    fi
    if trusted_git show-ref --quiet --verify "refs/heads/$target_branch"; then
      trusted_git checkout --quiet "$target_branch"
      trusted_git merge --ff-only "$target_ref" \
        || die "$target_branch has diverged from origin/$target_branch"
    else
      trusted_git checkout --quiet -b "$target_branch" "$target_ref"
    fi
    require_trusted_checkout "$SRC_DIR" \
      || die "the updated checkout violates the root ownership policy"
    if ! trusted_git diff --quiet "$before_sha" "$after_sha" -- \
      scripts/update.sh scripts/lib/layout.sh; then
      warn "update machinery changed — re-executing the trusted new version"
      exec env EXPLORER_UPDATE_NO_PULL=1 EXPLORER_UPDATE_YES=1 \
        EXPLORER_UPDATE_BASE_SHA="$before_sha" bash "$SRC_DIR/scripts/update.sh"
    fi
  else
    warn "source is current, but the installed ownership is legacy or unhealthy; rebuilding it"
  fi
fi

# Read the env as inert data; never source a service-owned file in a root shell.
ensure_auth_pubkey() {
  local found="" f
  unset AUTH_SIGNING_PUBKEY
  for f in "$APP_DIR/.env.shared" "$APP_DIR/.env"; do
    [[ -e $f || -L $f ]] || continue
    [[ -f $f && ! -L $f && $(stat -c %h "$f") -eq 1 ]] \
      || die "$f must be a single-link regular file"
    layout_read_env "$f"
    [[ -n ${AUTH_SIGNING_PUBKEY:-} ]] && found=$AUTH_SIGNING_PUBKEY
  done
  [[ -n $found ]] && return 0
  warn "AUTH_SIGNING_PUBKEY is unset; authentication cannot work until it is set"
  if [[ -t 0 ]]; then
    printf '%s?%s Paste the auth service public key now (blank to skip): ' "$c_cyan" "$c_reset"
    local pubkey_in; read -r pubkey_in
    if [[ -n $pubkey_in ]]; then
      [[ -f $APP_DIR/.env ]] || install -o "$APP_USER" -g "$APP_USER" -m 0600 /dev/null "$APP_DIR/.env"
      printf 'AUTH_SIGNING_PUBKEY="%s"\n' "$pubkey_in" >> "$APP_DIR/.env"
      chmod 0600 "$APP_DIR/.env"
      ok "AUTH_SIGNING_PUBKEY written to $APP_DIR/.env"
    fi
  fi
}
ensure_auth_pubkey

# ── 2. staging build ────────────────────────────────────────────────────
step "2/4  Building new venv in staging"
STAGING=$(mktemp -d "$(dirname -- "$APP_DIR")/.explorer-build.XXXXXX")
BACKUP=$(mktemp -d "$(dirname -- "$APP_DIR")/.explorer-backup.XXXXXX")
chmod 0700 "$BACKUP"
SWAP_STARTED=0
UPDATE_DONE=0
ROLLBACK_OK=0

SYSTEM_SOURCES=(
  "$SRC_DIR/deploy/systemd/explorer.service"
  "$SRC_DIR/deploy/systemd/explorer-attachment-cleanup.service"
  "$SRC_DIR/deploy/systemd/explorer-attachment-cleanup.timer"
  "$SRC_DIR/deploy/systemd/explorer.tmpfiles.conf"
  "$SRC_DIR/deploy/explorer-cli"
  "$SRC_DIR/deploy/motd"
)
SYSTEM_TARGETS=(
  "$SYSTEMD_DIR/explorer.service"
  "$SYSTEMD_DIR/explorer-attachment-cleanup.service"
  "$SYSTEMD_DIR/explorer-attachment-cleanup.timer"
  "$TMPFILES_DIR/explorer.conf"
  "$CLI_TARGET"
  "$MOTD_TARGET"
)
SYSTEM_MODES=(0644 0644 0644 0644 0755 0644)

snapshot_install() {
  local i target
  install -d -m 0700 "$BACKUP/system"
  for i in "${!SYSTEM_TARGETS[@]}"; do
    target=${SYSTEM_TARGETS[$i]}
    if [[ -e $target || -L $target ]]; then
      [[ -f $target && ! -L $target ]] || die "$target is not a regular file"
      cp -a -- "$target" "$BACKUP/system/$i"
    else
      : > "$BACKUP/system/$i.absent"
    fi
  done
  install -d -m 0700 "$BACKUP/app"
  rsync -a --delete --chown=root:root --chmod=go-w \
    "${LAYOUT_SYNC_EXCLUDES[@]}" "$APP_DIR/" "$BACKUP/app/"
}

restore_install() {
  local failed=0 i target mode
  warn "update failed — restoring the previous install"
  systemctl stop "$SERVICE" >/dev/null 2>&1 || true
  # The old and new revisions commonly contain same-sized files written in
  # the same second. A checksum is required or rsync can leave new content in
  # place while reporting a successful rollback.
  rsync -a --delete --checksum "${LAYOUT_SYNC_EXCLUDES[@]}" \
    "$BACKUP/app/" "$APP_DIR/" || failed=1
  rm -rf "$APP_DIR/.venv" || failed=1
  if [[ -d $BACKUP/venv ]]; then mv "$BACKUP/venv" "$APP_DIR/.venv" || failed=1; fi
  for i in "${!SYSTEM_TARGETS[@]}"; do
    target=${SYSTEM_TARGETS[$i]}; mode=${SYSTEM_MODES[$i]}
    if [[ -f $BACKUP/system/$i ]]; then
      install -o root -g root -m "$mode" "$BACKUP/system/$i" "$target" || failed=1
    elif [[ -f $BACKUP/system/$i.absent ]]; then
      rm -f -- "$target" || failed=1
    fi
  done
  systemctl daemon-reload >/dev/null 2>&1 || failed=1
  systemctl start "$SERVICE" >/dev/null 2>&1 || failed=1
  if (( failed )); then
    warn "automatic rollback was incomplete; preserved root-only backup: $BACKUP"
    return 1
  fi
  warn "previous install restored"
  ROLLBACK_OK=1
}

cleanup_update() {
  local status=$?
  if (( SWAP_STARTED )) && (( ! UPDATE_DONE )); then restore_install || true; fi
  rm -rf "$STAGING"
  if (( UPDATE_DONE )) || (( ! SWAP_STARTED )) || (( ROLLBACK_OK )); then rm -rf "$BACKUP"; fi
  return "$status"
}
trap cleanup_update EXIT

layout_build "$SRC_DIR" "$STAGING" \
  || die "uv build failed — the installed service was not changed"
snapshot_install
ok "staging venv ready"

# ── 3. guarded swap + restart ───────────────────────────────────────────
step "3/4  Swapping in + restarting"
systemctl stop "$SERVICE" || true
if [[ -d $APP_DIR/.venv && ! -L $APP_DIR/.venv ]]; then
  mv "$APP_DIR/.venv" "$BACKUP/venv"
  SWAP_STARTED=1
else
  die "$APP_DIR/.venv is not a real directory"
fi
layout_install_source "$SRC_DIR"
layout_write_revision "$after_sha"
mv "$STAGING/.venv" "$APP_DIR/.venv"
layout_secure_runtime

# Privileged files always come directly from the verified root checkout,
# never from the service-writable venv or any build output.
for i in "${!SYSTEM_TARGETS[@]}"; do
  install -o root -g root -m "${SYSTEM_MODES[$i]}" \
    "${SYSTEM_SOURCES[$i]}" "${SYSTEM_TARGETS[$i]}"
done
systemd-tmpfiles --create "$TMPFILES_DIR/explorer.conf" >/dev/null
if command -v restorecon >/dev/null 2>&1; then
  restorecon -RF "$APP_DIR" "$SRC_DIR" "${SYSTEM_TARGETS[@]}" 2>/dev/null || true
fi
systemctl daemon-reload
systemctl start "$SERVICE"
ok "service restarted"

# ── 4. health check ─────────────────────────────────────────────────────
step "4/4  Health check"
healthy=0
for (( attempt=1; attempt<=HEALTH_ATTEMPTS; attempt++ )); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "$HEALTH_URL" 2>/dev/null || echo 000)
  if [[ $code == 200 ]]; then healthy=1; break; fi
  sleep 1
done
[[ $healthy == 1 ]] || die "explorer did not answer $HEALTH_URL within 10 seconds"
layout_check || die "updated layout failed its ownership check"
ok "explorer /health → $code"
UPDATE_DONE=1
rm -rf "$BACKUP"
trap - EXIT
rm -rf "$STAGING"

say
printf '%s═══════════════════════════════════════════════%s\n' "$c_green" "$c_reset"
printf '%s ✓ Updated %s → %s%s\n' "$c_bold" "${before_sha:0:12}" "${after_sha:0:12}" "$c_reset"
printf '%s═══════════════════════════════════════════════%s\n' "$c_green" "$c_reset"
say
say "  Logs:      ${c_dim}explorer logs${c_reset}"
say "  Roll back: ${c_dim}cd $SRC_DIR && sudo git checkout -B rollback $before_sha && sudo explorer rebuild${c_reset}"
