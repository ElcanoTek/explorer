#!/usr/bin/env bash

# Root-only lifecycle test for the install trust boundary. All state lives in
# one explicit mktemp directory under /var/lib and is removed on exit.

set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "SKIP: layout harness requires root"; exit 0; }

REPO=$(cd "$(dirname "$0")/../.." && pwd)
BASE=$(mktemp -d /var/lib/explorer-layout-test.XXXXXX)
trap 'rm -rf "$BASE"' EXIT
SRC=$BASE/source
APP=$BASE/app
BIN=$BASE/bin
SYSTEMD=$BASE/systemd
TMPFILES=$BASE/tmpfiles
CLI=$BASE/usr-local-bin/explorer
MOTD=$BASE/motd
CACHE=$BASE/cache
LOCK=$BASE/update.lock
LOG=$BASE/systemctl.log
TEST_USER=daemon
CHECKS=0

[[ $(id -gn "$TEST_USER") == "$TEST_USER" ]] || {
  echo "FAIL: harness needs the standard daemon:daemon service account" >&2
  exit 1
}

pass() { CHECKS=$((CHECKS + 1)); }
assert() { "$@" || { echo "FAIL: $*" >&2; exit 1; }; pass; }
assert_eq() {
  [[ $1 == "$2" ]] || { echo "FAIL: expected '$2', got '$1'" >&2; exit 1; }
  pass
}

install -d -o root -g root -m 0755 "$SRC" "$APP" "$BIN" "$SYSTEMD" "$TMPFILES" "$(dirname "$CLI")"
rsync -a --chown=root:root --chmod=go-w --exclude='/.git' --exclude='/.venv' "$REPO/" "$SRC/"
git -C "$SRC" init -q
git -C "$SRC" config user.email test@example.invalid
git -C "$SRC" config user.name Test
git -C "$SRC" add -A
git -C "$SRC" commit -qm fixture

cat > "$BIN/uv" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case $1 in
  venv)
    install -d "$2/bin"
    printf '#!/bin/sh\nexit 0\n' > "$2/bin/python"
    chmod 0755 "$2/bin/python"
    ;;
  pip)
    # A dependency build can write inside the venv, but nowhere root trusts.
    python_path=''
    while (($#)); do
      [[ $1 == --python ]] && { python_path=$2; break; }
      shift
    done
    printf 'service-controlled\n' > "$(dirname "$python_path")/build-marker"
    ;;
  *) exit 2 ;;
esac
EOF
cat > "$BIN/systemctl" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> '$LOG'
exit 0
EOF
cat > "$BIN/systemd-tmpfiles" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat > "$BIN/restorecon" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat > "$BIN/curl" <<'EOF'
#!/usr/bin/env bash
printf '%s' "${HARNESS_HEALTH_CODE:-200}"
EOF
chmod 0755 "$BIN"/*

seed_legacy() {
  rm -rf "$APP"
  install -d -o "$TEST_USER" -g "$TEST_USER" -m 0755 "$APP/app" "$APP/.venv/bin" "$APP/.tmp"
  printf 'old-app\n' > "$APP/app/old-marker"
  printf 'old-venv\n' > "$APP/.venv/bin/old-marker"
  printf 'SECRET="kept"\n' > "$APP/.env"
  chown -R "$TEST_USER:$TEST_USER" "$APP"
  chmod 0600 "$APP/.env"
  for target in "$SYSTEMD/explorer.service" \
    "$SYSTEMD/explorer-attachment-cleanup.service" \
    "$SYSTEMD/explorer-attachment-cleanup.timer" "$TMPFILES/explorer.conf" "$CLI" "$MOTD"; do
    install -D -o root -g root -m 0644 /dev/null "$target"
    printf 'old-privileged\n' > "$target"
  done
  chmod 0755 "$CLI"
}

run_update() {
  env PATH="$BIN:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    SRC_DIR="$SRC" APP_DIR="$APP" APP_USER="$TEST_USER" \
    EXPLORER_BUILD_CACHE="$CACHE" EXPLORER_UV_BIN="$BIN/uv" \
    EXPLORER_SYSTEMD_DIR="$SYSTEMD" EXPLORER_TMPFILES_DIR="$TMPFILES" \
    EXPLORER_CLI_TARGET="$CLI" EXPLORER_MOTD_TARGET="$MOTD" \
    EXPLORER_UPDATE_LOCK="$LOCK" EXPLORER_UPDATE_NO_PULL=1 \
    EXPLORER_UPDATE_YES=1 EXPLORER_HEALTH_ATTEMPTS=1 \
    HARNESS_HEALTH_CODE="${1:-200}" \
    bash "$SRC/scripts/update.sh"
}

seed_legacy
run_update 200 >/dev/null
assert_eq "$(stat -c '%U:%G %a' "$APP")" "root:root 755"
assert_eq "$(stat -c %U "$APP/app")" root
assert_eq "$(stat -c '%U:%G %a' "$APP/.env")" "$TEST_USER:$TEST_USER 600"
assert_eq "$(stat -c %U "$APP/.venv")" "$TEST_USER"
REVISION=$(git -C "$SRC" rev-parse HEAD)
assert_eq "$(cat "$APP/.explorer-revision")" "$REVISION"
assert test -f "$APP/.venv/bin/build-marker"
assert cmp -s "$CLI" "$SRC/deploy/explorer-cli"
assert cmp -s "$SYSTEMD/explorer.service" "$SRC/deploy/systemd/explorer.service"
assert test ! -e "$APP/app/old-marker"
if runuser -u "$TEST_USER" -- touch "$APP/app/service-write" 2>/dev/null; then
  echo "FAIL: service user can modify installed source" >&2
  exit 1
fi
pass
assert test -z "$(find "$BASE" -maxdepth 1 -name '.explorer-backup.*' -print -quit)"

# A legacy process could change bytes while preserving size and mtime. The
# canonical source must still replace that content during migration/rebuild.
printf 'X' | dd of="$APP/requirements.txt" bs=1 seek=0 conv=notrunc status=none
touch -r "$SRC/requirements.txt" "$APP/requirements.txt"
if cmp -s "$SRC/requirements.txt" "$APP/requirements.txt"; then
  echo "FAIL: same-size install fixture did not differ" >&2
  exit 1
fi
pass
run_update 200 >/dev/null
assert cmp -s "$SRC/requirements.txt" "$APP/requirements.txt"

# A source tree the service can alter is rejected before a build or swap.
chmod g+w "$SRC"
if run_update 200 >/dev/null 2>&1; then
  echo "FAIL: group-writable source was accepted" >&2
  exit 1
fi
pass
chmod g-w "$SRC"

ln -s requirements.txt "$SRC/service-link"
if run_update 200 >/dev/null 2>&1; then
  echo "FAIL: source symlink was accepted" >&2
  exit 1
fi
pass
rm "$SRC/service-link"

# A post-swap health failure restores source, venv, privileged files and env.
cp -a "$APP" "$BASE/expected-app"
cp -a "$CLI" "$BASE/expected-cli"
printf 'new-but-unhealthy\n' > "$SRC/app/layout-harness-marker"
git -C "$SRC" add app/layout-harness-marker
git -C "$SRC" commit -qm unhealthy-fixture
NEW_REVISION=$(git -C "$SRC" rev-parse HEAD)
if run_update 500 >/dev/null 2>&1; then
  echo "FAIL: unhealthy update succeeded" >&2
  exit 1
fi
pass
assert diff -qr "$BASE/expected-app" "$APP"
assert cmp -s "$BASE/expected-cli" "$CLI"
assert test ! -e "$APP/app/layout-harness-marker"
assert_eq "$(cat "$APP/.explorer-revision")" "$REVISION"
assert test "$REVISION" != "$NEW_REVISION"
assert test -z "$(find "$BASE" -maxdepth 1 -name '.explorer-backup.*' -print -quit)"

printf 'layout harness: %d checks passed\n' "$CHECKS"
