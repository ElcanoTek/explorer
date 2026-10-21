#!/usr/bin/env bash

# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

# scripts/update.sh — bridge into the Go updater.
#
# `explorer update` is implemented in the explorer binary. This script
# exists for two callers:
#   * a box still running the Python-era bash CLI: its update.sh fetches,
#     fast-forwards, sees this file changed, and re-executes it with
#     EXPLORER_UPDATE_NO_PULL=1 EXPLORER_UPDATE_YES=1 EXPLORER_UPDATE_BASE_SHA;
#   * an operator recovering a box whose binary is missing or broken:
#       sudo bash /opt/explorer-src/scripts/update.sh
# It verifies the checkout, builds the binary from it, and runs that
# binary's `update` (which honours the same environment variables).

set -euo pipefail

SRC_DIR="${SRC_DIR:-${EXPLORER_SRC_DIR:-/opt/explorer-src}}"
APP_DIR="${APP_DIR:-${EXPLORER_APP_DIR:-/opt/explorer}}"

die() { printf '✗ %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root: sudo bash scripts/update.sh"
[[ -d $SRC_DIR/.git && ! -L $SRC_DIR ]] || die "no real source checkout at $SRC_DIR"

# This must stay inline: sourcing a helper before proving the checkout is
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
source "$SRC_DIR/scripts/lib/build.sh"

# The Python-era update.sh held its flock on fd 9 and exec'd us with it
# open; the Go updater takes the same lock and must not find it held.
{ exec 9>&-; } 2>/dev/null || true

explorer_require_go || die "could not install the Go toolchain (dnf install -y golang)"

parent=$(dirname -- "$APP_DIR")
staging=$(mktemp -d "$parent/.explorer-bridge.XXXXXX")
trap 'rm -rf "$staging"' EXIT
printf '▸ Building the explorer binary from %s\n' "$SRC_DIR"
explorer_build "$SRC_DIR" "$staging/explorer" || die "go build failed — the installed service was not changed"

EXPLORER_SRC_DIR="$SRC_DIR" EXPLORER_APP_DIR="$APP_DIR" "$staging/explorer" update "$@"
