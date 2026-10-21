#!/usr/bin/env bash

# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

# scripts/bootstrap.sh — install or reconfigure Explorer on Fedora/RHEL 9+.
#
# Verifies this checkout is exclusively root-controlled, installs the Go
# toolchain if needed, builds the explorer binary, and hands over to
# `explorer bootstrap`, which does the rest (packages, service user, .env,
# systemd, optional Caddy + TLS). Safe to re-run: existing .env values are
# kept and only missing ones are asked for.
#
# Usage:
#   sudo bash scripts/bootstrap.sh
#
# Scripted installs pre-answer prompts through the environment, e.g.
#   EXPLORER_AUTH_MODE=central AUTH_SIGNING_PUBKEY=... AUTH_ISSUER_URL=...
#   EXPLORER_PUBLIC_URL=... EXPLORER_BOOTSTRAP_HOSTNAME=...
#   EXPLORER_BOOTSTRAP_SETUP_CADDY=Y EXPLORER_BOOTSTRAP_USE_LETSENCRYPT=Y
#   (EXPLORER_BOOTSTRAP_NON_INTERACTIVE=1 never prompts). See docs/DEPLOYMENT.md.

set -euo pipefail

if [[ ! -t 0 && -t 1 ]]; then exec </dev/tty; fi

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR="${APP_DIR:-/opt/explorer}"

die() { printf '✗ %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root: sudo bash scripts/bootstrap.sh"
[[ -f "$SRC_DIR/go.mod" ]] || die "not an Explorer checkout at $SRC_DIR"

# Deliberately inline: sourcing a helper from an untrusted checkout in order
# to decide whether the checkout is trusted is already root code execution.
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
  || die "$SRC_DIR is not an exclusively root-owned, non-writable, symlink-free checkout"
# shellcheck disable=SC1091
source "$SRC_DIR/scripts/lib/build.sh"

command -v git >/dev/null 2>&1 || dnf install -y git >/dev/null || die "could not install git"
explorer_require_go || die "could not install the Go toolchain (dnf install -y golang)"

parent=$(dirname -- "$APP_DIR")
install -d -m 0755 "$parent"
staging=$(mktemp -d "$parent/.explorer-build.XXXXXX")
trap 'rm -rf "$staging"' EXIT
printf '▸ Building the explorer binary (first build downloads modules; a minute or two)\n'
explorer_build "$SRC_DIR" "$staging/explorer" || die "go build failed — nothing was installed"

"$staging/explorer" bootstrap --source "$SRC_DIR" "$@"
