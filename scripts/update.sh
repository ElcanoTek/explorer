#!/usr/bin/env bash

# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

# scripts/update.sh — bridge into the Go updater.
#
# `explorer update` is implemented in the explorer binary. This script
# exists for two callers:
#   * a box still running the Python-era bash CLI or an older Go binary:
#     its update fetches, fast-forwards, sees this file changed, and
#     re-executes it with EXPLORER_UPDATE_NO_PULL=1 EXPLORER_UPDATE_YES=1
#     EXPLORER_UPDATE_BASE_SHA;
#   * an operator recovering a box whose binary is missing or broken:
#       sudo bash /opt/explorer-src/scripts/update.sh
#
# By default, it fetches tags from origin, resolves the latest published
# release tag (or --tag v...), verifies SHA256SUMS (+ .sigstore.json),
# release.json (matching tag and commit), and explorer-linux-${arch}
# (+ .sigstore.json) with the pinned cosign in cosign.lock, checks out the tag
# in /opt/explorer-src, and hands over to the verified binary's `update` —
# without requiring `go` on the box. Pass --from-source (or
# EXPLORER_FROM_SOURCE=1) to compile from source with Go instead.

set -euo pipefail

SRC_DIR="${SRC_DIR:-${EXPLORER_SRC_DIR:-/opt/explorer-src}}"
APP_DIR="${APP_DIR:-${EXPLORER_APP_DIR:-/opt/explorer}}"
COSIGN_CACHE="${EXPLORER_COSIGN_CACHE:-${EXPLORER_BUILD_CACHE:-/var/cache/explorer-build}/cosign}"

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
# shellcheck disable=SC1091
source "$SRC_DIR/scripts/lib/release.sh"

# The Python-era update.sh held its flock on fd 9 and exec'd us with it
# open; the Go updater takes the same lock and must not find it held.
{ exec 9>&-; } 2>/dev/null || true

from_source=0
case "${EXPLORER_FROM_SOURCE:-${EXPLORER_UPDATE_FROM_SOURCE:-}}" in
  1|true|TRUE|yes|YES|on|ON) from_source=1 ;;
esac
no_pull=0
[[ "${EXPLORER_UPDATE_NO_PULL:-0}" == "1" ]] && no_pull=1
release_tag="${EXPLORER_RELEASE_TAG:-${EXPLORER_UPDATE_TAG:-}}"

forward_args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --from-source)
      from_source=1
      forward_args+=("$1")
      shift
      ;;
    --artifact)
      from_source=0
      forward_args+=("$1")
      shift
      ;;
    --no-pull)
      no_pull=1
      forward_args+=("$1")
      shift
      ;;
    --tag)
      [[ $# -ge 2 ]] || die "--tag requires a release tag (vYYYY.MM.DD.N)"
      release_tag="$2"
      forward_args+=("$1" "$2")
      shift 2
      ;;
    --tag=*)
      release_tag="${1#--tag=}"
      forward_args+=("$1")
      shift
      ;;
    *)
      forward_args+=("$1")
      shift
      ;;
  esac
done

parent=$(dirname -- "$APP_DIR")
install -d -m 0755 "$parent"
staging=$(mktemp -d "$parent/.explorer-bridge.XXXXXX")
chmod 0700 "$staging"
trap 'rm -rf "$staging"' EXIT

if [[ $from_source -eq 1 ]]; then
  explorer_require_go || die "could not install the Go toolchain (dnf install -y golang)"
  printf '▸ Building the explorer binary from %s\n' "$SRC_DIR"
  explorer_build "$SRC_DIR" "$staging/explorer" || die "go build failed — the installed service was not changed"
  EXPLORER_SRC_DIR="$SRC_DIR" EXPLORER_APP_DIR="$APP_DIR" EXPLORER_FROM_SOURCE=1 \
    "$staging/explorer" update "${forward_args[@]}"
  exit 0
fi

command -v curl >/dev/null 2>&1 || dnf install -y curl ca-certificates >/dev/null || die "could not install curl"

git_safe() {
  git -c safe.directory="$SRC_DIR" -c core.hooksPath=/dev/null -c core.fsmonitor=false \
    -c gc.auto=0 -c maintenance.auto=false -C "$SRC_DIR" "$@"
}

before="${EXPLORER_UPDATE_BASE_SHA:-$(git_safe rev-parse HEAD)}"
if [[ $no_pull -eq 0 ]]; then
  printf '▸ Fetching release tags from origin\n'
  git_safe fetch --quiet --force --tags origin || die "git fetch --tags origin failed"
fi

if [[ -z $release_tag ]]; then
  if [[ $no_pull -eq 1 ]]; then
    release_tag="$("$SRC_DIR/scripts/version.sh" released-at HEAD)"
    [[ -n $release_tag ]] || die "HEAD is not at a release tag; pass --tag vYYYY.MM.DD.N or --from-source"
  else
    release_tag="$(explorer_release_latest_tag)" || die "could not resolve the latest published Explorer release"
  fi
fi

commit="$(git_safe rev-parse "refs/tags/${release_tag}^{commit}" 2>/dev/null)" \
  || die "release tag ${release_tag} does not exist in $SRC_DIR"

printf '▸ Downloading and verifying signed release %s (%s)\n' "$release_tag" "${commit:0:12}"
verified_bin="$(explorer_release_fetch "$SRC_DIR" "$release_tag" "$staging/release" "$COSIGN_CACHE" "$commit")" \
  || die "release verification failed for ${release_tag} — the installed service was not changed"

git_safe checkout --detach --quiet "$commit" || die "could not check out ${release_tag} in $SRC_DIR"
require_trusted_checkout "$SRC_DIR" \
  || die "the checked-out release tree at $SRC_DIR violates the root ownership policy"

EXPLORER_SRC_DIR="$SRC_DIR" EXPLORER_APP_DIR="$APP_DIR" \
  EXPLORER_COSIGN_CACHE="$COSIGN_CACHE" \
  EXPLORER_UPDATE_BASE_SHA="$before" \
  EXPLORER_RELEASE_STAGING="$staging/release" \
  "$verified_bin" update --no-pull --tag "$release_tag" "${forward_args[@]}"
