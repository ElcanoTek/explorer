#!/usr/bin/env bash

# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

# scripts/bootstrap.sh — install or reconfigure Explorer on Fedora/RHEL 9+.
#
# Verifies this checkout is exclusively root-controlled, downloads and verifies
# the signed Explorer release binary (or, with --from-source /
# EXPLORER_FROM_SOURCE=1, installs Go and compiles from source), and hands over
# to `explorer bootstrap`, which does the rest (packages, service user, .env,
# systemd, optional Caddy + TLS). Safe to re-run: existing .env values are
# kept and only missing ones are asked for.
#
# Usage:
#   sudo bash scripts/bootstrap.sh [--tag vYYYY.MM.DD.N] [--from-source]
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
COSIGN_CACHE="${EXPLORER_COSIGN_CACHE:-${EXPLORER_BUILD_CACHE:-/var/cache/explorer-build}/cosign}"

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
# shellcheck disable=SC1091
source "$SRC_DIR/scripts/lib/release.sh"

from_source=0
case "${EXPLORER_FROM_SOURCE:-${EXPLORER_UPDATE_FROM_SOURCE:-}}" in
  1|true|TRUE|yes|YES|on|ON) from_source=1 ;;
esac
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

command -v git >/dev/null 2>&1 || dnf install -y git >/dev/null || die "could not install git"

parent=$(dirname -- "$APP_DIR")
install -d -m 0755 "$parent"
staging=$(mktemp -d "$parent/.explorer-build.XXXXXX")
chmod 0700 "$staging"
trap 'rm -rf "$staging"' EXIT

git_safe() {
  git -c safe.directory="$SRC_DIR" -c core.hooksPath=/dev/null -c core.fsmonitor=false \
    -c gc.auto=0 -c maintenance.auto=false -C "$SRC_DIR" "$@"
}

if [[ $from_source -eq 1 ]]; then
  if [[ -n $release_tag ]]; then
    if ! commit="$(git_safe rev-parse --verify --quiet "refs/tags/${release_tag}^{commit}")"; then
      git_safe fetch --quiet --force --tags origin || die "git fetch --tags origin failed"
      commit="$(git_safe rev-parse --verify --quiet "refs/tags/${release_tag}^{commit}")" \
        || die "release tag ${release_tag} does not exist in $SRC_DIR"
    fi
    git_safe checkout --detach --quiet "$commit" || die "could not check out ${release_tag} in $SRC_DIR"
    require_trusted_checkout "$SRC_DIR" \
      || die "the checked-out release tree at $SRC_DIR violates the root ownership policy"
  fi
  explorer_require_go || die "could not install the Go toolchain (dnf install -y golang)"
  printf '▸ Building the explorer binary (first build downloads modules; a minute or two)\n'
  explorer_build "$SRC_DIR" "$staging/explorer" || die "go build failed — nothing was installed"
  EXPLORER_FROM_SOURCE=1 "$staging/explorer" bootstrap --source "$SRC_DIR" "${forward_args[@]}"
  exit 0
fi

command -v curl >/dev/null 2>&1 || dnf install -y curl ca-certificates >/dev/null || die "could not install curl"

min_tag="$(git_safe tag --merged HEAD --list 'v*' | "$SRC_DIR/scripts/version.sh" filter | tail -n 1 || true)"
printf '▸ Fetching release tags from origin\n'
git_safe fetch --quiet --force --tags origin || die "git fetch --tags origin failed"

if [[ -z $release_tag ]]; then
  release_tag="$(explorer_release_latest_tag)" || die "could not resolve the latest published Explorer release"
  if [[ -n $min_tag ]] && explorer_release_older "$release_tag" "$min_tag"; then
    min_commit="$(git_safe rev-parse --verify --quiet "refs/tags/${min_tag}^{commit}" || true)"
    if [[ -n $min_commit ]] && explorer_release_verify_manifest "$SRC_DIR" "$min_tag" "$min_commit" "$COSIGN_CACHE" 2>/dev/null; then
      die "latest release ${release_tag} is older than the checkout's published release ${min_tag} — pass --tag ${release_tag} to install an older release on purpose"
    fi
  fi
fi

commit="$(git_safe rev-parse "refs/tags/${release_tag}^{commit}" 2>/dev/null)" \
  || die "release tag ${release_tag} does not exist in $SRC_DIR"

printf '▸ Downloading and verifying signed release %s (%s)\n' "$release_tag" "${commit:0:12}"
verified_bin="$(explorer_release_fetch "$SRC_DIR" "$release_tag" "$staging/release" "$COSIGN_CACHE" "$commit")" \
  || die "release verification failed for ${release_tag} — nothing was installed"

git_safe checkout --detach --quiet "$commit" || die "could not check out ${release_tag} in $SRC_DIR"
require_trusted_checkout "$SRC_DIR" \
  || die "the checked-out release tree at $SRC_DIR violates the root ownership policy"

EXPLORER_COSIGN_CACHE="$COSIGN_CACHE" \
  EXPLORER_RELEASE_STAGING="$staging/release" \
  "$verified_bin" bootstrap --source "$SRC_DIR" --tag "$release_tag" "${forward_args[@]}"
