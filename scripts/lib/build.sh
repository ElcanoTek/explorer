#!/usr/bin/env bash

# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

# Build the explorer binary from a verified, root-owned checkout. Sourced by
# scripts/bootstrap.sh and scripts/update.sh only AFTER their inline trust
# check: sourcing from an unverified tree would itself be root code
# execution. The Go side (internal/ops/build.go) builds the same way.

# explorer_require_go — install the Go toolchain when it is missing.
explorer_require_go() {
  if command -v go >/dev/null 2>&1 || [[ -x /usr/local/go/bin/go ]]; then
    return 0
  fi
  command -v dnf >/dev/null 2>&1 || { echo "the Go toolchain is missing and dnf is not available" >&2; return 1; }
  dnf install -y golang >/dev/null || return 1
}

# explorer_build SRC OUT — compile SRC/cmd/explorer into OUT, stamped with
# SRC's HEAD. Root-owned caches, a clean environment (no GOFLAGS or go.work
# from the caller), no cgo, no VCS probing by the toolchain.
explorer_build() {
  local src=$1 out=$2 cache="${EXPLORER_BUILD_CACHE:-/var/cache/explorer-build}" rev owner mode
  rev=$(git -c safe.directory="$src" -c core.hooksPath=/dev/null -c core.fsmonitor=false \
    -C "$src" rev-parse 'HEAD^{commit}') || return 1
  [[ $rev =~ ^[0-9a-f]{40,64}$ ]] || { echo "invalid source revision: $rev" >&2; return 1; }
  # A cache the service account could write (the Python era's uv cache was
  # the service user's) is discarded: module caches are not re-verified.
  if [[ -e $cache || -L $cache ]]; then
    owner=$(stat -c %u "$cache") mode=$(stat -c %a "$cache")
    if [[ -L $cache || ! -d $cache || $owner != 0 ]] || (( (8#$mode & 8#077) != 0 )); then
      rm -rf -- "$cache"
    fi
  fi
  install -d -o root -g root -m 0700 "$cache" || return 1
  local -a passthrough=()
  local name
  for name in HTTPS_PROXY HTTP_PROXY NO_PROXY https_proxy http_proxy no_proxy SSL_CERT_FILE SSL_CERT_DIR GOPROXY GOSUMDB GOPRIVATE; do
    [[ -n ${!name:-} ]] && passthrough+=("$name=${!name}")
  done
  env -i -C "$src" \
    PATH=/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin \
    HOME="$cache" GOPATH="$cache/gopath" GOMODCACHE="$cache/mod" GOCACHE="$cache/go-build" \
    GOTOOLCHAIN=auto GOFLAGS=-mod=readonly CGO_ENABLED=0 GOWORK=off GOENV=off GOTELEMETRY=off \
    "${passthrough[@]}" \
    go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X github.com/ElcanoTek/explorer/internal/version.revision=$rev" \
      -o "$out" ./cmd/explorer || return 1
  chmod 0755 "$out"
}
