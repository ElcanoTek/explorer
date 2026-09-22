#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.
# Public entry point. Bash parses the complete function before installation;
# a truncated download cannot execute a partial function. Prompts use the TTY.
set -euo pipefail
main() {
  if [[ "${1:-}" == --help ]]; then
    echo 'Usage: sudo bash install.sh [--help] (installs main into /opt/explorer-src)'
    exit 0
  fi
  [[ $# == 0 ]] || { echo 'Unknown argument; try --help' >&2; exit 2; }
  [[ $EUID == 0 ]] || { echo 'Run with sudo bash install.sh' >&2; exit 1; }
  command -v dnf >/dev/null || { echo 'Fedora/RHEL with dnf is required' >&2; exit 1; }
  local src="${EXPLORER_SRC_DIR:-/opt/explorer-src}"
  if [[ -e "$src" ]]; then
    echo "$src already exists. Use explorer update, or run its scripts/bootstrap.sh to reconfigure." >&2
    exit 1
  fi
  dnf install -y git ca-certificates
  # Clone beside the target (same filesystem, so the final mv is atomic)
  # and clean the partial clone up on failure: otherwise an interrupted
  # first run leaves $src behind and every retry stops at the existence
  # check, recommending an `explorer update` that was never installed.
  local tmp
  tmp="$(mktemp -d "$(dirname -- "$src")/.explorer-install.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  git clone --branch main --single-branch https://github.com/ElcanoTek/explorer.git "$tmp/repo"
  mv "$tmp/repo" "$src"
  rmdir "$tmp"
  trap - EXIT
  exec bash "$src/scripts/bootstrap.sh"
}
main "$@"
