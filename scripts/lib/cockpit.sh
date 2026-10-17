#!/usr/bin/env bash

# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

# The Vultr Fedora image ships Cockpit's root-capable web login on :9090; our boxes are administered over ssh only.
# Bootstrap only: remove every cockpit package when cockpit-ws is installed.
# EXPLORER_KEEP_COCKPIT=1 skips it; silent without rpm or cockpit; never
# touches firewalld; honours DRY_RUN=1; warns and continues on failure. Uses
# the caller's info/ok/warn.
explorer_cockpit_uninstall() {
  if [[ ${EXPLORER_KEEP_COCKPIT:-0} == 1 ]]; then
    info "EXPLORER_KEEP_COCKPIT=1 — leaving Cockpit installed"
    return 0
  fi
  command -v rpm >/dev/null 2>&1 && rpm -q cockpit-ws >/dev/null 2>&1 || return 0
  if [[ ${DRY_RUN:-0} == 1 ]]; then
    info "[dry-run] dnf -y remove 'cockpit*'"
  elif dnf -y remove 'cockpit*' >/dev/null; then
    ok "removed Cockpit — no web console on :9090"
  else
    warn "could not remove Cockpit — run: dnf -y remove 'cockpit*'"
  fi
  return 0
}
