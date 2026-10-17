#!/usr/bin/env bash

# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

# Keep the Cockpit web console off. The Vultr Fedora image ships cockpit, and
# cockpit.socket serves a root-capable web login on :9090 on a box whose only
# admin path is ssh. bootstrap.sh runs this on a new box and update.sh on every
# update, so an existing box stays healed (mirrors keel's step_cockpit).
#
# Safe on any host: does nothing (one line) unless systemd has a cockpit.socket
# unit; blanks cockpit's login-banner notice; touches the firewall only when firewalld is running and a zone lists
# cockpit; never installs or removes packages, never touches ufw/iptables, and
# never fails the caller. Idempotent: a masked socket is left alone. With
# DRY_RUN=1 it prints the commands instead. Uses the caller's say/ok/warn.

# Masking leaves cockpit's login-banner notice ("Activate the web console
# with: ...") in the MOTD: /etc/motd.d/cockpit links to /run/cockpit/issue,
# which the package's tmpfiles.d entry recreates at boot. A same-named
# /etc/tmpfiles.d copy overrides it and survives cockpit-ws upgrades. The
# source is the trusted root-owned checkout's deploy/ file. Overridable for
# the tests only; pure bash so sourcing never needs PATH.
EXPLORER_COCKPIT_PKG_TMPFILES=${EXPLORER_COCKPIT_PKG_TMPFILES:-/usr/lib/tmpfiles.d/cockpit-ws.conf}
EXPLORER_COCKPIT_ETC_TMPFILES=${EXPLORER_COCKPIT_ETC_TMPFILES:-/etc/tmpfiles.d/cockpit-ws.conf}
_explorer_lib_dir=${BASH_SOURCE[0]%/*}
[[ ${BASH_SOURCE[0]} == */* ]] || _explorer_lib_dir=.
EXPLORER_COCKPIT_TMPFILES_SRC=$_explorer_lib_dir/../../deploy/cockpit-ws.tmpfiles.conf
unset _explorer_lib_dir

_explorer_cockpit_do() {
  if [[ ${DRY_RUN:-0} == 1 ]]; then say "  [dry-run] $*"; else "$@"; fi
}

_explorer_cockpit_banner() {
  local src=$EXPLORER_COCKPIT_TMPFILES_SRC dst=$EXPLORER_COCKPIT_ETC_TMPFILES
  [[ -f $EXPLORER_COCKPIT_PKG_TMPFILES ]] || return 0
  command -v systemd-tmpfiles >/dev/null 2>&1 || return 0
  if cmp -s "$src" "$dst"; then
    ok "cockpit's login-banner notice already blank ($dst)"
  elif [[ ! -f $src || -L $src ]]; then
    warn "missing $src — cockpit's login-banner notice stays"
  elif _explorer_cockpit_do install -D -m 0644 "$src" "$dst" \
    && _explorer_cockpit_do systemd-tmpfiles --create "$dst"; then
    [[ ${DRY_RUN:-0} == 1 ]] || ok "blanked cockpit's login-banner notice ($dst)"
  else
    warn "could not blank cockpit's login-banner notice — run: install -m 0644 $src $dst && systemd-tmpfiles --create $dst"
  fi
  return 0
}

explorer_cockpit_off() {
  local zone zones="" services fw_failed=0
  if ! command -v systemctl >/dev/null 2>&1 \
    || [[ -z $(systemctl list-unit-files cockpit.socket --no-legend 2>/dev/null) ]]; then
    say "  cockpit is not installed — no web console to turn off"
    return 0
  fi
  if [[ $(systemctl is-enabled cockpit.socket 2>/dev/null || true) == masked* ]]; then
    ok "cockpit.socket already masked — no web console on :9090"
  elif _explorer_cockpit_do systemctl disable --now cockpit.socket \
    && _explorer_cockpit_do systemctl mask cockpit.socket; then
    [[ ${DRY_RUN:-0} == 1 ]] || ok "cockpit.socket disabled, stopped and masked — no web console on :9090"
  else
    warn "could not turn cockpit off — run: systemctl disable --now cockpit.socket && systemctl mask cockpit.socket"
  fi
  _explorer_cockpit_banner
  command -v firewall-cmd >/dev/null 2>&1 || return 0
  [[ $(firewall-cmd --state 2>/dev/null || true) == running ]] || return 0
  for zone in $(firewall-cmd --permanent --get-zones 2>/dev/null || true); do
    # Captured, not piped into grep -q: under pipefail an early grep exit can
    # SIGPIPE the writer and turn a match into a miss.
    services=$(firewall-cmd --permanent --zone="$zone" --list-services 2>/dev/null || true)
    [[ " $services " == *" cockpit "* ]] || continue
    zones+="$zone "
    _explorer_cockpit_do firewall-cmd -q --permanent --zone="$zone" --remove-service=cockpit || fw_failed=1
  done
  [[ -n $zones ]] || return 0
  _explorer_cockpit_do firewall-cmd -q --reload || fw_failed=1
  if [[ $fw_failed == 1 ]]; then
    warn "could not remove cockpit from firewalld (zones: ${zones% }) — run: firewall-cmd --permanent --zone=<zone> --remove-service=cockpit && firewall-cmd --reload"
  elif [[ ${DRY_RUN:-0} != 1 ]]; then
    ok "removed the cockpit service from firewalld (zones: ${zones% })"
  fi
  return 0
}
