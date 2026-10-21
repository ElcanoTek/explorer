#!/usr/bin/env bash

# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

# Compatibility shim: doctor lives in the explorer binary (`explorer doctor`).
set -euo pipefail
bin="${EXPLORER_APP_DIR:-${APP_DIR:-/opt/explorer}}/bin/explorer"
if [[ ! -x $bin ]]; then
  echo "explorer is not installed at $bin — run: sudo bash /opt/explorer-src/scripts/update.sh" >&2
  exit 1
fi
exec "$bin" doctor "$@"
