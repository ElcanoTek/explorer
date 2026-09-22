#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.
set -euo pipefail
exec python3 "$(dirname "${BASH_SOURCE[0]}")/doctor.py" "$@"
