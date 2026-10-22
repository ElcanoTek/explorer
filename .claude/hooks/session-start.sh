#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.
#
# Claude Code cloud sessions: make `go test`, golangci-lint (the version CI
# pins), shellcheck, the JS unit tests and stack-check runnable. Synchronous,
# idempotent, non-interactive; a no-op on a laptop.
set -euo pipefail

[ "${CLAUDE_CODE_REMOTE:-}" = "true" ] || exit 0

GOLANGCI_VERSION=v2.14.0 # keep in step with .github/workflows/ci.yml
cd "${CLAUDE_PROJECT_DIR:-$(dirname "$0")/../..}"

# go.mod pins an exact toolchain; let the go command fetch it.
export GOTOOLCHAIN=auto
go mod download

gobin="$(go env GOPATH)/bin"
if ! "$gobin/golangci-lint" --version 2>/dev/null | grep -q "version ${GOLANGCI_VERSION#v} "; then
  go install "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_VERSION}"
fi

# Later commands in this session find the pinned linter first.
if [ -n "${CLAUDE_ENV_FILE:-}" ] && ! grep -qs "^export PATH=\"$gobin:" "$CLAUDE_ENV_FILE"; then
  echo "export PATH=\"$gobin:\$PATH\"" >> "$CLAUDE_ENV_FILE"
  echo "export GOTOOLCHAIN=auto" >> "$CLAUDE_ENV_FILE"
fi

if ! command -v shellcheck >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq shellcheck >/dev/null || echo "session-start: shellcheck unavailable" >&2
  fi
fi
command -v node >/dev/null 2>&1 || echo "session-start: node not found; make test-js will not run" >&2

echo "session-start: go modules, golangci-lint ${GOLANGCI_VERSION} ready"
