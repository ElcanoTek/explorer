# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

# GOTOOLCHAIN=auto: go.mod pins an exact patch release, and Fedora's golang
# package ships GOTOOLCHAIN=local, which would turn "older distro Go" into a
# hard failure instead of a toolchain download.
GOTOOLCHAIN ?= auto
export GOTOOLCHAIN

REVISION := $(shell git rev-parse HEAD 2>/dev/null)
LDFLAGS := -X github.com/ElcanoTek/explorer/internal/version.revision=$(REVISION)

.PHONY: all build test test-race test-root test-js lint fmt vet vulncheck stack-check flag-status run ci clean

all: build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o ./explorer ./cmd/explorer

test:
	go test ./...

test-race:
	go test -race -count=1 ./...

# The install lifecycle harness needs root (ownership and mode assertions).
test-root:
	sudo env "PATH=$$PATH" "GOCACHE=$$(go env GOCACHE)" "GOMODCACHE=$$(go env GOMODCACHE)" go test -count=1 -run 'TestLifecycle|TestRequireTrusted|TestProvisionWritesPrivateFiles' ./internal/ops/

# The date picker and range arithmetic (plain JS) under Node's built-in runner.
test-js:
	node --test internal/web/jstest/*.test.js

vet:
	go vet ./...

lint:
	golangci-lint run
	shellcheck -S warning $$(git ls-files '*.sh')

fmt:
	gofmt -w .

# The Elcano frontend standard (AGENTS.md): standard block, flag.lock, no CDNs.
stack-check:
	scripts/stack-check.sh

# Vendored Flag files vs a sibling ../flag checkout (FLAG_DIR=... to override).
flag-status:
	scripts/flag-sync.sh status $(FLAG_DIR)

# govulncheck must be built with the toolchain go.mod selects: with plain
# GOTOOLCHAIN=auto the go command builds it with the older toolchain x/vuln
# itself asks for, which then cannot load this module's packages.
vulncheck:
	GOTOOLCHAIN=$$(go env GOVERSION) go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Local development server: reads ./.env (copy .env.example). Development
# only: plain HTTP needs EXPLORER_UI_COOKIE_SECURE=0.
run: build
	./explorer serve

ci: stack-check vet lint test-race test-js vulncheck

clean:
	rm -f ./explorer
