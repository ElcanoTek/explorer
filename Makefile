# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

# GOTOOLCHAIN=auto: go.mod pins an exact patch release, and Fedora's golang
# package ships GOTOOLCHAIN=local, which would turn "older distro Go" into a
# hard failure instead of a toolchain download.
GOTOOLCHAIN ?= auto
export GOTOOLCHAIN

REVISION := $(shell git rev-parse HEAD 2>/dev/null)
LDFLAGS := -X github.com/ElcanoTek/explorer/internal/version.revision=$(REVISION)

.PHONY: all build test test-race test-root lint fmt vet vulncheck run ci clean

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

vet:
	go vet ./...

lint:
	golangci-lint run
	shellcheck -S warning $$(git ls-files '*.sh')

fmt:
	gofmt -w .

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Local development server: reads ./.env (copy .env.example). Development
# only: plain HTTP needs EXPLORER_UI_COOKIE_SECURE=0.
run: build
	./explorer serve

ci: vet lint test-race vulncheck

clean:
	rm -f ./explorer
