// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

// Package version reports the source revision a binary was built from.
//
// The installer stamps the full commit it verified into the binary with
//
//	go build -ldflags "-X github.com/ElcanoTek/explorer/internal/version.revision=<sha>"
//
// (scripts/lib/build.sh and internal/ops/build.go), so `explorer version`,
// the installed-revision marker and doctor all agree on one value. A plain
// `go build` falls back to the toolchain's embedded VCS stamp, or "unknown".
package version

import "runtime/debug"

// revision is overridden at link time; a var, not a const, for that reason.
var revision = ""

// Revision returns the full commit hash the binary was built from, with a
// "+dirty" suffix for an unstamped build of a modified tree, or "unknown".
func Revision() string {
	if revision != "" {
		return revision
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	rev, dirty := "", false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return "unknown"
	}
	if dirty {
		rev += "+dirty"
	}
	return rev
}

// Short is the first 12 characters of Revision.
func Short() string {
	r := Revision()
	if len(r) > 12 && r != "unknown" {
		return r[:12]
	}
	return r
}
