// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package ops

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// What may live in the app directory, and who owns it.
var (
	// appEnvEntries belong to the operator and the service: never moved.
	appEnvEntries = map[string]bool{".env": true, ".env.shared": true}
	// appOwnedEntries are what the installer writes (installApp).
	appOwnedEntries = map[string]bool{"bin": true, ".explorer-revision": true}
	// legacyAppEntries are what the Python-era installer put there: a copy of
	// its source tree (every top-level name that tree ever had), its
	// virtualenv and its scratch space. All of it is reproducible.
	legacyAppEntries = map[string]bool{
		".env.example": true, ".github": true, ".gitignore": true, "AGENTS.md": true, "CLAUDE.md": true,
		"CODE_OF_CONDUCT.md": true, "CONTRIBUTING.md": true, "LICENSE": true, "NOTICE": true, "README.md": true,
		"SECURITY.md": true, "app": true, "deploy": true, "docs": true, "install.sh": true, "provision": true,
		"requirements-dev.in": true, "requirements-dev.txt": true, "requirements.in": true,
		"requirements.txt": true, "ruff.toml": true, "scripts": true, "tests": true,
		".venv": true, ".venv.old": true, ".tmp": true,
	}
)

// replaceableAppEntry reports whether an install or update may replace the
// entry: the installer's own files and Python-era leftovers. Anything else
// (an operator's file, an env backup) is never deleted.
func replaceableAppEntry(name string) bool {
	return appOwnedEntries[name] || legacyAppEntries[name]
}

// PreservedDir is where entries of the app directory that Explorer does not
// own are moved, beside it on the same filesystem.
func (p Paths) PreservedDir() string {
	return filepath.Join(filepath.Dir(p.AppDir), filepath.Base(p.AppDir)+"-preserved")
}

// preserveUnknownAppEntries moves every entry of the app directory that is
// neither an env file nor replaceable into a new root-only folder under
// PreservedDir, so the app directory holds only what the layout check
// expects and nothing anyone put there is lost. It returns that folder and
// the names moved ("" and nil when there was nothing to move).
func preserveUnknownAppEntries(p Paths) (string, []string, error) {
	entries, err := os.ReadDir(p.AppDir)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	var names []string
	for _, e := range entries {
		if !appEnvEntries[e.Name()] && !replaceableAppEntry(e.Name()) {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return "", nil, nil
	}
	parent := p.PreservedDir()
	if err := os.Mkdir(parent, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", nil, err
	}
	// Only into a real, root-owned directory: never through a link or into
	// a folder someone else controls.
	fi, err := os.Lstat(parent)
	if err != nil {
		return "", nil, err
	}
	if !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0 || statT(fi).Uid != trustedUID {
		return "", nil, fmt.Errorf("%s must be a real directory owned by root", parent)
	}
	if err := os.Chmod(parent, 0o700); err != nil { //nolint:gosec // G302: a root-only directory needs its execute bit.
		return "", nil, err
	}
	dir, err := os.MkdirTemp(parent, time.Now().UTC().Format("20060102T150405Z")+".")
	if err != nil {
		return "", nil, err
	}
	for _, name := range names {
		if err := os.Rename(filepath.Join(p.AppDir, name), filepath.Join(dir, name)); err != nil {
			return dir, nil, fmt.Errorf("could not move %s out of %s into %s: %w", name, p.AppDir, dir, err)
		}
	}
	return dir, names, nil
}

// preserveAndReport runs preserveUnknownAppEntries and says what it moved.
func preserveAndReport(u *ui, p Paths) error {
	dir, names, err := preserveUnknownAppEntries(p)
	if err != nil {
		return err
	}
	if len(names) > 0 {
		u.warnf("moved %d entr%s Explorer does not own out of %s into %s (nothing was deleted): %s",
			len(names), plural(len(names), "y", "ies"), p.AppDir, dir, strings.Join(names, ", "))
	}
	return nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
