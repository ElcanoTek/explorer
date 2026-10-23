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

// What lives in the app directory, and whose it is. The installer owns
// exactly two files, the binary and the revision marker (plus the bin
// directory that holds the binary); the env files belong to the operator
// and the service. Everything else, Python-era leftovers included (their
// names are generic: docs, scripts, bin), may be someone's, so it is never
// deleted: it is moved aside into PreservedDir.
var (
	appEnvEntries = map[string]bool{".env": true, ".env.shared": true}
	// appOwnedFiles, relative to the app directory.
	appOwnedFiles = []string{filepath.Join("bin", "explorer"), ".explorer-revision"}
)

const appBinDir = "bin"

// PreservedDir is where entries of the app directory that Explorer does not
// own are moved, beside it on the same filesystem.
func (p Paths) PreservedDir() string {
	return filepath.Join(filepath.Dir(p.AppDir), filepath.Base(p.AppDir)+"-preserved")
}

// checkAppDirForMoves refuses an app directory that moves could escape or
// break: a symlink or non-directory, or one mounted on another filesystem
// than its parent (renames into the sibling backup and preserved folders
// would fail half way). A missing app directory is fine (a first install).
func checkAppDirForMoves(p Paths) error {
	fi, err := os.Lstat(p.AppDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a real directory", p.AppDir)
	}
	parent, err := os.Stat(filepath.Dir(p.AppDir))
	if err != nil {
		return err
	}
	if statT(fi).Dev != statT(parent).Dev {
		return fmt.Errorf("%s is on another filesystem than %s; move it there before updating", p.AppDir, filepath.Dir(p.AppDir))
	}
	return nil
}

// foreignAppEntries lists, relative to the app directory, every entry that
// is neither an env file nor the installer's: top-level entries, and inside
// a real bin directory everything but a regular bin/explorer.
func foreignAppEntries(p Paths) ([]string, error) {
	entries, err := os.ReadDir(p.AppDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rel []string
	for _, e := range entries {
		name := e.Name()
		switch {
		case appEnvEntries[name], name == ".explorer-revision" && e.Type().IsRegular():
		case name == appBinDir && e.IsDir() && e.Type()&fs.ModeSymlink == 0:
			inner, err := os.ReadDir(filepath.Join(p.AppDir, appBinDir))
			if err != nil {
				return nil, err
			}
			for _, b := range inner {
				if b.Name() != "explorer" || !b.Type().IsRegular() {
					rel = append(rel, filepath.Join(appBinDir, b.Name()))
				}
			}
		default:
			rel = append(rel, name)
		}
	}
	return rel, nil
}

// preservedSet records what one run moved aside, so a rollback can put it
// back. A nil set moved nothing.
type preservedSet struct {
	dir   string
	moved []string // relative to the app directory, in move order
}

// preserveForeignAppEntries moves every foreign entry of the app directory
// into a new root-only folder under PreservedDir. If a move fails, the
// entries already moved are put back before the error is returned.
func preserveForeignAppEntries(p Paths) (*preservedSet, error) {
	rel, err := foreignAppEntries(p)
	if err != nil || len(rel) == 0 {
		return nil, err
	}
	if err := checkAppDirForMoves(p); err != nil {
		return nil, err
	}
	parent := p.PreservedDir()
	if err := os.Mkdir(parent, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	// Only into a real, root-owned directory: never through a link or into
	// a folder someone else controls.
	fi, err := os.Lstat(parent)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0 || statT(fi).Uid != trustedUID {
		return nil, fmt.Errorf("%s must be a real directory owned by root", parent)
	}
	if err := os.Chmod(parent, 0o700); err != nil { //nolint:gosec // G302: a root-only directory needs its execute bit.
		return nil, err
	}
	dir, err := os.MkdirTemp(parent, time.Now().UTC().Format("20060102T150405Z")+".")
	if err != nil {
		return nil, err
	}
	set := &preservedSet{dir: dir}
	for _, r := range rel {
		if filepath.Dir(r) == appBinDir {
			if err := os.MkdirAll(filepath.Join(dir, appBinDir), 0o700); err != nil {
				return nil, errors.Join(err, set.restore(p))
			}
		}
		if err := os.Rename(filepath.Join(p.AppDir, r), filepath.Join(dir, r)); err != nil {
			err = fmt.Errorf("could not move %s out of %s into %s: %w", r, p.AppDir, dir, err)
			return nil, errors.Join(err, set.restore(p))
		}
		set.moved = append(set.moved, r)
	}
	return set, nil
}

// restore moves everything back into the app directory (newest first) and
// removes the then-empty folders this run made. Nothing is overwritten: an
// entry whose place is taken again stays preserved and is reported.
func (s *preservedSet) restore(p Paths) error {
	if s == nil {
		return nil
	}
	var errs []error
	for i := len(s.moved) - 1; i >= 0; i-- {
		r := s.moved[i]
		dst := filepath.Join(p.AppDir, r)
		if _, err := os.Lstat(dst); err == nil {
			errs = append(errs, fmt.Errorf("%s exists again; its earlier copy stays in %s", dst, s.dir))
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil { //nolint:gosec // G301: the app tree is public and root-owned.
			errs = append(errs, err)
			continue
		}
		if err := os.Rename(filepath.Join(s.dir, r), dst); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		_ = os.Remove(filepath.Join(s.dir, appBinDir)) // only when empty
		_ = os.Remove(s.dir)
	}
	return errors.Join(errs...)
}

// preserveAndReport moves foreign entries aside and says what it moved.
func preserveAndReport(u *ui, p Paths) (*preservedSet, error) {
	set, err := preserveForeignAppEntries(p)
	if err != nil {
		return nil, err
	}
	if set != nil {
		u.warnf("moved %d entr%s Explorer does not own out of %s into %s (nothing was deleted): %s",
			len(set.moved), plural(len(set.moved), "y", "ies"), p.AppDir, set.dir, strings.Join(set.moved, ", "))
	}
	return set, nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
