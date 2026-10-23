// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package ops

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// asTrustedOwner makes the test user the owner the trust checks require.
func asTrustedOwner(t *testing.T) {
	t.Helper()
	old := trustedUID
	trustedUID = uint32(os.Getuid())
	t.Cleanup(func() { trustedUID = old })
}

// appTreeFixture: an app directory with the installer's two files, the env
// files, Python-era leftovers (one holding an operator's file) and entries
// that are nobody's business but their owner's.
func appTreeFixture(t *testing.T) Paths {
	t.Helper()
	asTrustedOwner(t)
	base := t.TempDir()
	p := Paths{AppDir: filepath.Join(base, "explorer")}
	for _, d := range []string{"bin", ".venv/bin", "docs"} {
		if err := os.MkdirAll(filepath.Join(p.AppDir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(p.AppDir, ".env"), "SECRET=1\n", 0o600)
	writeFile(t, filepath.Join(p.AppDir, ".env.shared"), "SHARED=1\n", 0o600)
	writeFile(t, filepath.Join(p.AppDir, "bin", "explorer"), "binary\n", 0o755)
	writeFile(t, filepath.Join(p.AppDir, "bin", "custom-helper"), "operator's\n", 0o755)
	writeFile(t, filepath.Join(p.AppDir, ".explorer-revision"), "rev\n", 0o644)
	writeFile(t, filepath.Join(p.AppDir, ".venv", "bin", "python"), "venv\n", 0o755)
	// "docs" was a Python-era name, but this one holds an operator's notes.
	writeFile(t, filepath.Join(p.AppDir, "docs", "customer-notes.md"), "keep me\n", 0o644)
	writeFile(t, filepath.Join(p.AppDir, ".env.backup.20261020T101010Z.AbC123"), "OLD_SECRET=1\n", 0o600)
	return p
}

func names(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

func TestPreserveKeepsOnlyTheInstallersFilesAndDeletesNothing(t *testing.T) {
	p := appTreeFixture(t)
	set, err := preserveForeignAppEntries(p)
	if err != nil {
		t.Fatal(err)
	}
	moved := append([]string(nil), set.moved...)
	sort.Strings(moved)
	if got := strings.Join(moved, ","); got != ".env.backup.20261020T101010Z.AbC123,.venv,bin/custom-helper,docs" {
		t.Fatalf("moved %s", got)
	}
	if !strings.HasPrefix(set.dir, p.PreservedDir()+string(os.PathSeparator)) {
		t.Fatalf("preserved into %s", set.dir)
	}
	for rel, want := range map[string]string{
		"docs/customer-notes.md": "keep me\n", "bin/custom-helper": "operator's\n", ".venv/bin/python": "venv\n",
		".env.backup.20261020T101010Z.AbC123": "OLD_SECRET=1\n",
	} {
		if readFile(t, filepath.Join(set.dir, rel)) != want {
			t.Fatalf("%s changed", rel)
		}
	}
	if fi, err := os.Stat(p.PreservedDir()); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("preserved folder mode: %v %v", fi, err)
	}
	if got := strings.Join(names(t, p.AppDir), ","); got != ".env,.env.shared,.explorer-revision,bin" {
		t.Fatalf("app dir now holds %s", got)
	}
	if got := strings.Join(names(t, filepath.Join(p.AppDir, "bin")), ","); got != "explorer" {
		t.Fatalf("bin now holds %s", got)
	}
	// Nothing to move the second time.
	if again, err := preserveForeignAppEntries(p); err != nil || again != nil {
		t.Fatalf("second run: %+v %v", again, err)
	}
}

func TestPreservedEntriesComeBackOnRestore(t *testing.T) {
	p := appTreeFixture(t)
	set, err := preserveForeignAppEntries(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := set.restore(p); err != nil {
		t.Fatal(err)
	}
	if readFile(t, filepath.Join(p.AppDir, "docs", "customer-notes.md")) != "keep me\n" ||
		readFile(t, filepath.Join(p.AppDir, "bin", "custom-helper")) != "operator's\n" {
		t.Fatal("not restored")
	}
	if exists(set.dir) {
		t.Fatal("the emptied preserved folder stayed")
	}
}

func TestRestoreNeverOverwritesAnEntryThatCameBack(t *testing.T) {
	p := appTreeFixture(t)
	set, err := preserveForeignAppEntries(p)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(p.AppDir, ".env.backup.20261020T101010Z.AbC123"), "NEWER\n", 0o600)
	if err := set.restore(p); err == nil {
		t.Fatal("restore over an existing entry succeeded")
	}
	if readFile(t, filepath.Join(p.AppDir, ".env.backup.20261020T101010Z.AbC123")) != "NEWER\n" ||
		readFile(t, filepath.Join(set.dir, ".env.backup.20261020T101010Z.AbC123")) != "OLD_SECRET=1\n" {
		t.Fatal("an entry was overwritten or lost")
	}
}

func TestPreserveRefusesALinkedPreservedFolderAndALinkedAppDir(t *testing.T) {
	p := appTreeFixture(t)
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, p.PreservedDir()); err != nil {
		t.Fatal(err)
	}
	if _, err := preserveForeignAppEntries(p); err == nil {
		t.Fatal("moved files through a symlinked preserved folder")
	}
	if !exists(filepath.Join(p.AppDir, "docs", "customer-notes.md")) {
		t.Fatal("a refused move lost the file")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Fatal("wrote through the link")
	}
	linked := Paths{AppDir: filepath.Join(t.TempDir(), "explorer")}
	if err := os.Symlink(p.AppDir, linked.AppDir); err != nil {
		t.Fatal(err)
	}
	if err := checkAppDirForMoves(linked); err == nil {
		t.Fatal("a symlinked app directory passed")
	}
}

func TestUpdateSwapMovesOnlyTheInstallersFilesAndUndoesExactly(t *testing.T) {
	p := appTreeFixture(t)
	if _, err := preserveForeignAppEntries(p); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "app")
	swap, err := moveOwnedFiles(p, dst)
	if err != nil {
		t.Fatal(err)
	}
	if readFile(t, filepath.Join(dst, "bin", "explorer")) != "binary\n" || readFile(t, filepath.Join(dst, ".explorer-revision")) != "rev\n" {
		t.Fatal("owned files not in the backup")
	}
	if got := strings.Join(names(t, p.AppDir), ","); got != ".env,.env.shared,bin" {
		t.Fatalf("left %s", got)
	}
	// The update installs new ones, then fails: the old ones come back.
	writeFile(t, filepath.Join(p.AppDir, "bin", "explorer"), "new binary\n", 0o755)
	writeFile(t, filepath.Join(p.AppDir, ".explorer-revision"), "new\n", 0o644)
	if errs := restoreOwnedFiles(p, dst, swap); len(errs) != 0 {
		t.Fatal(errs)
	}
	if readFile(t, filepath.Join(p.AppDir, "bin", "explorer")) != "binary\n" || readFile(t, filepath.Join(p.AppDir, ".explorer-revision")) != "rev\n" {
		t.Fatal("old files not restored")
	}
}

func TestRestoreLeavesAnOriginalThatWasNeverMoved(t *testing.T) {
	p := appTreeFixture(t)
	// A swap that stopped before moving anything (as after a failed rename).
	swap := &ownedSwap{binExisted: true, existed: map[string]bool{"bin/explorer": true, ".explorer-revision": true}, moved: map[string]bool{}}
	if errs := restoreOwnedFiles(p, t.TempDir(), swap); len(errs) != 0 {
		t.Fatal(errs)
	}
	if readFile(t, filepath.Join(p.AppDir, "bin", "explorer")) != "binary\n" || readFile(t, filepath.Join(p.AppDir, ".explorer-revision")) != "rev\n" {
		t.Fatal("an unmoved original was removed")
	}
}
