// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package ops

import (
	"bytes"
	"context"
	"os"
	"strings"
	"sync"
	"testing"
)

// fakeRunner records commands and answers them from handle (default: exit 0).
// Commands named in real are passed to the real runner instead.
type fakeRunner struct {
	mu     sync.Mutex
	tools  map[string]bool
	real   map[string]bool
	handle func(c Cmd) Result
	calls  []string
}

func newFake(tools ...string) *fakeRunner {
	f := &fakeRunner{tools: map[string]bool{}, real: map[string]bool{}}
	for _, t := range tools {
		f.tools[t] = true
	}
	return f
}

func (f *fakeRunner) record(c Cmd) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, strings.TrimSpace(c.Name+" "+strings.Join(c.Args, " ")))
}

func (f *fakeRunner) Run(ctx context.Context, c Cmd) Result {
	if f.real[c.Name] {
		return execRunner{}.Run(ctx, c)
	}
	f.record(c)
	if f.handle != nil {
		return f.handle(c)
	}
	return Result{}
}

func (f *fakeRunner) Interactive(ctx context.Context, c Cmd) int {
	return f.Run(ctx, c).Code
}

func (f *fakeRunner) LookPath(name string) (string, bool) {
	if f.real[name] {
		return execRunner{}.LookPath(name)
	}
	return "/usr/bin/" + name, f.tools[name]
}

func (f *fakeRunner) called(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// testUI captures output.
func testUI() (*ui, *bytes.Buffer) {
	var buf bytes.Buffer
	return &ui{out: &buf, errw: &buf}, &buf
}

func writeFile(t *testing.T, path, text string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
