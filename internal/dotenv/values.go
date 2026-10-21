// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package dotenv

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// Value is a resolved binding. Set is false for a bare `KEY` line, which
// python-dotenv reports as None and never exports.
type Value struct {
	S   string
	Set bool
}

// Resolve interpolates bindings in file order (python-dotenv's
// resolve_variables). Each value sees base plus the file's earlier values;
// override decides which side wins when both define a name.
func Resolve(bindings []Binding, base map[string]string, override bool) map[string]Value {
	out := map[string]Value{}
	lookup := func(name string) (string, bool) {
		fileV, inFile := out[name]
		baseV, inBase := base[name]
		switch {
		case override && inFile:
			return fileV.S, true
		case inBase:
			return baseV, true
		case inFile:
			return fileV.S, true
		}
		return "", false
	}
	for _, b := range bindings {
		if !b.HasKey || b.Error {
			continue
		}
		if !b.HasValue {
			out[b.Key] = Value{}
			continue
		}
		out[b.Key] = Value{S: Interpolate(b.Value, lookup), Set: true}
	}
	return out
}

// ReadRegular returns a file's text when it is a regular file reached
// without following a symlink. A missing file is ("", false, nil).
func ReadRegular(path string) (string, bool, error) {
	st, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if !st.Mode().IsRegular() {
		return "", false, nil
	}
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the operator-chosen app directory's dotenv file.
	if err != nil {
		return "", false, err
	}
	return string(raw), true, nil
}

// Layer applies dir/.env.shared and then dir/.env to environ with the
// precedence Explorer has always used: .env overrides everything, the
// process environment comes next, and .env.shared fills in only what is
// still unset. environ is not modified; the merged view is returned.
// Symlinked or non-regular dotenv files are ignored.
func Layer(dir string, environ map[string]string) map[string]string {
	env := make(map[string]string, len(environ))
	for k, v := range environ {
		env[k] = v
	}
	if text, ok, _ := ReadRegular(filepath.Join(dir, ".env.shared")); ok {
		for k, v := range Resolve(Parse(text), env, false) {
			if _, exists := env[k]; !exists && v.Set {
				env[k] = v.S
			}
		}
	}
	if text, ok, _ := ReadRegular(filepath.Join(dir, ".env")); ok {
		for k, v := range Resolve(Parse(text), env, true) {
			if v.Set {
				env[k] = v.S
			}
		}
	}
	return env
}

// Environ returns the process environment as a map.
func Environ() map[string]string {
	env := map[string]string{}
	for _, kv := range os.Environ() {
		for i := 0; i < len(kv); i++ {
			if kv[i] == '=' {
				env[kv[:i]] = kv[i+1:]
				break
			}
		}
	}
	return env
}
