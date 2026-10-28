// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package ops

import (
	"bufio"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ElcanoTek/explorer/deploy"
)

// CaddyMarker is the first line of every Explorer site block. It is a
// compatibility identifier: bootstrap must recognise (and clean up) copies
// written by older releases, so it never changes.
const CaddyMarker = "# Caddy site block for Explorer, imported by /etc/caddy/Caddyfile via"

var reImport = regexp.MustCompile(`^\s*import\s+(.+)$`)

// caddyIsOurs reports whether path is a regular file (not a link) whose
// first line is the marker.
func caddyIsOurs(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	f, err := os.Open(path) //nolint:gosec // G304: a path the installer chose, not request input.
	if err != nil {
		return false
	}
	defer f.Close()
	line, _ := bufio.NewReader(f).ReadString('\n')
	return strings.TrimRight(line, "\n") == CaddyMarker
}

// caddyImports lists the import patterns of a Caddyfile, quoted or bare.
func caddyImports(caddyfile string) []string {
	raw, err := os.ReadFile(caddyfile) //nolint:gosec // G304: a path the installer chose, not request input.
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		m := reImport.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m == nil {
			continue
		}
		rest := strings.TrimSpace(m[1])
		var pattern string
		if rest != "" && (rest[0] == '"' || rest[0] == '\'') {
			q := rest[0]
			end := strings.IndexByte(rest[1:], q)
			if end < 0 {
				continue
			}
			pattern = rest[1 : 1+end]
			tail := strings.TrimSpace(rest[2+end:])
			if tail != "" && !strings.HasPrefix(tail, "#") {
				continue
			}
		} else {
			pattern = strings.Fields(rest + " ")[0]
		}
		if pattern != "" {
			out = append(out, pattern)
		}
	}
	return out
}

// realpathM resolves symlinks in the existing part of path and keeps the
// rest literally (realpath -m).
func realpathM(path string) string {
	path = filepath.Clean(path)
	var tail []string
	p := path
	for {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return filepath.Join(append([]string{r}, tail...)...)
		}
		parent := filepath.Dir(p)
		if parent == p {
			return path
		}
		tail = append([]string{filepath.Base(p)}, tail...)
		p = parent
	}
}

// caddyCandidate synthesises the Explorer file name an import glob in a
// concrete directory would load: '*' becomes "explorer" ('*' alone gives
// explorer.caddy), '?' becomes 'x'.
func caddyCandidate(caddyfile, pattern string) (string, bool) {
	dir, glob := filepath.Dir(pattern), filepath.Base(pattern)
	if strings.ContainsAny(dir, "*?[") || !strings.ContainsAny(glob, "*?[") {
		return "", false
	}
	if !strings.HasPrefix(dir, "/") {
		dir = filepath.Join(filepath.Dir(caddyfile), dir)
	}
	dir = realpathM(dir)
	name := strings.ReplaceAll(strings.ReplaceAll(glob, "*", "explorer"), "?", "x")
	if glob == "*" {
		name = "explorer.caddy"
	}
	if ok, err := filepath.Match(glob, name); err != nil || !ok {
		return "", false
	}
	return filepath.Join(dir, name), true
}

type caddyPlan struct {
	target     string
	addImport  bool
	candidates []string
}

// planCaddySite picks where the Explorer site block goes: an existing
// marker-owned copy the Caddyfile already loads, else a free name under an
// imported glob, else conf.d/explorer.caddy plus a new import line. An
// occupied, unmarked file is never chosen.
func planCaddySite(caddyfile string) (caddyPlan, error) {
	var plan caddyPlan
	for _, pattern := range caddyImports(caddyfile) {
		if c, ok := caddyCandidate(caddyfile, pattern); ok {
			plan.candidates = append(plan.candidates, c)
		}
	}
	for _, c := range plan.candidates {
		if caddyIsOurs(c) {
			plan.target = c
			return plan, nil
		}
	}
	for _, c := range plan.candidates {
		if !exists(c) {
			plan.target = c
			return plan, nil
		}
	}
	plan.target = realpathM(filepath.Join(filepath.Dir(caddyfile), "conf.d", "explorer.caddy"))
	plan.addImport = true
	if exists(plan.target) && !caddyIsOurs(plan.target) {
		return plan, errors.New("no safe Caddy site path is available: " + plan.target + " exists and is not Explorer's")
	}
	return plan, nil
}

// removeStaleCaddySites deletes marker-owned Explorer site blocks other
// than target from every directory a candidate lives in.
func removeStaleCaddySites(caddyfile string, plan caddyPlan) ([]string, error) {
	dirs := map[string]bool{}
	for _, c := range append(append([]string{}, plan.candidates...),
		filepath.Join(filepath.Dir(caddyfile), "conf.d", "explorer.caddy"),
		filepath.Join(filepath.Dir(caddyfile), "Caddyfile.d", "explorer.caddyfile")) {
		d := filepath.Dir(c)
		if fi, err := os.Lstat(d); err == nil && fi.IsDir() {
			dirs[d] = true
		}
	}
	var removed []string
	for d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			return removed, err
		}
		for _, e := range entries {
			path := filepath.Join(d, e.Name())
			if path == plan.target || e.Type()&fs.ModeType != 0 {
				continue
			}
			if caddyIsOurs(path) {
				if err := os.Remove(path); err != nil {
					return removed, err
				}
				removed = append(removed, path)
			}
		}
	}
	return removed, nil
}

// renderCaddySite fills the site template for host; without Let's Encrypt
// it pins `tls internal` inside the site block.
func renderCaddySite(host string, letsEncrypt bool) string {
	site := strings.ReplaceAll(string(deploy.CaddySite), "{{HOSTNAME}}", host)
	if letsEncrypt {
		return site
	}
	var out []string
	for _, line := range strings.Split(site, "\n") {
		out = append(out, line)
		if line == host+" {" {
			out = append(out, "\ttls internal")
		}
	}
	return strings.Join(out, "\n")
}

// adaptedHasSite reports whether `caddy adapt` JSON contains a route that
// matches host and reverse-proxies to upstream: a site that is written but
// never loaded is invisible until someone opens the URL.
func adaptedHasSite(adapted []byte, host, upstream string) bool {
	var doc struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []json.RawMessage `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if json.Unmarshal(adapted, &doc) != nil {
		return false
	}
	for _, srv := range doc.Apps.HTTP.Servers {
		for _, raw := range srv.Routes {
			var route struct {
				Match []struct {
					Host []string `json:"host"`
				} `json:"match"`
			}
			if json.Unmarshal(raw, &route) != nil {
				continue
			}
			hostOK := false
			for _, m := range route.Match {
				for _, h := range m.Host {
					if h == host {
						hostOK = true
					}
				}
			}
			if !hostOK {
				continue
			}
			var tree any
			if json.Unmarshal(raw, &tree) == nil && proxiesTo(tree, upstream) {
				return true
			}
		}
	}
	return false
}

// proxiesTo walks any JSON value for a reverse_proxy handler dialling upstream.
func proxiesTo(v any, upstream string) bool {
	switch t := v.(type) {
	case map[string]any:
		if t["handler"] == "reverse_proxy" {
			if ups, ok := t["upstreams"].([]any); ok {
				for _, up := range ups {
					if m, ok := up.(map[string]any); ok && m["dial"] == upstream {
						return true
					}
				}
			}
		}
		for _, child := range t {
			if proxiesTo(child, upstream) {
				return true
			}
		}
	case []any:
		for _, child := range t {
			if proxiesTo(child, upstream) {
				return true
			}
		}
	}
	return false
}

// caddySiteHost finds the installed Explorer site block the way bootstrap
// would place it, and returns its path and hostname ("" when none).
func caddySiteHost(caddyfile string) (string, string) {
	plan, err := planCaddySite(caddyfile)
	if err != nil || plan.addImport || !caddyIsOurs(plan.target) {
		return "", ""
	}
	raw, err := os.ReadFile(plan.target)
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		s := strings.TrimSpace(line)
		if s != "" && !strings.HasPrefix(s, "#") && !strings.HasPrefix(s, "import") &&
			!strings.HasPrefix(s, "}") && strings.HasSuffix(s, "{") {
			return plan.target, strings.TrimSpace(strings.TrimRight(strings.TrimSpace(strings.TrimSuffix(s, "{")), "{"))
		}
	}
	return "", ""
}
