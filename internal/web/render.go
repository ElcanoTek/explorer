// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package web

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// pages are parsed once at startup: base.html plus one page template each.
var pageNames = []string{"inbox", "email_detail", "auth_error", "signed_out"}

type kv struct{ Key, Value string }

type pageView struct {
	Title         string
	Nonce         string
	StaticVersion string
	Page          any
}

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"field": func(name, value string) kv { return kv{name, value} },
	}
}

func parsePages() (map[string]*template.Template, error) {
	pages := map[string]*template.Template{}
	for _, name := range pageNames {
		t, err := template.New(name).Funcs(templateFuncs()).ParseFS(templateFS, "templates/base.html", "templates/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", name, err)
		}
		pages[name] = t
	}
	return pages, nil
}

// staticVersion is a short content hash of the static tree, so a deploy
// busts browser caches exactly when an asset changed.
func staticVersion() string {
	h := sha256.New()
	_ = fs.WalkDir(staticFS, "static", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := staticFS.ReadFile(path)
		if err == nil {
			h.Write([]byte(path))
			h.Write(b)
		}
		return nil
	})
	return hex.EncodeToString(h.Sum(nil))[:12]
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, page string, data any) {
	t, ok := s.pages[page]
	if !ok {
		http.Error(w, "unknown page", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	view := pageView{Nonce: nonceFrom(r), StaticVersion: s.staticVersion, Page: data}
	if err := t.ExecuteTemplate(&buf, "base", view); err != nil {
		slog.Error("render template", "page", page, "err", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

type messagePage struct {
	Heading, Message       string
	ActionURL, ActionLabel string
}

func (s *Server) messagePage(w http.ResponseWriter, r *http.Request, status int, heading, message string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	s.render(w, r, status, "auth_error", messagePage{heading, message, "/auth/login", "Try again"})
}

// sender is how a From header is shown: the display name if there is one,
// else the address; Avatar is its first letter.
type sender struct{ Name, Email, Display, Avatar string }

func parseSender(raw string) sender {
	name := strings.TrimSpace(strings.ReplaceAll(strings.SplitN(raw, "<", 2)[0], `"`, ""))
	email := strings.TrimSpace(raw)
	if strings.Contains(raw, "<") && strings.Contains(raw, ">") {
		email = strings.TrimSpace(strings.SplitN(strings.SplitN(raw, "<", 2)[1], ">", 2)[0])
	}
	display := name
	if display == "" {
		display = email
	}
	avatar := "?"
	for _, r := range display {
		avatar = strings.ToUpper(string(r))
		break
	}
	return sender{name, email, display, avatar}
}

func itoa(n int) string { return strconv.Itoa(n) }
