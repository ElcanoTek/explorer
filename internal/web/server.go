// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

// Package web is Explorer's HTTP service: the inbox and message pages, the
// attachment endpoint, sign-in for both authentication modes, and the
// security middleware every response passes through.
package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ElcanoTek/explorer/internal/archive"
	"github.com/ElcanoTek/explorer/internal/auth"
	"github.com/ElcanoTek/explorer/internal/config"
)

// Server holds everything a request needs. Build one with New.
type Server struct {
	settings     config.Settings
	inbox        *archive.Inbox
	auth         provider
	sessions     sessionCodec
	jobs         *jobStore
	pages        map[string]*template.Template
	allowedRoots []string
	now          func() time.Time
	handler      http.Handler
}

// Options are the seams tests and the CLI use; zero values mean production.
type Options struct {
	// Store replaces the S3 client (tests use an in-memory fake).
	Store archive.Store
	// HTTPClient is used for the central auth service's back channel.
	HTTPClient *http.Client
	// Now replaces the clock.
	Now func() time.Time
}

// New validates settings and builds the service. Like the Python app's
// startup, central mode refuses to start without its signing key, client
// configuration or a generated session secret.
func New(ctx context.Context, s config.Settings, opts Options) (*Server, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	store := opts.Store
	if store == nil {
		var err error
		if store, err = archive.NewS3Store(ctx, s); err != nil {
			return nil, fmt.Errorf("configure S3: %w", err)
		}
	}
	pages, err := parsePages()
	if err != nil {
		return nil, err
	}
	prov, err := buildProvider(s, opts.HTTPClient, now)
	if err != nil {
		return nil, err
	}
	srv := &Server{
		settings:     s,
		inbox:        archive.New(store, s),
		auth:         prov,
		sessions:     sessionCodec{key: []byte(s.SessionSecret), secure: s.UICookieSecure, now: now},
		jobs:         newJobStore(now),
		pages:        pages,
		allowedRoots: s.AllowedKeyRoots(),
		now:          now,
	}
	srv.handler = srv.routes()
	return srv, nil
}

// Close releases the access database in central mode.
func (s *Server) Close() error { return s.auth.close() }

// ServeHTTP makes Server an http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", staticHandler())
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /login", s.handleLogin)
	mux.HandleFunc("GET /auth/login", s.handleLogin)
	mux.HandleFunc("GET /auth/callback", s.handleCallback)
	mux.HandleFunc("GET /signed-out", s.handleSignedOut)
	mux.HandleFunc("POST /auth/backchannel-logout", s.handleBackchannel)
	mux.HandleFunc("POST /logout", s.handleLogout)
	mux.HandleFunc("GET /email", s.handleEmail)
	mux.HandleFunc("GET /attachment", s.handleAttachment)
	mux.HandleFunc("GET /{$}", s.handleInbox)
	return s.securityHeaders(s.withSession(s.requireAuthentication(mux)))
}

// staticHandler serves the embedded static tree. Pages reference it through
// assetURL, which appends ?v=<content hash of the tree>: a request carrying
// the current version is cached for a year as immutable, because a deploy
// that changes any static file changes the version. Anything else (no or a
// stale ?v=, or a font that fonts.css loads by relative URL) must revalidate,
// which the per-file ETag makes a cheap 304.
func staticHandler() http.Handler {
	static, _ := fs.Sub(staticFS, "static")
	etags := map[string]string{}
	_ = fs.WalkDir(static, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(static, path)
		if err == nil {
			sum := sha256.Sum256(b)
			etags[path] = `"` + hex.EncodeToString(sum[:12]) + `"`
		}
		return nil
	})
	files := http.StripPrefix("/static/", http.FileServerFS(filesOnly{static}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tag, ok := etags[strings.TrimPrefix(r.URL.Path, "/static/")]; ok {
			w.Header().Set("ETag", tag)
			if r.URL.Query().Get("v") == assetVersion() {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			} else {
				w.Header().Set("Cache-Control", "no-cache")
			}
		}
		files.ServeHTTP(w, r)
	})
}

// filesOnly serves files and answers 404 for directories, so the static
// tree is never listed.
type filesOnly struct{ fs.FS }

func (f filesOnly) Open(name string) (fs.File, error) {
	file, err := f.FS.Open(name)
	if err != nil {
		return nil, err
	}
	if st, err := file.Stat(); err != nil || st.IsDir() {
		_ = file.Close()
		return nil, fs.ErrNotExist
	}
	return file, nil
}

// publicPaths are reachable without signing in. Everything else, every data
// route included, is behind requireAuthentication.
var publicPaths = map[string]bool{
	"/health": true, "/login": true, "/auth/login": true, "/auth/callback": true,
	"/auth/backchannel-logout": true, "/signed-out": true,
}

const maxBackchannelBody = 20_000

type ctxKey int

const (
	ctxIdentity ctxKey = iota
	ctxNonce
	ctxSession
)

func identityFrom(r *http.Request) *auth.Identity {
	id, _ := r.Context().Value(ctxIdentity).(*auth.Identity)
	return id
}

func nonceFrom(r *http.Request) string {
	n, _ := r.Context().Value(ctxNonce).(string)
	return n
}

func sessionFrom(r *http.Request) *uiSession {
	if s, ok := r.Context().Value(ctxSession).(*uiSession); ok {
		return s
	}
	return &uiSession{}
}

func (s *Server) requireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/auth/backchannel-logout" && r.Method == http.MethodPost {
			switch {
			case r.ContentLength < 0 || (r.Header.Get("Content-Length") == "" && len(r.TransferEncoding) == 0):
				http.Error(w, "Length Required", http.StatusLengthRequired)
				return
			case r.ContentLength > maxBackchannelBody:
				http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBackchannelBody)
		}
		if path == "/health" || strings.HasPrefix(path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}
		id := s.auth.identity(r)
		if id != nil {
			r = r.WithContext(context.WithValue(r.Context(), ctxIdentity, id))
		}
		if !publicPaths[path] && id == nil {
			s.auth.unauthenticated(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Content-Security-Policy. Pages carry one inline <script> (the theme
// bootstrap, which must run before first paint); it gets this response's
// nonce, and every other script is a same-origin file. Scripts are the
// strict part: no inline handlers, no eval, no other origins, so markup
// injected into an email body cannot run script. Styles are 'self' only:
// the templates have no inline styles and the sanitizer strips style
// attributes and <style> blocks from email bodies. Email bodies may
// reference remote images, so img-src allows https: and data:. No
// form-action: Elcano-mode logout is a form POST that redirects to the auth
// host, and browsers apply form-action to that redirect. frame-ancestors
// 'none' mirrors X-Frame-Options: DENY. Nothing frames, plays media or
// starts workers (the sanitizer drops iframe/video/audio, and the date
// picker is our own plain script), so frame-src, media-src and worker-src
// are 'none' rather than falling back to 'self'.
const cspNonPage = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'"

func cspForPage(nonce string) string {
	return "default-src 'self'; script-src 'self' 'nonce-" + nonce + "'; style-src 'self'; " +
		"img-src 'self' data: https:; font-src 'self'; connect-src 'self'; " +
		"media-src 'none'; frame-src 'none'; worker-src 'none'; " +
		"object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
}

type headerWriter struct {
	http.ResponseWriter
	nonce       string
	wroteHeader bool
	before      []func(http.Header)
}

func (h *headerWriter) WriteHeader(code int) {
	if !h.wroteHeader {
		h.wroteHeader = true
		hdr := h.Header()
		for _, f := range h.before {
			f(hdr)
		}
		if strings.HasPrefix(hdr.Get("Content-Type"), "text/html") {
			hdr.Set("Content-Security-Policy", cspForPage(h.nonce))
		} else if hdr.Get("Content-Security-Policy") == "" {
			hdr.Set("Content-Security-Policy", cspNonPage)
		}
		for k, v := range map[string]string{
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "DENY",
			"Referrer-Policy":        "strict-origin-when-cross-origin",
		} {
			if hdr.Get(k) == "" {
				hdr.Set(k, v)
			}
		}
	}
	h.ResponseWriter.WriteHeader(code)
}

func (h *headerWriter) Write(b []byte) (int, error) {
	if !h.wroteHeader {
		if h.Header().Get("Content-Type") == "" {
			h.Header().Set("Content-Type", http.DetectContentType(b))
		}
		h.WriteHeader(http.StatusOK)
	}
	return h.ResponseWriter.Write(b)
}

func (h *headerWriter) Unwrap() http.ResponseWriter { return h.ResponseWriter }

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := make([]byte, 16)
		_, _ = rand.Read(nonce)
		n := base64.RawURLEncoding.EncodeToString(nonce)
		hw := &headerWriter{ResponseWriter: w, nonce: n}
		start := s.now()
		rec := &statusRecorder{headerWriter: hw}
		next.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), ctxNonce, n)))
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			// Path only: query strings carry search terms and S3 keys.
			slog.Info("request", "method", r.Method, "path", r.URL.Path, "status", rec.status(),
				"duration_ms", time.Since(start).Milliseconds())
		}
	})
}

type statusRecorder struct {
	*headerWriter
	code int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.code == 0 {
		s.code = code
	}
	s.headerWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.code == 0 {
		s.code = http.StatusOK
	}
	return s.headerWriter.Write(b)
}

func (s *statusRecorder) status() int {
	if s.code == 0 {
		return http.StatusOK
	}
	return s.code
}

// withSession decodes the UI cookie and re-issues it, just before the
// response headers go out, when a handler changed it.
func (s *Server) withSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/static/") || r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		sess := s.sessions.decode(r)
		if rec, ok := w.(*statusRecorder); ok {
			rec.before = append(rec.before, func(h http.Header) {
				// Re-issued on every page while it carries anything, so the
				// 14-day limit counts from the last visit (Starlette's
				// behaviour), not from when the cookie was first set.
				if sess.dirty || sess.data != (uiSessionData{}) {
					h.Add("Set-Cookie", s.sessions.cookie(sess).String())
				}
			})
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxSession, sess)))
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, map[string]string{"detail": detail})
}

// isAllowedS3Key is the S3 prefix boundary for the s3_key parameter: a key
// outside the configured archive, with control characters, or absurdly long
// is refused, so the parameter cannot walk the bucket.
func (s *Server) isAllowedS3Key(key string) bool {
	if key == "" || len(key) > 1024 {
		return false
	}
	for _, r := range key {
		if r < 32 {
			return false
		}
	}
	if len(s.allowedRoots) == 0 {
		return true
	}
	for _, root := range s.allowedRoots {
		if strings.HasPrefix(key, root) {
			return true
		}
	}
	return false
}

// safeLocalPath returns raw when it is a same-origin absolute path, else def.
func safeLocalPath(raw, def string) string {
	if raw == "" || len(raw) > 2048 || !strings.HasPrefix(raw, "/") ||
		strings.HasPrefix(raw, "//") || strings.Contains(raw, `\`) {
		return def
	}
	for _, r := range raw {
		if r < 32 || r == 127 {
			return def
		}
	}
	if i := strings.IndexAny(raw, "/?#"); i >= 0 && strings.Contains(raw[:i], ":") {
		return def
	}
	return raw
}

// requestURL reconstructs the browser-visible URL. X-Forwarded-Proto is only
// believed from the loopback reverse proxy (Caddy), as uvicorn's
// --forwarded-allow-ips=127.0.0.1 did.
func requestURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			if p := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])); p == "https" || p == "http" {
				scheme = p
			}
		}
	}
	return scheme + "://" + r.Host + r.URL.RequestURI()
}

// errorIs reports whether err is a cancellation or deadline.
func isCancellation(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
