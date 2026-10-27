// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

// Package apitoken holds the scoped bearer tokens programmatic Explorer
// callers (Fleet, scripts) use for /mcp and /api/v1.
//
// Browser sign-in (the Elcano cookie or central Auth) is for people. A
// machine caller gets one of these instead: an operator mints it on the host
// with `explorer token create`, it is shown once, and only its SHA-256 is
// stored. Tokens are 256-bit random strings, so an unsalted hash is enough to
// make a stolen database useless; there is nothing to brute-force.
//
// There is one scope, email:search: run the archive searches (targeted,
// fuzzy, latest report) and read the metadata they return. It cannot read a
// message body beyond the bounded preview a search returns, download
// attachments, or change anything; no token is an admin key.
//
// The schema and stored formats match Lens's internal/apitoken (tables
// api_tokens and api_meta), so the two products' token tooling reads alike.
package apitoken

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // database/sql driver "sqlite"
)

// ScopeSearch runs archive searches.
const ScopeSearch = "email:search"

// Scopes lists every scope in canonical order.
var Scopes = []string{ScopeSearch}

const (
	// TokenPrefix starts every raw token, so a leaked one is recognisable.
	TokenPrefix = "explorer_"
	// DisplayPrefixChars is how much of a token listings and logs show, so an
	// operator can tell tokens apart without ever seeing a secret again.
	DisplayPrefixChars = 16
	// LastUsedResolutionSeconds: last_used_at is a convenience for operators,
	// not an audit log; writing it on every request would turn reads into
	// writes.
	LastUsedResolutionSeconds = 60
	// maxRawTokenLength rejects absurd inputs before hashing.
	maxRawTokenLength = 200
)

var labelRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._:@-]{0,79}$`)

// TokenError is an unusable token; its message is safe to show a caller.
type TokenError struct{ msg string }

func (e *TokenError) Error() string { return e.msg }

func tokenError(msg string) error { return &TokenError{msg: msg} }

// ValidationError is a bad label or scope given to Create (an operator error).
type ValidationError struct{ msg string }

func (e *ValidationError) Error() string { return e.msg }

// Token is one stored API token (never its secret).
type Token struct {
	ID         int64
	Label      string
	Prefix     string
	Scopes     []string
	CreatedAt  string
	LastUsedAt string // "" when never used
	RevokedAt  string // "" while active
}

// Allows reports whether the token carries scope.
func (t *Token) Allows(scope string) bool { return slices.Contains(t.Scopes, scope) }

// Store is the token database. It opens the SQLite file lazily: a lookup on
// a host where no token was ever minted must not create the database as a
// side effect of an unauthenticated request. Safe for concurrent use.
type Store struct {
	path string
	now  func() time.Time

	mu sync.Mutex
	db *sql.DB
}

// NewStore returns a store for the database at path. Nothing touches the
// filesystem until the first operation.
func NewStore(path string) *Store {
	return &Store{path: path, now: time.Now}
}

// Path is the database file.
func (s *Store) Path() string { return s.path }

// SetClock replaces the store's clock (tests).
func (s *Store) SetClock(now func() time.Time) { s.now = now }

// Close releases the database handle, if one was opened.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

func sqliteDSN(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	// A SQLite URI, so a path containing '?' or '#' cannot be misread as
	// parameters.
	return "file:" + (&url.URL{Path: abs}).EscapedPath() + "?_pragma=busy_timeout(5000)", nil
}

func (s *Store) conn(ctx context.Context) (*sql.DB, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		return s.db, nil
	}
	if dir := filepath.Dir(s.path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	// Create the file owner-only before SQLite opens it, so there is no
	// window in which a fresh token database is world-readable.
	f, err := os.OpenFile(s.path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	_ = f.Close()
	dsn, err := sqliteDSN(s.path)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            label TEXT NOT NULL,
            prefix TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            scopes TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            revoked_at TEXT
        )`,
		"CREATE TABLE IF NOT EXISTS api_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	// Best effort: an operator-owned file we cannot chmod is still usable.
	_ = os.Chmod(s.path, 0o600)
	s.db = db
	return db, nil
}

func (s *Store) exists() bool {
	_, err := os.Stat(s.path)
	return err == nil
}

func (s *Store) utcNow() string {
	return s.now().UTC().Format("2006-01-02T15:04:05+00:00")
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// NormalizeScopes validates scopes and returns them deduplicated in canonical
// order.
func NormalizeScopes(scopes []string) ([]string, error) {
	wanted := map[string]bool{}
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if !slices.Contains(Scopes, scope) {
			return nil, &ValidationError{fmt.Sprintf("unknown scope '%s'; choose from %s", scope, strings.Join(Scopes, ", "))}
		}
		wanted[scope] = true
	}
	if len(wanted) == 0 {
		return nil, &ValidationError{"a token needs at least one scope"}
	}
	out := make([]string, 0, len(wanted))
	for _, scope := range Scopes {
		if wanted[scope] {
			out = append(out, scope)
		}
	}
	return out, nil
}

func parseScopes(stored string) []string {
	out := []string{}
	for _, scope := range strings.Fields(stored) {
		if slices.Contains(Scopes, scope) {
			out = append(out, scope)
		}
	}
	return out
}

const selectColumns = "id, label, prefix, scopes, created_at, last_used_at, revoked_at"

type scanner interface{ Scan(dest ...any) error }

func scanToken(row scanner) (*Token, error) {
	var (
		t                   Token
		scopes              string
		lastUsed, revokedAt sql.NullString
	)
	if err := row.Scan(&t.ID, &t.Label, &t.Prefix, &scopes, &t.CreatedAt, &lastUsed, &revokedAt); err != nil {
		return nil, err
	}
	t.Scopes = parseScopes(scopes)
	t.LastUsedAt = lastUsed.String
	t.RevokedAt = revokedAt.String
	return &t, nil
}

// Create mints a token and returns it with its raw secret, which is never
// stored and cannot be shown again.
func (s *Store) Create(ctx context.Context, label string, scopes []string) (*Token, string, error) {
	label = strings.Join(strings.Fields(label), " ")
	if !labelRE.MatchString(label) {
		return nil, "", &ValidationError{"label must be 1-80 characters: letters, digits, space . _ : @ -"}
	}
	normalized, err := NormalizeScopes(scopes)
	if err != nil {
		return nil, "", err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, "", err
	}
	raw := TokenPrefix + base64.RawURLEncoding.EncodeToString(secret)
	db, err := s.conn(ctx)
	if err != nil {
		return nil, "", err
	}
	res, err := db.ExecContext(ctx,
		"INSERT INTO api_tokens (label, prefix, token_hash, scopes, created_at) VALUES (?, ?, ?, ?, ?)",
		label, raw[:DisplayPrefixChars], hashToken(raw), strings.Join(normalized, " "), s.utcNow())
	if err != nil {
		return nil, "", err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, "", err
	}
	token, err := scanToken(db.QueryRowContext(ctx, "SELECT "+selectColumns+" FROM api_tokens WHERE id = ?", id))
	if err != nil {
		return nil, "", err
	}
	return token, raw, nil
}

// List returns every token, active and revoked, oldest first.
func (s *Store) List(ctx context.Context) ([]*Token, error) {
	if !s.exists() {
		return nil, nil
	}
	db, err := s.conn(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, "SELECT "+selectColumns+" FROM api_tokens ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*Token
	for rows.Next() {
		token, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, token)
	}
	return out, rows.Err()
}

// Revoke revokes an active token; false when no active token has that id.
func (s *Store) Revoke(ctx context.Context, id int64) (bool, error) {
	if !s.exists() {
		return false, nil
	}
	db, err := s.conn(ctx)
	if err != nil {
		return false, err
	}
	res, err := db.ExecContext(ctx,
		"UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL", s.utcNow(), id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// Verify resolves a presented bearer secret to its active token. An unusable
// token is a *TokenError; any other error is a storage failure.
//
// The lookup is by SHA-256 of the presented value through the UNIQUE index,
// so no stored secret is ever compared byte by byte.
func (s *Store) Verify(ctx context.Context, raw string) (*Token, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, TokenPrefix) || len(raw) > maxRawTokenLength {
		return nil, tokenError("Invalid API token")
	}
	if !s.exists() {
		// No token was ever minted on this host; do not create the database
		// as a side effect of an unauthenticated request.
		return nil, tokenError("Invalid API token")
	}
	db, err := s.conn(ctx)
	if err != nil {
		return nil, err
	}
	token, err := scanToken(db.QueryRowContext(ctx,
		"SELECT "+selectColumns+" FROM api_tokens WHERE token_hash = ?", hashToken(raw)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, tokenError("Invalid API token")
	}
	if err != nil {
		return nil, err
	}
	if token.RevokedAt != "" {
		return nil, tokenError("This API token has been revoked")
	}
	if len(token.Scopes) == 0 {
		return nil, tokenError("This API token carries no usable scope")
	}
	stale := true
	if token.LastUsedAt != "" {
		if last, err := time.Parse(time.RFC3339, token.LastUsedAt); err == nil {
			stale = s.now().Sub(last) >= LastUsedResolutionSeconds*time.Second
		}
	}
	if stale {
		now := s.utcNow()
		if _, err := db.ExecContext(ctx, "UPDATE api_tokens SET last_used_at = ? WHERE id = ?", now, token.ID); err != nil {
			return nil, err
		}
		token.LastUsedAt = now
	}
	return token, nil
}
