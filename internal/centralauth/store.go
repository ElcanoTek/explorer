// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package centralauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ElcanoTek/explorer/internal/auth"

	_ "modernc.org/sqlite" // database/sql driver "sqlite"
)

// schemaSQL is the access database DDL, unchanged from the Python service so
// an existing /var/lib/explorer/access.db keeps working.
const schemaSQL = `
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS access_entries (
    email TEXT PRIMARY KEY COLLATE NOCASE,
    enabled INTEGER NOT NULL DEFAULT 1
        CHECK (enabled IN (0, 1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    email TEXT NOT NULL REFERENCES access_entries(email),
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    idle_expires_at INTEGER NOT NULL,
    absolute_expires_at INTEGER NOT NULL,
    revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS sessions_email_idx ON sessions(email);
CREATE INDEX IF NOT EXISTS sessions_expiry_idx
    ON sessions(absolute_expires_at, idle_expires_at);

CREATE TABLE IF NOT EXISTS revocation_events (
    event_id TEXT PRIMARY KEY,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    received_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS access_provisioning_state (
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    email TEXT NOT NULL,
    version INTEGER NOT NULL,
    allowed INTEGER NOT NULL CHECK (allowed IN (0, 1)),
    event_id TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    PRIMARY KEY (issuer, subject)
);
`

// AccessEntry is one email on the access list.
type AccessEntry struct {
	Email     string
	Enabled   bool
	CreatedAt int64
	UpdatedAt int64
}

// IssuedSession is a new app session: the token goes in the cookie, only
// its hash is stored.
type IssuedSession struct {
	Token     string
	TokenHash string
}

// Store is the SQLite-backed email allowlist and revocable app sessions.
type Store struct {
	path     string
	db       *sql.DB
	idle     time.Duration
	absolute time.Duration
	// Now is the store's clock; tests replace it.
	Now func() time.Time
}

// OpenStore opens (creating when needed) the access database at path.
func OpenStore(path string, idle, absolute time.Duration) (*Store, error) {
	if idle <= 0 || absolute <= 0 {
		return nil, errors.New("session timeouts must be positive")
	}
	if idle > absolute {
		return nil, errors.New("idle timeout may not exceed absolute timeout")
	}
	if path == "" || strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("unsupported access database path %q", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create access database directory: %w", err)
	}
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	s := &Store{path: path, db: db, idle: idle, absolute: absolute, Now: time.Now}
	if err := s.initialize(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) initialize() error {
	ctx := context.Background()
	if _, err := s.db.ExecContext(ctx, schemaSQL); err != nil {
		return fmt.Errorf("initialize access database: %w", err)
	}
	return s.tx(func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			"INSERT OR IGNORE INTO schema_meta(key, value) VALUES('schema_version', ?)",
			strconv.Itoa(SchemaVersion)); err != nil {
			return err
		}
		var raw string
		if err := tx.QueryRowContext(ctx, "SELECT value FROM schema_meta WHERE key = 'schema_version'").Scan(&raw); err != nil {
			return err
		}
		v, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil || v > SchemaVersion {
			return errors.New("unsupported Explorer access database schema version")
		}
		_, err = tx.ExecContext(ctx, "UPDATE schema_meta SET value = ? WHERE key = 'schema_version'", strconv.Itoa(SchemaVersion))
		return err
	})
}

// Path is the database file.
func (s *Store) Path() string { return s.path }

// Idle is the idle session lifetime.
func (s *Store) Idle() time.Duration { return s.idle }

// Absolute is the absolute session lifetime.
func (s *Store) Absolute() time.Duration { return s.absolute }

// AbsoluteSeconds is the cookie Max-Age.
func (s *Store) AbsoluteSeconds() int { return int(s.absolute / time.Second) }

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) now() int64 { return s.Now().Unix() }

// tx runs fn in a BEGIN IMMEDIATE transaction (the DSN's _txlock).
func (s *Store) tx(fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func tokenHash(token string) (string, bool) {
	for i := 0; i < len(token); i++ {
		if token[i] >= 0x80 {
			return "", false
		}
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:]), true
}

// RandomToken is 32 random bytes, base64url without padding.
func RandomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// CSRFToken binds a logout form to the app session secret.
func CSRFToken(sessionToken string) string {
	mac := hmac.New(sha256.New, []byte(sessionToken))
	mac.Write([]byte(csrfMessage))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyCSRF checks a submitted CSRF token against the session token.
func VerifyCSRF(sessionToken, submitted string) bool {
	if sessionToken == "" || submitted == "" {
		return false
	}
	return hmac.Equal([]byte(CSRFToken(sessionToken)), []byte(submitted))
}

func scanEntry(row interface{ Scan(...any) error }) (AccessEntry, error) {
	var e AccessEntry
	var enabled int64
	err := row.Scan(&e.Email, &enabled, &e.CreatedAt, &e.UpdatedAt)
	e.Enabled = enabled != 0
	return e, err
}

// GrantAccess allows email (re-enabling a revoked entry).
func (s *Store) GrantAccess(email string) (AccessEntry, error) {
	normalized, err := NormalizeEmail(email)
	if err != nil {
		return AccessEntry{}, err
	}
	now := s.now()
	if _, err := s.db.ExecContext(context.Background(), `
		INSERT INTO access_entries(email, enabled, created_at, updated_at)
		VALUES (?, 1, ?, ?)
		ON CONFLICT(email) DO UPDATE SET enabled = 1, updated_at = excluded.updated_at`,
		normalized, now, now); err != nil {
		return AccessEntry{}, err
	}
	return s.GetAccess(normalized)
}

// GetAccess returns email's entry, or ErrAccessDenied when absent.
func (s *Store) GetAccess(email string) (AccessEntry, error) {
	normalized, err := NormalizeEmail(email)
	if err != nil {
		return AccessEntry{}, err
	}
	e, err := scanEntry(s.db.QueryRowContext(context.Background(),
		"SELECT email, enabled, created_at, updated_at FROM access_entries WHERE email = ?", normalized))
	if errors.Is(err, sql.ErrNoRows) {
		return AccessEntry{}, newErr(ErrAccessDenied, "Email is not on this Explorer access list")
	}
	return e, err
}

// ListAccess lists allowed emails, or every known email.
func (s *Store) ListAccess(includeDisabled bool) ([]AccessEntry, error) {
	q := "SELECT email, enabled, created_at, updated_at FROM access_entries WHERE enabled = 1 ORDER BY email"
	if includeDisabled {
		q = "SELECT email, enabled, created_at, updated_at FROM access_entries ORDER BY email"
	}
	rows, err := s.db.QueryContext(context.Background(), q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccessEntry
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// IsAllowed reports whether email is enabled. Invalid emails are not.
func (s *Store) IsAllowed(email string) bool {
	normalized, err := NormalizeEmail(email)
	if err != nil {
		return false
	}
	var enabled int64
	err = s.db.QueryRowContext(context.Background(),
		"SELECT enabled FROM access_entries WHERE email = ?", normalized).Scan(&enabled)
	return err == nil && enabled != 0
}

// RevokeAccess disables email and revokes all its sessions; false when it
// was not currently allowed.
func (s *Store) RevokeAccess(email string) (bool, error) {
	normalized, err := NormalizeEmail(email)
	if err != nil {
		return false, err
	}
	now := s.now()
	var changed int64
	err = s.tx(func(tx *sql.Tx) error {
		res, err := tx.ExecContext(context.Background(), "UPDATE access_entries SET enabled = 0, updated_at = ? WHERE email = ? AND enabled = 1", now, normalized)
		if err != nil {
			return err
		}
		changed, _ = res.RowsAffected()
		_, err = tx.ExecContext(context.Background(), "UPDATE sessions SET revoked_at = ? WHERE email = ? AND revoked_at IS NULL", now, normalized)
		return err
	})
	return changed > 0, err
}

// CreateSession issues a session for an allowed email.
func (s *Store) CreateSession(subject, email string) (IssuedSession, error) {
	normalized, err := NormalizeEmail(email)
	if err != nil {
		return IssuedSession{}, err
	}
	if subject == "" || !utf8.ValidString(subject) || utf8.RuneCountInString(subject) > maxIdentifierLength || hasOtherChar(subject) {
		return IssuedSession{}, newErr(ErrCentralAuth, "The authenticated account identifier is invalid")
	}
	now := s.now()
	absoluteExpires := now + int64(s.absolute/time.Second)
	idleExpires := min(now+int64(s.idle/time.Second), absoluteExpires)
	token := RandomToken()
	hash, _ := tokenHash(token)
	err = s.tx(func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(context.Background(), "DELETE FROM sessions WHERE revoked_at IS NOT NULL OR absolute_expires_at <= ?", now); err != nil {
			return err
		}
		var one int
		err := tx.QueryRowContext(context.Background(), "SELECT 1 FROM access_entries WHERE email = ? AND enabled = 1", normalized).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return newErr(ErrAccessDenied, "Email is not on this Explorer access list")
		}
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(context.Background(), `
			INSERT INTO sessions(
				token_hash, subject, email, created_at, last_seen_at,
				idle_expires_at, absolute_expires_at, revoked_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
			hash, subject, normalized, now, now, idleExpires, absoluteExpires)
		return err
	})
	if err != nil {
		return IssuedSession{}, err
	}
	return IssuedSession{Token: token, TokenHash: hash}, nil
}

// GetIdentity returns the identity for a live session token, or nil. An
// expired or disabled session is revoked on sight. The idle clock is written
// at most once per SessionTouch. Database errors fail closed.
func (s *Store) GetIdentity(token string) *auth.Identity {
	if token == "" {
		return nil
	}
	hash, ok := tokenHash(token)
	if !ok {
		return nil
	}
	now := s.now()
	ctx := context.Background()
	var subject, email string
	var lastSeen, idleExp, absExp, enabled int64
	// Plain read first: most requests fall inside the touch interval and
	// must not take the write lock.
	err := s.db.QueryRowContext(ctx, `
		SELECT s.subject, s.email, s.last_seen_at, s.idle_expires_at,
		       s.absolute_expires_at, a.enabled
		FROM sessions AS s
		JOIN access_entries AS a ON a.email = s.email
		WHERE s.token_hash = ? AND s.revoked_at IS NULL`, hash).
		Scan(&subject, &email, &lastSeen, &idleExp, &absExp, &enabled)
	if err != nil {
		return nil
	}
	if enabled == 0 || now >= idleExp || now >= absExp {
		_, _ = s.db.ExecContext(ctx, "UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL", now, hash)
		return nil
	}
	if now-lastSeen >= int64(SessionTouch/time.Second) {
		nextIdle := min(now+int64(s.idle/time.Second), absExp)
		if _, err := s.db.ExecContext(ctx, `
			UPDATE sessions SET last_seen_at = ?, idle_expires_at = ?
			WHERE token_hash = ? AND revoked_at IS NULL`, now, nextIdle, hash); err != nil {
			return nil
		}
	}
	return &auth.Identity{Subject: subject, Email: email, Provider: "central"}
}

// RevokeSession revokes one session; true when it was live.
func (s *Store) RevokeSession(token string) bool {
	hash, ok := tokenHash(token)
	if token == "" || !ok {
		return false
	}
	res, err := s.db.ExecContext(context.Background(),
		"UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL", s.now(), hash)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

// ConsumeLogoutEvent records a back-channel logout once and revokes every
// session of its subject; false for a replay.
func (s *Store) ConsumeLogoutEvent(ev LogoutEvent) (bool, error) {
	now := s.now()
	var inserted int64
	err := s.tx(func(tx *sql.Tx) error {
		// Replay protection only needs to outlive a token's acceptance
		// window (minutes); a week is kept for forensics.
		if _, err := tx.ExecContext(context.Background(), "DELETE FROM revocation_events WHERE received_at < ?",
			now-int64(RevocationEventRetention/time.Second)); err != nil {
			return err
		}
		res, err := tx.ExecContext(context.Background(), `
			INSERT OR IGNORE INTO revocation_events(event_id, issuer, subject, issued_at, received_at)
			VALUES (?, ?, ?, ?, ?)`, ev.EventID, ev.Issuer, ev.Subject, ev.IssuedAt, now)
		if err != nil {
			return err
		}
		inserted, _ = res.RowsAffected()
		if inserted > 0 {
			_, err = tx.ExecContext(context.Background(), "UPDATE sessions SET revoked_at = ? WHERE subject = ? AND revoked_at IS NULL", now, ev.Subject)
		}
		return err
	})
	return inserted > 0, err
}

// ApplyAccessProvisioning applies only a newer desired-state version,
// atomically and idempotently; false when the event is stale or a replay.
func (s *Store) ApplyAccessProvisioning(ev AccessProvisionEvent) (bool, error) {
	now := s.now()
	applied := false
	err := s.tx(func(tx *sql.Tx) error {
		var oldEmail string
		var version int64
		err := tx.QueryRowContext(context.Background(), "SELECT email, version FROM access_provisioning_state WHERE issuer = ? AND subject = ?",
			ev.Issuer, ev.Subject).Scan(&oldEmail, &version)
		switch {
		case err == nil && version >= ev.Version:
			return nil
		case err != nil && !errors.Is(err, sql.ErrNoRows):
			return err
		}
		if oldEmail != "" && oldEmail != ev.Email {
			if _, err := tx.ExecContext(context.Background(), "UPDATE access_entries SET enabled = 0, updated_at = ? WHERE email = ?", now, oldEmail); err != nil {
				return err
			}
			if _, err := tx.ExecContext(context.Background(), "UPDATE sessions SET revoked_at = ? WHERE email = ? AND revoked_at IS NULL", now, oldEmail); err != nil {
				return err
			}
		}
		allowed := 0
		if ev.Allowed {
			allowed = 1
		}
		if _, err := tx.ExecContext(context.Background(), `
			INSERT INTO access_entries(email, enabled, created_at, updated_at)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(email) DO UPDATE SET
				enabled = excluded.enabled, updated_at = excluded.updated_at`,
			ev.Email, allowed, now, now); err != nil {
			return err
		}
		if !ev.Allowed {
			if _, err := tx.ExecContext(context.Background(), "UPDATE sessions SET revoked_at = ? WHERE email = ? AND revoked_at IS NULL", now, ev.Email); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(context.Background(), `
			INSERT INTO access_provisioning_state(
				issuer, subject, email, version, allowed, event_id, issued_at, received_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(issuer, subject) DO UPDATE SET
				email = excluded.email, version = excluded.version,
				allowed = excluded.allowed, event_id = excluded.event_id,
				issued_at = excluded.issued_at, received_at = excluded.received_at`,
			ev.Issuer, ev.Subject, ev.Email, ev.Version, allowed, ev.EventID, ev.IssuedAt, now); err != nil {
			return err
		}
		applied = true
		return nil
	})
	return applied, err
}

// Backup writes a transactionally consistent copy of the database to dest
// (SQLite's VACUUM INTO) while the service keeps running. dest must not
// exist; the copy is made owner-only.
func (s *Store) Backup(ctx context.Context, dest string) error {
	if strings.ContainsAny(dest, "?#") {
		return errors.New("backup path may not contain '?' or '#'")
	}
	if _, err := os.Lstat(dest); err == nil {
		return fmt.Errorf("%s already exists", dest)
	}
	if _, err := s.db.ExecContext(ctx, "VACUUM INTO ?", dest); err != nil {
		return fmt.Errorf("back up access database: %w", err)
	}
	return os.Chmod(dest, 0o600)
}
