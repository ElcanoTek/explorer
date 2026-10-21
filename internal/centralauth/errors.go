// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

// Package centralauth is Explorer's client for the central auth service and
// its local access boundary.
//
// Passwords and primary login sessions belong to the central auth service.
// Explorer receives a short-lived, one-time authorization code, exchanges it
// over a TLS backchannel, verifies the signed id_token that comes back,
// applies its deployment-local email allowlist, and then issues an opaque
// cookie that is useful only to this Explorer instance.
package centralauth

import "time"

// authError carries a safe message and the kind it belongs to, so callers
// branch with errors.Is and show only messages written for people.
type authError struct {
	kind error
	msg  string
}

func (e *authError) Error() string { return e.msg }
func (e *authError) Unwrap() error { return e.kind }

func newErr(kind error, msg string) error { return &authError{kind: kind, msg: msg} }

var (
	// ErrCentralAuth is a safe, expected failure while completing central
	// authentication. Every other error here wraps it.
	ErrCentralAuth error = &authError{msg: "central authentication failed"}
	// ErrAccessDenied: the authenticated email is not enabled here.
	ErrAccessDenied = newErr(ErrCentralAuth, "access denied")
	// ErrTransaction: the browser callback did not match a live login.
	ErrTransaction = newErr(ErrCentralAuth, "sign-in transaction invalid")
	// ErrCodeRejected: the auth service refused the code (expired, replayed
	// or superseded). That is the user's retry, not an outage.
	ErrCodeRejected = newErr(ErrCentralAuth, "sign-in code rejected")
)

const (
	// CookieName is the host-only app session cookie used over HTTPS.
	CookieName = "__Host-explorer_session"
	// InsecureCookieName is used only when Secure cookies are disabled for
	// development (a __Host- cookie must be Secure).
	InsecureCookieName = "explorer_session"

	// Application sessions are deliberately short: expiry costs only a
	// redirect while the 30-day central session lives, and the limit bounds
	// a stolen cookie and forces a daily re-check with Auth (the Elcano
	// convention for every application session).
	DefaultIdle     = 12 * time.Hour
	DefaultAbsolute = 24 * time.Hour
	// SessionTouch is how often a validated session rewrites its idle clock:
	// the idle limit behaves as "12 hours minus at most one minute", and a
	// page's burst of requests costs one SQLite write. A constant on purpose.
	SessionTouch = 60 * time.Second
	// LoginTransaction bounds the state/nonce/PKCE transaction.
	LoginTransaction = 10 * time.Minute
	// ClockSkew tolerated between this host and the auth service.
	ClockSkew = 60 * time.Second

	SchemaVersion = 3

	MaxTokenResponseBytes = 64 * 1024
	MaxTokenBytes         = 16_384

	BackchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"
	ApplicationAccessEvent = "urn:elcanotek:event:application-access"

	RevocationEventRetention = 7 * 24 * time.Hour

	JWKSCacheTTL        = 10 * time.Minute
	JWKSMinRefresh      = 60 * time.Second
	MaxJWKSBytes        = 64 * 1024
	DefaultJWKSTimeout  = 5 * time.Second
	DefaultHTTPTimeout  = 10 * time.Second
	csrfMessage         = "explorer-central-csrf-v1"
	maxIdentifierLength = 255
)
