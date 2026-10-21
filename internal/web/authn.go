// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ElcanoTek/explorer/internal/auth"
	"github.com/ElcanoTek/explorer/internal/centralauth"
	"github.com/ElcanoTek/explorer/internal/config"
)

// provider is what differs between the two authentication modes.
type provider interface {
	mode() string
	identity(r *http.Request) *auth.Identity
	unauthenticated(w http.ResponseWriter, r *http.Request)
	close() error
}

func buildProvider(s config.Settings, httpClient *http.Client, now func() time.Time) (provider, error) {
	switch s.AuthMode {
	case "elcano":
		return &elcanoProvider{settings: s, now: now}, nil
	case "central":
		return newCentralProvider(s, httpClient, now)
	default:
		return nil, errors.New("EXPLORER_AUTH_MODE must be either 'elcano' or 'central'")
	}
}

// elcanoProvider verifies the cookie minted by Elcano's magic-link service
// with that service's Ed25519 public key. Explorer holds only the public
// half, so a compromised Explorer host cannot mint sessions.
type elcanoProvider struct {
	settings config.Settings
	now      func() time.Time
}

func (p *elcanoProvider) mode() string { return "elcano" }
func (p *elcanoProvider) close() error { return nil }

func (p *elcanoProvider) identity(r *http.Request) *auth.Identity {
	ck, err := r.Cookie(p.settings.AuthCookieName)
	if err != nil {
		return nil
	}
	return auth.VerifyElcanoCookie(ck.Value, p.settings.AuthSigningPubkey, p.now())
}

func (p *elcanoProvider) unauthenticated(w http.ResponseWriter, r *http.Request) {
	target := p.settings.AuthLoginURL + "/?return_to=" + quoteAll(requestURL(r))
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// centralProvider runs the authorization-code flow against the client's
// central auth service, then applies Explorer's own email allow-list and
// issues an opaque, app-scoped session.
type centralProvider struct {
	settings   config.Settings
	client     *centralauth.Client
	keys       *centralauth.KeyResolver
	store      *centralauth.Store
	cookieName string
	secure     bool
	now        func() time.Time
}

func newCentralProvider(s config.Settings, httpClient *http.Client, now func() time.Time) (*centralProvider, error) {
	if (!s.AuthCookieSecure || !s.UICookieSecure) && !s.AuthAllowInsecureHTTP {
		return nil, errors.New("central auth requires Secure app and UI cookies; insecure HTTP is only allowed for development")
	}
	if s.SessionSecret == "" || s.SessionSecret == config.DevSessionSecret {
		return nil, errors.New("central auth requires a generated EXPLORER_SESSION_SECRET for login state")
	}
	keys := s.SigningKeys()
	if err := centralauth.RequireSigningKeys(keys); err != nil {
		return nil, err
	}
	client, err := centralauth.NewClient(centralauth.ClientOptions{
		IssuerURL:         s.AuthIssuerURL,
		PublicURL:         s.PublicURL,
		ClientID:          s.AuthClientID,
		ClientSecret:      s.AuthClientSecret,
		TimeoutRaw:        s.AuthHTTPTimeoutRaw,
		AllowInsecureHTTP: s.AuthAllowInsecureHTTP,
		HTTPClient:        httpClient,
	})
	if err != nil {
		return nil, err
	}
	store, err := centralauth.OpenStore(s.AccessDB,
		time.Duration(s.SessionIdleSeconds)*time.Second, time.Duration(s.SessionAbsoluteSeconds)*time.Second)
	if err != nil {
		return nil, fmt.Errorf("open access database: %w", err)
	}
	store.Now = now
	cookie := centralauth.CookieName
	if !s.AuthCookieSecure {
		cookie = centralauth.InsecureCookieName
	}
	return &centralProvider{
		settings: s, client: client, store: store, now: now,
		keys:       centralauth.NewKeyResolver(client.IssuerURL(), keys, fetchFor(httpClient), now),
		cookieName: cookie, secure: s.AuthCookieSecure,
	}, nil
}

// fetchFor is the JWKS fetcher; nil keeps the resolver's default client.
func fetchFor(c *http.Client) centralauth.FetchFunc {
	if c == nil {
		return nil
	}
	return centralauth.DefaultFetch(c)
}

func (p *centralProvider) mode() string { return "central" }
func (p *centralProvider) close() error { return p.store.Close() }

func (p *centralProvider) sessionToken(r *http.Request) string {
	if ck, err := r.Cookie(p.cookieName); err == nil {
		return ck.Value
	}
	return ""
}

func (p *centralProvider) identity(r *http.Request) *auth.Identity {
	tok := p.sessionToken(r)
	if tok == "" {
		return nil
	}
	return p.store.GetIdentity(tok)
}

func (p *centralProvider) unauthenticated(w http.ResponseWriter, r *http.Request) {
	target := r.URL.RequestURI()
	if len(target) > 2048 {
		target = "/"
	}
	http.Redirect(w, r, "/auth/login?next="+quoteAll(target), http.StatusSeeOther) //nolint:gosec // G710: a fixed local path; the target is percent-encoded data.
}

func (p *centralProvider) csrfToken(r *http.Request) string {
	if tok := p.sessionToken(r); tok != "" {
		return centralauth.CSRFToken(tok)
	}
	return ""
}

// quoteAll percent-encodes everything but RFC 3986 unreserved characters,
// like Python's quote(value, safe="").
func quoteAll(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (p *centralProvider) beginLogin(w http.ResponseWriter, r *http.Request, next string) {
	if len(next) > 2048 {
		next = "/"
	}
	tx := &loginTransaction{
		State:     centralauth.RandomToken(),
		Nonce:     centralauth.RandomToken(),
		Verifier:  centralauth.RandomToken() + centralauth.RandomToken(),
		Next:      next,
		CreatedAt: p.now().Unix(),
	}
	sess := sessionFrom(r)
	sess.data.Login = tx
	sess.dirty = true
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, p.client.AuthorizationURL(tx.State, pkceChallenge(tx.Verifier), tx.Nonce), http.StatusSeeOther)
}

// completeLogin checks the callback against the pending transaction,
// redeems the code and creates the app session. It returns the session
// token and where to send the browser.
func (p *centralProvider) completeLogin(r *http.Request, code, state string) (string, string, error) {
	sess := sessionFrom(r)
	tx := sess.data.Login
	sess.data.Login = nil
	sess.dirty = true
	now := p.now().Unix()
	if tx == nil || tx.State == "" || tx.Verifier == "" || tx.Nonce == "" ||
		!hmac.Equal([]byte(tx.State), []byte(state)) ||
		now < tx.CreatedAt || now-tx.CreatedAt > int64(centralauth.LoginTransaction/time.Second) {
		return "", "", centralauth.ErrTransaction
	}
	principal, err := p.client.Exchange(r.Context(), code, tx.Verifier, tx.Nonce, p.keys.KeysForToken)
	if err != nil {
		return "", "", err
	}
	issued, err := p.store.CreateSession(principal.Subject, principal.Email)
	if err != nil {
		return "", "", err
	}
	return issued.Token, tx.Next, nil
}

// The session and clearing cookies are Secure unless the operator turned
// EXPLORER_AUTH_COOKIE_SECURE off, which startup refuses outside development.
func (p *centralProvider) sessionCookie(token string) *http.Cookie {
	return &http.Cookie{ //nolint:gosec // G124: Secure follows config; HttpOnly and SameSite are set.
		Name: p.cookieName, Value: token, Path: "/", Secure: p.secure, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: p.settings.SessionAbsoluteSeconds,
	}
}

func (p *centralProvider) clearCookie() *http.Cookie {
	return &http.Cookie{ //nolint:gosec // G124: Secure follows config; HttpOnly and SameSite are set.
		Name: p.cookieName, Value: "", Path: "/", Secure: p.secure, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: -1,
	}
}
