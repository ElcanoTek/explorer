// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package centralauth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ClientOptions configures the backchannel client. Values are the raw
// settings (AUTH_ISSUER_URL, EXPLORER_PUBLIC_URL, AUTH_CLIENT_ID,
// AUTH_CLIENT_SECRET, AUTH_HTTP_TIMEOUT_SECONDS, AUTH_ALLOW_INSECURE_HTTP).
type ClientOptions struct {
	IssuerURL         string
	PublicURL         string
	ClientID          string
	ClientSecret      string
	TimeoutRaw        string
	AllowInsecureHTTP bool
	HTTPClient        *http.Client
}

// Client is the backchannel client for the auth service's
// authorization-code API.
type Client struct {
	issuerURL    string
	publicURL    string
	clientID     string
	clientSecret string
	timeout      time.Duration
	http         *http.Client
	now          func() time.Time
}

// ValidateOrigin returns scheme://host for an HTTPS (or, when allowHTTP,
// HTTP) origin with no credentials, path, query or fragment.
func ValidateOrigin(name, raw string, allowHTTP bool) (string, error) {
	requirement := "an HTTPS origin"
	if allowHTTP {
		requirement = "an HTTP(S) origin"
	}
	bad := fmt.Errorf("%s must be %s without a path or query", name, requirement)
	s := strings.Map(func(r rune) rune {
		if r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, strings.TrimSpace(raw))
	scheme, rest, ok := strings.Cut(s, ":")
	if !ok || scheme == "" {
		return "", bad
	}
	scheme = strings.ToLower(scheme)
	if scheme != "https" && (!allowHTTP || scheme != "http") {
		return "", bad
	}
	if !strings.HasPrefix(rest, "//") {
		return "", bad
	}
	rest = rest[2:]
	end := strings.IndexAny(rest, "/?#")
	netloc, tail := rest, ""
	if end >= 0 {
		netloc, tail = rest[:end], rest[end:]
	}
	if netloc == "" || strings.Contains(netloc, "@") || tail != "" && tail != "/" {
		return "", bad
	}
	if strings.Count(netloc, "[") != strings.Count(netloc, "]") {
		return "", bad
	}
	return scheme + "://" + netloc, nil
}

// ValidateClientID checks AUTH_CLIENT_ID: 1-128 characters without ':'.
func ValidateClientID(id string) (string, error) {
	id = strings.TrimSpace(id)
	if id == "" || strings.Contains(id, ":") || utf8.RuneCountInString(id) > 128 {
		return "", errors.New("AUTH_CLIENT_ID must be 1-128 characters without ':'")
	}
	return id, nil
}

// ValidateClientSecret checks AUTH_CLIENT_SECRET: at least 32 bytes, at
// most 256 characters, no ':' (it is sent as HTTP Basic credentials).
func ValidateClientSecret(secret string) error {
	if len(secret) < 32 {
		return errors.New("AUTH_CLIENT_SECRET must contain at least 32 bytes")
	}
	if utf8.RuneCountInString(secret) > 256 || strings.Contains(secret, ":") {
		return errors.New("AUTH_CLIENT_SECRET must be at most 256 characters without ':'")
	}
	return nil
}

// ParseTimeout reads AUTH_HTTP_TIMEOUT_SECONDS: a number in (0, 60]. Empty
// means the 10 s default.
func ParseTimeout(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultHTTPTimeout, nil
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(f) {
		return 0, errors.New("AUTH_HTTP_TIMEOUT_SECONDS must be a number")
	}
	if f <= 0 || f > 60 {
		return 0, errors.New("AUTH_HTTP_TIMEOUT_SECONDS must be between 0 and 60")
	}
	return time.Duration(f * float64(time.Second)), nil
}

// ValidateClientSettings reports every problem NewClient would refuse to
// start on, without network or database access (for `explorer doctor`).
func ValidateClientSettings(o ClientOptions) []error {
	var errs []error
	if _, err := ValidateOrigin("AUTH_ISSUER_URL", o.IssuerURL, o.AllowInsecureHTTP); err != nil {
		errs = append(errs, err)
	}
	if _, err := ValidateOrigin("EXPLORER_PUBLIC_URL", o.PublicURL, o.AllowInsecureHTTP); err != nil {
		errs = append(errs, err)
	}
	if _, err := ValidateClientID(o.ClientID); err != nil {
		errs = append(errs, err)
	}
	if err := ValidateClientSecret(o.ClientSecret); err != nil {
		errs = append(errs, err)
	}
	if _, err := ParseTimeout(o.TimeoutRaw); err != nil {
		errs = append(errs, err)
	}
	return errs
}

// NewClient validates o and returns a client, or the first problem.
func NewClient(o ClientOptions) (*Client, error) {
	if errs := ValidateClientSettings(o); len(errs) > 0 {
		return nil, errs[0]
	}
	issuer, _ := ValidateOrigin("AUTH_ISSUER_URL", o.IssuerURL, o.AllowInsecureHTTP)
	public, _ := ValidateOrigin("EXPLORER_PUBLIC_URL", o.PublicURL, o.AllowInsecureHTTP)
	id, _ := ValidateClientID(o.ClientID)
	timeout, _ := ParseTimeout(o.TimeoutRaw)
	base := o.HTTPClient
	if base == nil {
		base = &http.Client{}
	}
	hc := *base
	// Never forward a client credential through a token-endpoint redirect.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	hc.Timeout = timeout
	return &Client{
		issuerURL: issuer, publicURL: public, clientID: id, clientSecret: o.ClientSecret,
		timeout: timeout, http: &hc, now: time.Now,
	}, nil
}

// IssuerURL is the validated AUTH_ISSUER_URL origin.
func (c *Client) IssuerURL() string { return c.issuerURL }

// ClientID is the registered client ID.
func (c *Client) ClientID() string { return c.clientID }

// Timeout is the backchannel request timeout.
func (c *Client) Timeout() time.Duration { return c.timeout }

// CallbackURL is the exact redirect URI registered with Auth.
func (c *Client) CallbackURL() string { return c.publicURL + "/auth/callback" }

// SetClock replaces the clock used to check id_token times (tests).
func (c *Client) SetClock(now func() time.Time) { c.now = now }

type pair struct{ k, v string }

func encodeForm(pairs []pair) string {
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = url.QueryEscape(p.k) + "=" + url.QueryEscape(p.v)
	}
	return strings.Join(parts, "&")
}

// AuthorizationURL is the /authorize redirect for one login transaction.
func (c *Client) AuthorizationURL(state, codeChallenge, nonce string) string {
	return c.issuerURL + "/authorize?" + encodeForm([]pair{
		{"response_type", "code"},
		{"client_id", c.clientID},
		{"redirect_uri", c.CallbackURL()},
		{"scope", "email"},
		{"state", state},
		{"code_challenge", codeChallenge},
		{"code_challenge_method", "S256"},
		{"nonce", nonce},
	})
}

// Exchange redeems code at /token and verifies the id_token it returns.
// keysFor is KeyResolver.KeysForToken: static keys plus Auth's JWKS.
// A 400 is ErrCodeRejected (consumed, expired or superseded code); any other
// failure is ErrCentralAuth.
func (c *Client) Exchange(ctx context.Context, code, codeVerifier, expectedNonce string, keysFor func(string) []string) (Principal, error) {
	body := encodeForm([]pair{
		{"grant_type", "authorization_code"},
		{"code", code},
		{"redirect_uri", c.CallbackURL()},
		{"client_id", c.clientID},
		{"code_verifier", codeVerifier},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.issuerURL+"/token", strings.NewReader(body))
	if err != nil {
		return Principal{}, newErr(ErrCentralAuth, "The authentication service rejected the code exchange")
	}
	credentials := base64.StdEncoding.EncodeToString([]byte(c.clientID + ":" + c.clientSecret))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Basic "+credentials)
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return Principal{}, newErr(ErrCentralAuth, "The authentication service rejected the code exchange")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusBadRequest {
		return Principal{}, newErr(ErrCodeRejected, "The authentication service rejected the sign-in code")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Principal{}, newErr(ErrCentralAuth, "The authentication service rejected the code exchange")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxTokenResponseBytes+1))
	if err != nil {
		return Principal{}, newErr(ErrCentralAuth, "The authentication service rejected the code exchange")
	}
	if len(raw) > MaxTokenResponseBytes {
		return Principal{}, newErr(ErrCentralAuth, "The authentication response was too large")
	}
	payload, ok := decodeObject(raw)
	if !ok {
		return Principal{}, newErr(ErrCentralAuth, "The authentication response was invalid")
	}
	// Identity comes only from the signed id_token; the plain claims
	// alongside it in the response are not read.
	idToken, ok := payload["id_token"].(string)
	if !ok || idToken == "" {
		return Principal{}, newErr(ErrCentralAuth, "The authentication response was invalid")
	}
	return VerifyIdentityToken(idToken, c.issuerURL, c.clientID, expectedNonce, keysFor(idToken), c.now())
}
