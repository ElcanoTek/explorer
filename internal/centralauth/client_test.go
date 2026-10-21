// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package centralauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

const testSecret = "a-random-client-secret-with-32-bytes"

var idNow = time.Unix(1_800_000_000, 0)

// tokenServer is a fake Auth /token endpoint.
type tokenServer struct {
	*httptest.Server
	status   int
	body     []byte
	lastForm url.Values
	lastAuth string
	lastPath string
	redirect string
}

func newTokenServer(t *testing.T) *tokenServer {
	ts := &tokenServer{status: http.StatusOK}
	ts.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ts.redirect != "" {
			http.Redirect(w, r, ts.redirect, http.StatusTemporaryRedirect)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		ts.lastForm, _ = url.ParseQuery(string(raw))
		ts.lastAuth = r.Header.Get("Authorization")
		ts.lastPath = r.Method + " " + r.URL.Path
		w.WriteHeader(ts.status)
		_, _ = w.Write(ts.body)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func newTestClient(t *testing.T, ts *tokenServer) *Client {
	t.Helper()
	c, err := NewClient(ClientOptions{
		IssuerURL: ts.URL, PublicURL: "https://explorer.example.com",
		ClientID: "explorer", ClientSecret: testSecret, HTTPClient: ts.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	c.SetClock(func() time.Time { return idNow })
	return c
}

// tokenResponse is Auth's /token body: plain claims plus the signed id_token.
func tokenResponse(t *testing.T, idToken any, plain map[string]any) []byte {
	t.Helper()
	body := map[string]any{"sub": "account-123", "email": "alice@example.com"}
	for k, v := range plain {
		body[k] = v
	}
	if idToken != deleteClaim {
		body["id_token"] = idToken
	}
	return mustJSON(t, body)
}

func idFor(t *testing.T, k key, issuer string, overrides map[string]any) string {
	return mintID(t, k, idNow.Unix(), nil, merge(map[string]any{"iss": issuer}, overrides))
}

func staticKeys(keys ...key) func(string) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.pub)
	}
	return func(string) []string { return out }
}

func TestExchangeAuthenticatesClientAndValidatesNonce(t *testing.T) {
	k := newKey(t)
	ts := newTokenServer(t)
	c := newTestClient(t, ts)
	ts.body = tokenResponse(t, idFor(t, k, c.IssuerURL(), nil), nil)
	p, err := c.Exchange(context.Background(), "single-use-code", "pkce-verifier", "expected-nonce", staticKeys(k))
	if err != nil || p.Subject != "account-123" || p.Email != "alice@example.com" {
		t.Fatalf("%+v %v", p, err)
	}
	if ts.lastPath != "POST /token" || !strings.HasPrefix(ts.lastAuth, "Basic ") {
		t.Fatalf("request %q auth %q", ts.lastPath, ts.lastAuth)
	}
	creds, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(ts.lastAuth, "Basic "))
	if string(creds) != "explorer:"+testSecret {
		t.Fatalf("credentials %q", creds)
	}
	want := url.Values{
		"grant_type": {"authorization_code"}, "code": {"single-use-code"},
		"redirect_uri": {"https://explorer.example.com/auth/callback"},
		"client_id":    {"explorer"}, "code_verifier": {"pkce-verifier"},
	}
	if !reflect.DeepEqual(ts.lastForm, want) {
		t.Fatalf("form %v", ts.lastForm)
	}
	if c.Timeout() != 10*time.Second {
		t.Fatalf("timeout %v", c.Timeout())
	}
}

func TestAuthorizationURLUsesExactCallbackAndPKCE(t *testing.T) {
	c, err := NewClient(ClientOptions{
		IssuerURL: "https://auth.example.com", PublicURL: "https://explorer.example.com",
		ClientID: "explorer", ClientSecret: testSecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := c.AuthorizationURL("browser-state", "s256-challenge", "nonce")
	if !strings.HasPrefix(raw, "https://auth.example.com/authorize?response_type=code&client_id=explorer&") {
		t.Fatalf("url %s", raw)
	}
	u, _ := url.Parse(raw)
	want := url.Values{
		"response_type": {"code"}, "client_id": {"explorer"},
		"redirect_uri": {"https://explorer.example.com/auth/callback"}, "scope": {"email"},
		"state": {"browser-state"}, "code_challenge": {"s256-challenge"},
		"code_challenge_method": {"S256"}, "nonce": {"nonce"},
	}
	if !reflect.DeepEqual(u.Query(), want) {
		t.Fatalf("query %v", u.Query())
	}
}

func TestIdentityComesFromSignedTokenNotPlainClaims(t *testing.T) {
	k := newKey(t)
	ts := newTokenServer(t)
	c := newTestClient(t, ts)
	ts.body = tokenResponse(t, idFor(t, k, c.IssuerURL(), nil), map[string]any{"sub": "account-666", "email": "mallory@example.com"})
	p, err := c.Exchange(context.Background(), "c", "v", "expected-nonce", staticKeys(k))
	if err != nil || p.Subject != "account-123" || p.Email != "alice@example.com" {
		t.Fatalf("%+v %v", p, err)
	}
}

func TestExchangeRequiresAValidIDToken(t *testing.T) {
	k := newKey(t)
	ts := newTokenServer(t)
	c := newTestClient(t, ts)
	good := idFor(t, k, c.IssuerURL(), nil)
	parts := strings.Split(good, ".")
	var claims map[string]any
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(raw, &claims)
	claims["email"] = "mallory@example.com"
	tampered := parts[0] + "." + b64url(mustJSON(t, claims)) + "." + parts[2]
	cases := map[string][]byte{
		"missing":        tokenResponse(t, deleteClaim, nil),
		"empty":          tokenResponse(t, "", nil),
		"not a string":   tokenResponse(t, 42, nil),
		"garbage":        tokenResponse(t, "not.a.jwt", nil),
		"tampered":       tokenResponse(t, tampered, nil),
		"unknown key":    tokenResponse(t, idFor(t, newKey(t), c.IssuerURL(), nil), nil),
		"wrong nonce":    tokenResponse(t, idFor(t, k, c.IssuerURL(), map[string]any{"nonce": "x"}), nil),
		"not json":       []byte("<html>"),
		"json array":     []byte("[]"),
		"wrong issuer":   tokenResponse(t, idFor(t, k, "https://auth.example.com", nil), nil),
		"wrong audience": tokenResponse(t, idFor(t, k, c.IssuerURL(), map[string]any{"aud": "lens"}), nil),
	}
	for name, body := range cases {
		ts.body = body
		_, err := c.Exchange(context.Background(), "c", "v", "expected-nonce", staticKeys(k))
		if err == nil || !strings.Contains(err.Error(), "invalid") || !errors.Is(err, ErrCentralAuth) || errors.Is(err, ErrCodeRejected) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestExchangeAcceptsKeyKnownOnlyFromJWKS(t *testing.T) {
	static, rotated := newKey(t), newKey(t)
	ts := newTokenServer(t)
	c := newTestClient(t, ts)
	jwks := &fakeJWKS{doc: jwksFor(rotated)}
	r := NewKeyResolver(c.IssuerURL(), []string{static.pub}, jwks.fetch, func() time.Time { return idNow })
	ts.body = tokenResponse(t, idFor(t, rotated, c.IssuerURL(), nil), nil)
	p, err := c.Exchange(context.Background(), "c", "v", "expected-nonce", r.KeysForToken)
	if err != nil || p.Email != "alice@example.com" {
		t.Fatalf("%+v %v", p, err)
	}
	if !reflect.DeepEqual(jwks.urls, []string{c.IssuerURL() + "/jwks.json"}) {
		t.Fatalf("fetched %v", jwks.urls)
	}
}

func TestTokenEndpointStatusMapping(t *testing.T) {
	k := newKey(t)
	ts := newTokenServer(t)
	c := newTestClient(t, ts)
	ts.status = http.StatusBadRequest
	if _, err := c.Exchange(context.Background(), "c", "v", "n", staticKeys(k)); !errors.Is(err, ErrCodeRejected) {
		t.Fatalf("400: %v", err)
	}
	for _, status := range []int{http.StatusUnauthorized, http.StatusInternalServerError, http.StatusFound} {
		ts.status = status
		_, err := c.Exchange(context.Background(), "c", "v", "n", staticKeys(k))
		if !errors.Is(err, ErrCentralAuth) || errors.Is(err, ErrCodeRejected) {
			t.Errorf("%d: %v", status, err)
		}
	}
	ts.status = http.StatusOK
	ts.body = make([]byte, MaxTokenResponseBytes+1)
	if _, err := c.Exchange(context.Background(), "c", "v", "n", staticKeys(k)); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("oversize: %v", err)
	}
}

func TestExchangeNeverFollowsRedirects(t *testing.T) {
	hits := 0
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer target.Close()
	ts := newTokenServer(t)
	ts.redirect = target.URL + "/steal"
	c := newTestClient(t, ts)
	if _, err := c.Exchange(context.Background(), "c", "v", "n", staticKeys(newKey(t))); err == nil || hits != 0 {
		t.Fatalf("err=%v hits=%d", err, hits)
	}
}

func TestClientRequiresHTTPSAndAStrongSecret(t *testing.T) {
	base := ClientOptions{
		IssuerURL: "https://auth.example.com", PublicURL: "https://explorer.example.com",
		ClientID: "explorer", ClientSecret: testSecret,
	}
	if _, err := NewClient(base); err != nil {
		t.Fatal(err)
	}
	mutate := func(f func(*ClientOptions)) ClientOptions { o := base; f(&o); return o }
	bad := map[string]ClientOptions{
		"http issuer":     mutate(func(o *ClientOptions) { o.IssuerURL = "http://auth.example.com" }),
		"issuer path":     mutate(func(o *ClientOptions) { o.IssuerURL = "https://auth.example.com/x" }),
		"issuer query":    mutate(func(o *ClientOptions) { o.IssuerURL = "https://auth.example.com/?a=b" }),
		"issuer fragment": mutate(func(o *ClientOptions) { o.IssuerURL = "https://auth.example.com#f" }),
		"issuer userinfo": mutate(func(o *ClientOptions) { o.IssuerURL = "https://u:p@auth.example.com" }),
		"issuer empty":    mutate(func(o *ClientOptions) { o.IssuerURL = "" }),
		"public relative": mutate(func(o *ClientOptions) { o.PublicURL = "/explorer" }),
		"short secret":    mutate(func(o *ClientOptions) { o.ClientSecret = "short" }),
		"colon secret":    mutate(func(o *ClientOptions) { o.ClientSecret = testSecret + ":" }),
		"long secret":     mutate(func(o *ClientOptions) { o.ClientSecret = strings.Repeat("s", 257) }),
		"colon id":        mutate(func(o *ClientOptions) { o.ClientID = "a:b" }),
		"empty id":        mutate(func(o *ClientOptions) { o.ClientID = " " }),
		"long id":         mutate(func(o *ClientOptions) { o.ClientID = strings.Repeat("i", 129) }),
		"timeout zero":    mutate(func(o *ClientOptions) { o.TimeoutRaw = "0" }),
		"timeout big":     mutate(func(o *ClientOptions) { o.TimeoutRaw = "61" }),
		"timeout nan":     mutate(func(o *ClientOptions) { o.TimeoutRaw = "nan" }),
		"timeout word":    mutate(func(o *ClientOptions) { o.TimeoutRaw = "soon" }),
	}
	for name, o := range bad {
		if _, err := NewClient(o); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	dev := mutate(func(o *ClientOptions) { o.IssuerURL = "http://localhost:9000/"; o.AllowInsecureHTTP = true })
	c, err := NewClient(dev)
	if err != nil || c.IssuerURL() != "http://localhost:9000" {
		t.Fatalf("dev client: %v %v", c, err)
	}
	if errs := ValidateClientSettings(mutate(func(o *ClientOptions) { o.ClientSecret = "x"; o.TimeoutRaw = "0" })); len(errs) != 2 {
		t.Fatalf("ValidateClientSettings = %v", errs)
	}
}
