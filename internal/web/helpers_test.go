// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package web

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ElcanoTek/explorer/internal/archive"
	"github.com/ElcanoTek/explorer/internal/centralauth"
	"github.com/ElcanoTek/explorer/internal/config"
)

// fakeStore is an in-memory S3: keys sorted, LastModified per object.
type fakeStore struct {
	mu      sync.Mutex
	objects map[string]fakeObject
	gets    int
}

type fakeObject struct {
	body []byte
	at   time.Time
}

func newFakeStore() *fakeStore { return &fakeStore{objects: map[string]fakeObject{}} }

func (f *fakeStore) put(key, body string, at time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key] = fakeObject{[]byte(body), at}
}

func (f *fakeStore) List(_ context.Context, prefix, token string, maxKeys int32) (archive.ListPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var keys []string
	for k := range f.objects {
		if strings.HasPrefix(k, prefix) && k > token {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	page := archive.ListPage{}
	for i, k := range keys {
		if maxKeys > 0 && int32(i) == maxKeys {
			page.NextToken = keys[i-1]
			break
		}
		o := f.objects[k]
		page.Objects = append(page.Objects, archive.Object{Key: k, LastModified: o.at, Size: int64(len(o.body))})
	}
	return page, nil
}

func (f *fakeStore) Get(_ context.Context, key string, maxBytes int64) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets++
	o, ok := f.objects[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s", archive.ErrNoSuchKey, key)
	}
	if maxBytes > 0 && int64(len(o.body)) > maxBytes {
		return o.body[:maxBytes], nil
	}
	return o.body, nil
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func mintElcano(priv ed25519.PrivateKey, email string, exp time.Time) string {
	body := b64url(mustJSON(map[string]any{"email": email, "tenant": "example.com", "iat": time.Now().Unix(), "exp": exp.Unix()}))
	return body + "." + b64url(ed25519.Sign(priv, []byte(body)))
}

func kidFor(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return b64url(sum[:16])
}

func signJWT(priv ed25519.PrivateKey, header, claims map[string]any) string {
	body := b64url(mustJSON(header)) + "." + b64url(mustJSON(claims))
	return body + "." + b64url(ed25519.Sign(priv, []byte(body)))
}

// testEnv is a running Explorer (over TLS, so Secure cookies flow) plus a
// browser with a cookie jar that does not follow redirects.
type testEnv struct {
	t       *testing.T
	srv     *Server
	ts      *httptest.Server
	browser *http.Client
	store   *fakeStore
	priv    ed25519.PrivateKey
	auth    *fakeAuth
}

func baseEnv(priv ed25519.PrivateKey) map[string]string {
	return map[string]string{
		"EMAIL_S3_BUCKET":         "archive",
		"AUTH_SIGNING_PUBKEY":     base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
		"AUTH_LOGIN_URL":          "https://auth.example.com",
		"EXPLORER_SESSION_SECRET": "test-session-secret-with-32-bytes-minimum",
	}
}

func newEnv(t *testing.T, env map[string]string, opts ...func(*Options)) *testEnv {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	full := baseEnv(priv)
	for k, v := range env {
		full[k] = v
	}
	settings, err := config.FromEnv(full)
	if err != nil {
		t.Fatal(err)
	}
	store := newFakeStore()
	o := Options{Store: store}
	for _, f := range opts {
		f(&o)
	}
	srv, err := New(context.Background(), settings, o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	ts := httptest.NewTLSServer(srv)
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	browser := ts.Client()
	browser.Jar = jar
	browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &testEnv{t: t, srv: srv, ts: ts, browser: browser, store: store, priv: priv}
}

// elcanoEnv is a signed-in Elcano-mode deployment.
func elcanoEnv(t *testing.T) *testEnv {
	e := newEnv(t, map[string]string{"EXPLORER_AUTH_MODE": "elcano"})
	e.setCookie("elcano_auth", mintElcano(e.priv, "alice@example.com", time.Now().Add(time.Hour)))
	return e
}

func (e *testEnv) setCookie(name, value string) {
	u, _ := url.Parse(e.ts.URL)
	e.browser.Jar.SetCookies(u, []*http.Cookie{{Name: name, Value: value, Path: "/"}})
}

func (e *testEnv) cookie(name string) string {
	u, _ := url.Parse(e.ts.URL)
	for _, c := range e.browser.Jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

type response struct {
	*http.Response
	body string
}

func (e *testEnv) do(method, path string, form url.Values) response {
	e.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(context.Background(), method, e.ts.URL+path, body)
	if err != nil {
		e.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := e.browser.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return response{resp, string(b)}
}

func (e *testEnv) get(path string) response { return e.do(http.MethodGet, path, nil) }

func (e *testEnv) post(path string, form url.Values) response {
	if form == nil {
		form = url.Values{}
	}
	return e.do(http.MethodPost, path, form)
}

// fakeAuth is a central auth service over TLS: /token answers with an
// id_token signed by key for the nonce the last /authorize carried.
type fakeAuth struct {
	ts        *httptest.Server
	key       ed25519.PrivateKey
	mu        sync.Mutex
	nonce     string
	email     string
	codes     []string
	tokenCode int
	signer    ed25519.PrivateKey
}

func newFakeAuth(t *testing.T, key ed25519.PrivateKey) *fakeAuth {
	fa := &fakeAuth{key: key, email: "alice@example.com", tokenCode: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		fa.mu.Lock()
		defer fa.mu.Unlock()
		fa.codes = append(fa.codes, r.PostForm.Get("code"))
		if fa.tokenCode != http.StatusOK {
			w.WriteHeader(fa.tokenCode)
			return
		}
		signer := fa.key
		if fa.signer != nil {
			signer = fa.signer
		}
		now := time.Now().Unix()
		tok := signJWT(signer, map[string]any{"typ": "JWT", "alg": "EdDSA", "kid": kidFor(fa.key.Public().(ed25519.PublicKey))},
			map[string]any{"iss": fa.ts.URL, "sub": "account-123", "aud": "explorer", "email": fa.email,
				"iat": now, "exp": now + 300, "nonce": fa.nonce})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": tok})
	})
	mux.HandleFunc("GET /jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	})
	fa.ts = httptest.NewTLSServer(mux)
	t.Cleanup(fa.ts.Close)
	return fa
}

// centralEnv is a central-mode deployment wired to a fake auth service,
// with alice@example.com on the access list.
func centralEnv(t *testing.T) *testEnv {
	t.Helper()
	_, authKey, _ := ed25519.GenerateKey(rand.Reader)
	fa := newFakeAuth(t, authKey)
	e := newEnv(t, map[string]string{
		"EXPLORER_AUTH_MODE":  "central",
		"EXPLORER_ACCESS_DB":  filepath.Join(t.TempDir(), "access.db"),
		"AUTH_ISSUER_URL":     fa.ts.URL,
		"EXPLORER_PUBLIC_URL": "https://explorer.example.com",
		"AUTH_CLIENT_ID":      "explorer",
		"AUTH_CLIENT_SECRET":  "a-test-client-secret-with-at-least-32-bytes",
		"AUTH_SIGNING_PUBKEY": base64.StdEncoding.EncodeToString(authKey.Public().(ed25519.PublicKey)),
	}, func(o *Options) { o.HTTPClient = fa.ts.Client() })
	e.auth = fa
	if _, err := e.central().store.GrantAccess("alice@example.com"); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *testEnv) central() *centralProvider { return e.srv.auth.(*centralProvider) }

// beginLogin starts a sign-in and returns the state the authorize redirect
// carried (and records its nonce at the fake auth service).
func (e *testEnv) beginLogin(next string) string {
	e.t.Helper()
	resp := e.get("/auth/login?next=" + url.QueryEscape(next))
	if resp.StatusCode != http.StatusSeeOther {
		e.t.Fatalf("login status %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		e.t.Fatal(err)
	}
	q := loc.Query()
	e.auth.mu.Lock()
	e.auth.nonce = q.Get("nonce")
	e.auth.mu.Unlock()
	return q.Get("state")
}

func (e *testEnv) completeLogin(next string) response {
	state := e.beginLogin(next)
	return e.get("/auth/callback?code=one-time-code&state=" + url.QueryEscape(state))
}

// accessToken is a signed application-access event from the fake service.
func (e *testEnv) accessToken(action string, version int, email string) string {
	pub := e.auth.key.Public().(ed25519.PublicKey)
	return signJWT(e.auth.key, map[string]any{"typ": "access+jwt", "alg": "EdDSA", "kid": kidFor(pub)},
		map[string]any{"iss": e.auth.ts.URL, "sub": "account-bob", "aud": "explorer", "email": email,
			"iat": 1000, "exp": 2_000_000_000, "jti": fmt.Sprintf("access-%d", version),
			"events": map[string]any{centralauth.ApplicationAccessEvent: map[string]any{"action": action, "version": version}}})
}

func (e *testEnv) logoutToken(subject, jti string) string {
	pub := e.auth.key.Public().(ed25519.PublicKey)
	return signJWT(e.auth.key, map[string]any{"typ": "logout+jwt", "alg": "EdDSA", "kid": kidFor(pub)},
		map[string]any{"iss": e.auth.ts.URL, "sub": subject, "aud": "explorer",
			"iat": time.Now().Unix(), "exp": 2_000_000_000, "jti": jti,
			"events": map[string]any{centralauth.BackchannelLogoutEvent: map[string]any{}}})
}

type archiveRow = archive.Row

func tlsDial(host string) (net.Conn, error) {
	return tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true})
}
