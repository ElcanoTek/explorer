// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package centralauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }
func newClock(unix int64) *fakeClock         { return &fakeClock{t: time.Unix(unix, 0)} }
func fixedFetch(doc []byte) FetchFunc {
	return func(context.Context, string) ([]byte, error) { return doc, nil }
}
func newResolver(static []string, f FetchFunc, c *fakeClock) *KeyResolver {
	return NewKeyResolver("https://auth.example.com", static, f, c.now)
}

type fakeJWKS struct {
	doc   []byte
	fail  bool
	calls int
	urls  []string
}

func (f *fakeJWKS) fetch(_ context.Context, url string) ([]byte, error) {
	f.calls++
	f.urls = append(f.urls, url)
	if f.fail {
		return nil, errors.New("auth is restarting")
	}
	return f.doc, nil
}

func TestResolverMergesStaticAndPublishedKeysAndSurvivesFailure(t *testing.T) {
	old, fresh := newKey(t), newKey(t)
	clock := newClock(1_000)
	jwks := &fakeJWKS{doc: jwksFor(fresh)}
	r := NewKeyResolver("https://auth.example.com/", []string{old.pub}, jwks.fetch, clock.now)
	want := []string{old.pub, fresh.pub}
	if got := r.PublicKeys(); !reflect.DeepEqual(got, want) || jwks.calls != 1 || jwks.urls[0] != "https://auth.example.com/jwks.json" {
		t.Fatalf("got %v calls %d urls %v", got, jwks.calls, jwks.urls)
	}
	if got := r.PublicKeys(); !reflect.DeepEqual(got, want) || jwks.calls != 1 {
		t.Fatal("cache not used inside the TTL")
	}
	clock.advance(11 * time.Minute)
	jwks.fail = true
	if got := r.PublicKeys(); !reflect.DeepEqual(got, want) || jwks.calls != 2 {
		t.Fatalf("failed refresh lost keys: %v calls %d", got, jwks.calls)
	}

	// A token signed by a key only in a newer JWKS triggers one refresh,
	// rate-limited to once a minute.
	rotated := newKey(t)
	jwks.fail = false
	jwks.doc = jwksFor(fresh, rotated)
	clock.advance(61 * time.Second)
	if !slices.Contains(r.KeysForToken(mintLogout(t, rotated, nil)), rotated.pub) {
		t.Fatal("rotated key not picked up")
	}
	after := jwks.calls
	r.KeysForToken(mintLogout(t, newKey(t), nil))
	if jwks.calls != after {
		t.Fatal("unknown kid refreshed inside the minute")
	}
}

func TestResolverIgnoresMalformedEntries(t *testing.T) {
	good := newKey(t)
	var doc map[string][]any
	_ = json.Unmarshal(jwksFor(good), &doc)
	doc["keys"] = append(doc["keys"],
		map[string]any{"kty": "RSA", "n": "x", "e": "AQAB"},
		map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "dG9vLXNob3J0"},
		"not-a-key")
	raw, _ := json.Marshal(doc)
	r := newResolver(nil, fixedFetch(raw), newClock(1_000))
	if got := r.PublicKeys(); !reflect.DeepEqual(got, []string{good.pub}) {
		t.Fatalf("got %v", got)
	}
	for _, bad := range []string{`[]`, `{"keys":{}}`, `nope`, `{}`} {
		r := newResolver(nil, fixedFetch([]byte(bad)), newClock(1_000))
		if got := r.PublicKeys(); len(got) != 0 {
			t.Errorf("%s: got %v", bad, got)
		}
	}
}

func TestLogoutVerifiesAgainstAKeyOnlyInJWKS(t *testing.T) {
	signer := newKey(t)
	raw := mintLogout(t, signer, nil)
	r := newResolver(nil, fixedFetch(jwksFor(signer)), newClock(1_000))
	ev, err := VerifyLogoutToken(raw, "https://auth.example.com", "explorer", r.KeysForToken(raw), t1010)
	if err != nil || ev.Subject != "account-123" {
		t.Fatalf("%+v %v", ev, err)
	}
}

func TestRetiredJWKSKeyStopsBeingTrustedAfterCacheWindow(t *testing.T) {
	static, retired := newKey(t), newKey(t)
	clock := newClock(10_000)
	jwks := &fakeJWKS{doc: jwksFor(retired)}
	r := newResolver([]string{static.pub}, jwks.fetch, clock)
	tok := mintLogout(t, retired, nil)
	if !slices.Contains(r.KeysForToken(tok), retired.pub) {
		t.Fatal("retired key not trusted initially")
	}
	jwks.doc = jwksFor(newKey(t))
	clock.advance(300 * time.Second)
	if !slices.Contains(r.KeysForToken(tok), retired.pub) {
		t.Fatal("cache dropped too early")
	}
	clock.advance(301 * time.Second)
	if slices.Contains(r.KeysForToken(tok), retired.pub) {
		t.Fatal("retired key still trusted after the cache window")
	}
}

func TestJWKSKeyKeptWhenRefreshFails(t *testing.T) {
	static, remote := newKey(t), newKey(t)
	clock := newClock(10_000)
	jwks := &fakeJWKS{doc: jwksFor(remote)}
	r := newResolver([]string{static.pub}, jwks.fetch, clock)
	tok := mintLogout(t, remote, nil)
	r.KeysForToken(tok)
	jwks.fail = true
	clock.advance(time.Hour)
	if !slices.Contains(r.KeysForToken(tok), remote.pub) || jwks.calls != 2 {
		t.Fatalf("calls=%d", jwks.calls)
	}
}

func TestStaticKeyNeverWaitsOnJWKS(t *testing.T) {
	static := newKey(t)
	clock := newClock(10_000)
	jwks := &fakeJWKS{doc: jwksFor(newKey(t))}
	r := newResolver([]string{static.pub}, jwks.fetch, clock)
	for range 3 {
		if !slices.Contains(r.KeysForToken(mintLogout(t, static, nil)), static.pub) {
			t.Fatal("static key missing")
		}
		clock.advance(time.Hour)
	}
	if jwks.calls != 0 {
		t.Fatalf("JWKS fetched %d times", jwks.calls)
	}
}

func TestDefaultFetchRefusesRedirectsAndOversize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/ok", http.StatusFound)
		case "/big":
			_, _ = w.Write(make([]byte, MaxJWKSBytes+10))
		default:
			_, _ = w.Write([]byte(`{"keys":[]}`))
		}
	}))
	defer srv.Close()
	fetch := DefaultFetch(srv.Client())
	if _, err := fetch(context.Background(), srv.URL+"/redirect"); err == nil {
		t.Error("redirect followed")
	}
	if _, err := fetch(context.Background(), srv.URL+"/big"); err == nil {
		t.Error("oversized document accepted")
	}
	if raw, err := fetch(context.Background(), srv.URL+"/ok"); err != nil || string(raw) != `{"keys":[]}` {
		t.Errorf("%s %v", raw, err)
	}
}
