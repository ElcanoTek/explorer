// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

// Package config reads Explorer's settings from the environment, layered
// over the deployment's dotenv files exactly as the Python service did:
// .env overrides everything, the process environment comes next, and
// .env.shared fills in only what is still unset.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ElcanoTek/explorer/internal/dotenv"
)

// DevSessionSecret is the placeholder used when EXPLORER_SESSION_SECRET is
// unset. Central mode refuses to start with it.
const DevSessionSecret = "explorer-dev-session-secret" //nolint:gosec // G101: a public placeholder that central mode refuses, not a credential.

// Settings is every knob Explorer reads. Field comments name the variable.
type Settings struct {
	// AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN: static
	// credentials. Blank means the ambient AWS credential chain.
	AWSAccessKeyID     string
	AWSSecretAccessKey string
	AWSSessionToken    string
	AWSRegion          string // AWS_REGION

	Bucket              string // EMAIL_S3_BUCKET
	Prefix              string // EMAIL_S3_PREFIX
	DatePrefixFormat    string // EMAIL_S3_DATE_PREFIX_FORMAT
	MaxDatePrefixDays   int    // EMAIL_S3_MAX_DATE_PREFIX_DAYS
	MaxBodySearchDays   int    // EMAIL_S3_MAX_BODY_SEARCH_DAYS
	HeaderFetchBytes    int    // EMAIL_HEADER_FETCH_BYTES
	SearchJobMaxSeconds int    // EMAIL_SEARCH_JOB_MAX_SECONDS
	// EMAIL_S3_FORCE_PATH_STYLE: bucket in the path, not the host name, for
	// S3-compatible stores (MinIO, LocalStack) behind AWS_ENDPOINT_URL_S3.
	S3ForcePathStyle bool

	// EXPLORER_SESSION_SECRET signs the UI cookie (search ownership and the
	// central-login transaction).
	SessionSecret  string
	UICookieSecure bool // EXPLORER_UI_COOKIE_SECURE

	AuthMode string // EXPLORER_AUTH_MODE: "elcano" or "central"

	AuthSigningPubkey          string   // AUTH_SIGNING_PUBKEY
	AuthSigningPreviousPubkeys []string // AUTH_SIGNING_PREVIOUS_PUBKEYS (comma separated)
	AuthLoginURL               string   // AUTH_LOGIN_URL (Elcano mode)
	AuthCookieName             string   // AUTH_COOKIE_NAME (Elcano mode)

	AuthIssuerURL          string // AUTH_ISSUER_URL
	PublicURL              string // EXPLORER_PUBLIC_URL
	AuthClientID           string // AUTH_CLIENT_ID
	AuthClientSecret       string // AUTH_CLIENT_SECRET
	AuthHTTPTimeoutRaw     string // AUTH_HTTP_TIMEOUT_SECONDS (validated by the auth client)
	AuthAllowInsecureHTTP  bool   // AUTH_ALLOW_INSECURE_HTTP (development only)
	AccessDB               string // EXPLORER_ACCESS_DB
	AuthCookieSecure       bool   // EXPLORER_AUTH_COOKIE_SECURE
	SessionIdleSeconds     int    // EXPLORER_SESSION_IDLE_SECONDS
	SessionAbsoluteSeconds int    // EXPLORER_SESSION_ABSOLUTE_SECONDS

	ListenAddr string // EXPLORER_LISTEN_ADDR (default 127.0.0.1:8080)
}

// Load layers appDir's dotenv files over the process environment and
// parses the result.
func Load(appDir string) (Settings, map[string]string, error) {
	env := dotenv.Layer(appDir, dotenv.Environ())
	s, err := FromEnv(env)
	return s, env, err
}

// Truthy is the set of values every Explorer boolean accepts.
func Truthy(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// FromEnv parses settings from an environment map.
func FromEnv(env map[string]string) (Settings, error) {
	get := func(key, def string) string {
		if v, ok := env[key]; ok {
			return v
		}
		return def
	}
	var errs []string
	num := func(key, def string) int {
		raw := strings.TrimSpace(get(key, def))
		n, err := strconv.Atoi(raw)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s must be an integer (got %q)", key, raw))
			n, _ = strconv.Atoi(def)
		}
		return n
	}
	var previous []string
	for _, k := range strings.Split(get("AUTH_SIGNING_PREVIOUS_PUBKEYS", ""), ",") {
		if k = strings.TrimSpace(k); k != "" {
			previous = append(previous, k)
		}
	}
	s := Settings{
		AWSAccessKeyID:     get("AWS_ACCESS_KEY_ID", ""),
		AWSSecretAccessKey: get("AWS_SECRET_ACCESS_KEY", ""),
		AWSSessionToken:    get("AWS_SESSION_TOKEN", ""),
		AWSRegion:          get("AWS_REGION", "us-east-2"),

		Bucket:              get("EMAIL_S3_BUCKET", ""),
		Prefix:              get("EMAIL_S3_PREFIX", "emails/"),
		DatePrefixFormat:    get("EMAIL_S3_DATE_PREFIX_FORMAT", "emails/%Y/%m/%d/"),
		MaxDatePrefixDays:   num("EMAIL_S3_MAX_DATE_PREFIX_DAYS", "62"),
		MaxBodySearchDays:   num("EMAIL_S3_MAX_BODY_SEARCH_DAYS", "14"),
		HeaderFetchBytes:    num("EMAIL_HEADER_FETCH_BYTES", "65536"),
		SearchJobMaxSeconds: num("EMAIL_SEARCH_JOB_MAX_SECONDS", "120"),
		S3ForcePathStyle:    Truthy(get("EMAIL_S3_FORCE_PATH_STYLE", "0")),

		SessionSecret:  get("EXPLORER_SESSION_SECRET", DevSessionSecret),
		UICookieSecure: Truthy(get("EXPLORER_UI_COOKIE_SECURE", "1")),

		AuthMode: strings.ToLower(strings.TrimSpace(get("EXPLORER_AUTH_MODE", "elcano"))),

		AuthSigningPubkey:          strings.TrimSpace(get("AUTH_SIGNING_PUBKEY", "")),
		AuthSigningPreviousPubkeys: previous,
		AuthLoginURL:               strings.TrimRight(get("AUTH_LOGIN_URL", "https://auth.elcanotek.com"), "/"),
		AuthCookieName:             get("AUTH_COOKIE_NAME", "elcano_auth"),

		AuthIssuerURL:          get("AUTH_ISSUER_URL", ""),
		PublicURL:              get("EXPLORER_PUBLIC_URL", ""),
		AuthClientID:           get("AUTH_CLIENT_ID", "explorer"),
		AuthClientSecret:       get("AUTH_CLIENT_SECRET", ""),
		AuthHTTPTimeoutRaw:     get("AUTH_HTTP_TIMEOUT_SECONDS", "10"),
		AuthAllowInsecureHTTP:  Truthy(get("AUTH_ALLOW_INSECURE_HTTP", "0")),
		AccessDB:               get("EXPLORER_ACCESS_DB", "/var/lib/explorer/access.db"),
		AuthCookieSecure:       Truthy(get("EXPLORER_AUTH_COOKIE_SECURE", "1")),
		SessionIdleSeconds:     num("EXPLORER_SESSION_IDLE_SECONDS", "43200"),
		SessionAbsoluteSeconds: num("EXPLORER_SESSION_ABSOLUTE_SECONDS", "86400"),

		ListenAddr: get("EXPLORER_LISTEN_ADDR", "127.0.0.1:8080"),
	}
	if s.HeaderFetchBytes <= 0 {
		errs = append(errs, "EMAIL_HEADER_FETCH_BYTES must be positive")
	}
	if s.SearchJobMaxSeconds <= 0 {
		errs = append(errs, "EMAIL_SEARCH_JOB_MAX_SECONDS must be positive")
	}
	if len(errs) > 0 {
		return s, fmt.Errorf("invalid configuration: %s", strings.Join(errs, "; "))
	}
	return s, nil
}

// AppDir is where the service reads its dotenv files: EXPLORER_APP_DIR, or
// the working directory (the systemd unit sets /opt/explorer).
func AppDir() string {
	if d := os.Getenv("EXPLORER_APP_DIR"); d != "" {
		return d
	}
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}

// SigningKeys is AUTH_SIGNING_PUBKEY followed by any previous keys.
func (s Settings) SigningKeys() []string {
	var keys []string
	if s.AuthSigningPubkey != "" {
		keys = append(keys, s.AuthSigningPubkey)
	}
	return append(keys, s.AuthSigningPreviousPubkeys...)
}

// AllowedKeyRoots are the S3 key prefixes Explorer may read: the archive
// prefix and the literal head of the date-partition format.
func (s Settings) AllowedKeyRoots() []string {
	seen := map[string]bool{}
	var roots []string
	for _, r := range []string{s.Prefix, strings.SplitN(s.DatePrefixFormat, "%", 2)[0]} {
		if r != "" && !seen[r] {
			seen[r] = true
			roots = append(roots, r)
		}
	}
	return roots
}
