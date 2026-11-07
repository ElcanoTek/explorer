// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package ops

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ReleaseRepository is the GitHub repository releases are published from.
const ReleaseRepository = "ElcanoTek/explorer"

// SignerIdentity is the ONE certificate identity an Explorer release signature
// may carry: the release workflow, run from the default branch.
const SignerIdentity = "https://github.com/" + ReleaseRepository + "/.github/workflows/release.yml@refs/heads/main"

// OIDCIssuer is GitHub Actions' OIDC issuer, the only issuer accepted for
// SignerIdentity.
const OIDCIssuer = "https://token.actions.githubusercontent.com"

// Published file names. One binary per architecture; every file listed in
// SHA256SUMS is covered by its signature.
const (
	SumsFile       = "SHA256SUMS"
	ManifestFile   = "release.json"
	BundleSuffix   = ".sigstore.json"
	binaryPrefix   = "explorer-linux-"
	manifestSchema = 1
)

// Size ceilings for a download: stop a hostile or broken server from filling
// the disk.
const (
	maxMetaBytes   = 4 << 20   // SHA256SUMS, release.json, signature bundles
	maxBinaryBytes = 512 << 20 // the explorer binary
	maxCosignBytes = 512 << 20
)

// DefaultReleaseBaseURL is where release assets are downloaded from:
// <base>/<tag>/<file>. EXPLORER_RELEASE_BASE_URL overrides it.
const DefaultReleaseBaseURL = "https://github.com/" + ReleaseRepository + "/releases/download"

// DefaultReleaseLatestURL is the GitHub API endpoint for the latest published release.
const DefaultReleaseLatestURL = "https://api.github.com/repos/" + ReleaseRepository + "/releases/latest"

//go:embed cosign.lock
var cosignLockFile []byte

// BinaryAsset is the published binary name for a GOARCH ("explorer-linux-amd64").
func BinaryAsset(arch string) string { return binaryPrefix + arch }

// SupportedArch reports whether release.yml publishes a binary for arch.
func SupportedArch(arch string) bool { return arch == "amd64" || arch == "arm64" }

// HostArch is the architecture this process runs on.
func HostArch() string { return runtime.GOARCH }

// Tag is a parsed release tag vYYYY.MM.DD.N.
type Tag struct {
	Year, Month, Day, N int
}

var (
	tagRE     = regexp.MustCompile(`^v([0-9]{4})\.([0-9]{2})\.([0-9]{2})\.([1-9][0-9]*)$`)
	versionRE = regexp.MustCompile(`^v?([0-9]{4})\.([0-9]{2})\.([0-9]{2})\.([1-9][0-9]*)(?:\+.*)?$`)
)

// ParseTag parses an exact release tag (vYYYY.MM.DD.N).
func ParseTag(s string) (Tag, error) {
	m := tagRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return Tag{}, fmt.Errorf("%q is not a release tag (want vYYYY.MM.DD.N)", s)
	}
	return tagFrom(m), nil
}

// ParseVersion extracts the release a stamped build version is at or past.
func ParseVersion(v string) (Tag, bool) {
	m := versionRE.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return Tag{}, false
	}
	return tagFrom(m), true
}

func tagFrom(m []string) Tag {
	n := func(s string) int { v, _ := strconv.Atoi(s); return v }
	return Tag{Year: n(m[1]), Month: n(m[2]), Day: n(m[3]), N: n(m[4])}
}

// String renders the tag as published ("v2026.11.07.1").
func (t Tag) String() string {
	return fmt.Sprintf("v%04d.%02d.%02d.%d", t.Year, t.Month, t.Day, t.N)
}

// Version renders the release version without the leading "v" ("2026.11.07.1").
func (t Tag) Version() string {
	return fmt.Sprintf("%04d.%02d.%02d.%d", t.Year, t.Month, t.Day, t.N)
}

// Compare orders tags by release date, then by the day's ordinal.
func (t Tag) Compare(o Tag) int {
	for _, d := range [][2]int{{t.Year, o.Year}, {t.Month, o.Month}, {t.Day, o.Day}, {t.N, o.N}} {
		switch {
		case d[0] < d[1]:
			return -1
		case d[0] > d[1]:
			return 1
		}
	}
	return 0
}

// Sums is a parsed SHA256SUMS: file name -> lowercase hex digest.
type Sums map[string]string

// ParseSums parses `sha256sum` output strictly.
func ParseSums(data []byte) (Sums, error) {
	out := Sums{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimRight(sc.Text(), "\r")
		if text == "" {
			continue
		}
		sum, name, ok := strings.Cut(text, "  ")
		if !ok {
			sum, name, ok = strings.Cut(text, " *")
		}
		if !ok || len(sum) != 64 {
			return nil, fmt.Errorf("%s line %d: not a `sha256sum` line", SumsFile, line)
		}
		if _, err := hex.DecodeString(sum); err != nil {
			return nil, fmt.Errorf("%s line %d: digest is not hex", SumsFile, line)
		}
		if name == "" || strings.ContainsAny(name, "/\\") || name == "." || name == ".." {
			return nil, fmt.Errorf("%s line %d: %q is not a plain file name", SumsFile, line, name)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("%s lists %q twice", SumsFile, name)
		}
		out[name] = strings.ToLower(sum)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New(SumsFile + " is empty")
	}
	return out, nil
}

// ManifestBinary describes one architecture binary entry in release.json.
type ManifestBinary struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

// Manifest is release.json: the signed statement of what one release is.
type Manifest struct {
	Schema   int                       `json:"schema,omitempty"`
	Tag      string                    `json:"tag"`
	Version  string                    `json:"version,omitempty"`
	Commit   string                    `json:"commit"`
	BuiltAt  string                    `json:"built_at,omitempty"`
	Binaries map[string]ManifestBinary `json:"binaries,omitempty"`
}

// ParseManifest decodes and validates release.json against the tag that was
// requested.
func ParseManifest(data []byte, want Tag) (Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("%s: %w", ManifestFile, err)
	}
	if m.Schema != 0 && m.Schema != manifestSchema {
		return Manifest{}, fmt.Errorf("%s: schema %d, this explorer understands %d", ManifestFile, m.Schema, manifestSchema)
	}
	if m.Tag != want.String() {
		return Manifest{}, fmt.Errorf("%s names release %q but %s was requested — refusing a release served under another tag", ManifestFile, m.Tag, want)
	}
	if m.Version != "" && m.Version != want.Version() && m.Version != want.String() {
		return Manifest{}, fmt.Errorf("%s names version %q for tag %s", ManifestFile, m.Version, want)
	}
	if !validRevision(strings.ToLower(m.Commit)) || len(m.Commit) != 40 {
		return Manifest{}, fmt.Errorf("%s: commit %q is not a 40-char hex SHA", ManifestFile, m.Commit)
	}
	m.Commit = strings.ToLower(m.Commit)
	for platform, b := range m.Binaries {
		if b.SHA256 != "" {
			if len(b.SHA256) != 64 {
				return Manifest{}, fmt.Errorf("%s: binary %q sha256 is not 64 hex chars", ManifestFile, platform)
			}
			if _, err := hex.DecodeString(b.SHA256); err != nil {
				return Manifest{}, fmt.Errorf("%s: binary %q sha256 is not hex", ManifestFile, platform)
			}
		}
	}
	return m, nil
}

// CosignPin is one pinned cosign build.
type CosignPin struct {
	Version string
	SHA256  map[string]string
}

// LoadCosignLock parses cosign.lock.
func LoadCosignLock(data []byte) (CosignPin, error) {
	pin := CosignPin{SHA256: map[string]string{}}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if len(f) != 2 {
			return CosignPin{}, fmt.Errorf("cosign.lock: malformed line %q", sc.Text())
		}
		if f[0] == "version" {
			pin.Version = f[1]
			continue
		}
		if len(f[1]) != 64 {
			return CosignPin{}, fmt.Errorf("cosign.lock: %s digest is not a SHA-256", f[0])
		}
		if _, err := hex.DecodeString(f[1]); err != nil {
			return CosignPin{}, fmt.Errorf("cosign.lock: %s digest is not hex", f[0])
		}
		pin.SHA256[f[0]] = strings.ToLower(f[1])
	}
	if pin.Version == "" || len(pin.SHA256) == 0 {
		return CosignPin{}, errors.New("cosign.lock: missing version or digests")
	}
	return pin, sc.Err()
}

// PinnedCosign returns the cosign build compiled into this explorer binary.
func PinnedCosign() CosignPin {
	pin, err := LoadCosignLock(cosignLockFile)
	if err != nil {
		panic(err)
	}
	return pin
}

func cosignURL(pin CosignPin, arch string) string {
	if base := strings.TrimRight(os.Getenv("EXPLORER_COSIGN_URL"), "/"); base != "" {
		return base + "/cosign-linux-" + arch
	}
	return "https://github.com/sigstore/cosign/releases/download/" + pin.Version + "/cosign-linux-" + arch
}

// EnsureCosign returns the path of the pinned cosign for arch under cacheDir,
// downloading it when absent and checking its SHA-256 on every call.
func EnsureCosign(ctx context.Context, d *Downloader, cacheDir, arch string) (string, error) {
	if src := os.Getenv("EXPLORER_COSIGN_BIN"); src != "" {
		return InstallCosignFrom(src, cacheDir, arch)
	}
	pin := PinnedCosign()
	want, ok := pin.SHA256["linux/"+arch]
	if !ok {
		return "", fmt.Errorf("no pinned cosign for linux/%s", arch)
	}
	if err := EnsurePrivateDir(cacheDir); err != nil {
		return "", fmt.Errorf("cosign cache: %w", err)
	}
	path := filepath.Join(cacheDir, "cosign-"+pin.Version+"-linux-"+arch)
	if got, err := fileSHA256(path); err == nil && got == want {
		return path, nil
	}
	tmp := path + ".download"
	if err := d.Get(ctx, cosignURL(pin, arch), tmp, maxCosignBytes); err != nil {
		return "", fmt.Errorf("download cosign %s: %w", pin.Version, err)
	}
	got, err := fileSHA256(tmp)
	if err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if got != want {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("cosign %s for linux/%s has SHA-256 %s, cosign.lock pins %s — refusing to run it", pin.Version, arch, got, want)
	}
	if err := os.Chmod(tmp, 0o755); err != nil { //nolint:gosec // G302: executable binary inside a 0700 private dir.
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	return path, nil
}

// InstallCosignFrom copies an operator-supplied cosign (EXPLORER_COSIGN_BIN)
// into the private cache under the pinned name, verifying its SHA-256 as it is
// copied.
func InstallCosignFrom(src, cacheDir, arch string) (string, error) {
	pin := PinnedCosign()
	want, ok := pin.SHA256["linux/"+arch]
	if !ok {
		return "", fmt.Errorf("no pinned cosign for linux/%s", arch)
	}
	if err := EnsurePrivateDir(cacheDir); err != nil {
		return "", fmt.Errorf("cosign cache: %w", err)
	}
	in, err := os.Open(src) //nolint:gosec // G304: operator-supplied EXPLORER_COSIGN_BIN, verified against cosign.lock.
	if err != nil {
		return "", err
	}
	defer in.Close()
	path := filepath.Join(cacheDir, "cosign-"+pin.Version+"-linux-"+arch)
	tmp := path + ".copy"
	_ = os.Remove(tmp)
	if err := copyFromFD(in, tmp, want); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("EXPLORER_COSIGN_BIN %s is not cosign %s for linux/%s: %w", src, pin.Version, arch, err)
	}
	if err := os.Chmod(tmp, 0o700); err != nil { //nolint:gosec // G302: private executable in 0700 dir.
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	return path, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: internal staging/cache path.
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// FileSHA256 returns the lowercase hex SHA-256 of path.
func FileSHA256(path string) (string, error) { return fileSHA256(path) }

// Verifier checks Sigstore blob signatures.
type Verifier interface {
	VerifyBlob(ctx context.Context, path, bundle string) error
}

// Policy defines the expected certificate identity and OIDC issuer.
type Policy struct {
	Identity    string
	Issuer      string
	TrustedRoot string
}

// ExplorerPolicy returns the default Sigstore policy for Explorer releases.
func ExplorerPolicy() Policy {
	return Policy{
		Identity:    SignerIdentity,
		Issuer:      OIDCIssuer,
		TrustedRoot: os.Getenv("EXPLORER_SIGSTORE_TRUSTED_ROOT"),
	}
}

// Cosign runs the pinned cosign CLI to verify blob signatures.
type Cosign struct {
	Bin     string
	Policy  Policy
	TUFRoot string
	Timeout time.Duration
}

func (c *Cosign) policyArgs() ([]string, error) {
	if c.Policy.Identity == "" || c.Policy.Issuer == "" {
		return nil, errors.New("verification policy has no identity/issuer")
	}
	args := []string{"--certificate-identity", c.Policy.Identity, "--certificate-oidc-issuer", c.Policy.Issuer}
	if c.Policy.TrustedRoot != "" {
		args = append(args, "--trusted-root", c.Policy.TrustedRoot)
	}
	return args, nil
}

// VerifyBlob verifies that bundle is a valid signature over path by Policy.
func (c *Cosign) VerifyBlob(ctx context.Context, path, bundle string) error {
	if _, err := os.Stat(bundle); err != nil {
		return fmt.Errorf("no signature for %s: %w", filepath.Base(path), err)
	}
	pa, err := c.policyArgs()
	if err != nil {
		return err
	}
	args := append([]string{"verify-blob", "--bundle", bundle}, pa...)
	return c.run(ctx, append(args, path)...)
}

func (c *Cosign) run(ctx context.Context, args ...string) error {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Bin, args...) //nolint:gosec // G204: c.Bin is the digest-verified cosign binary.
	if c.TUFRoot != "" {
		cmd.Env = append(cmd.Environ(), "TUF_ROOT="+c.TUFRoot)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(out.String())
		if len(msg) > 2000 {
			msg = msg[len(msg)-2000:]
		}
		return fmt.Errorf("signature verification FAILED (cosign %s): %w: %s", args[0], err, msg)
	}
	return nil
}

// ReleaseBaseURL resolves the asset base URL.
func ReleaseBaseURL() string {
	if v := strings.TrimRight(os.Getenv("EXPLORER_RELEASE_BASE_URL"), "/"); v != "" {
		return v
	}
	return DefaultReleaseBaseURL
}

// Downloader fetches URLs to files with a size ceiling.
type Downloader struct {
	Client *http.Client
}

// NewDownloader returns a Downloader with conservative timeouts.
func NewDownloader() *Downloader {
	return &Downloader{Client: &http.Client{Timeout: 15 * time.Minute}}
}

// Get downloads url to path (mode 0600), refusing a body larger than limit.
func (d *Downloader) Get(ctx context.Context, url, path string, limit int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "explorer-update")
	resp, err := d.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &HTTPError{URL: url, Status: resp.StatusCode}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) //nolint:gosec // G304: path is inside the caller's private staging dir.
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, limit+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	if n > limit {
		_ = os.Remove(path)
		return fmt.Errorf("%s is larger than %d bytes — refusing it", url, limit)
	}
	return nil
}

// HTTPError represents a non-200 HTTP response.
type HTTPError struct {
	URL    string
	Status int
}

func (e *HTTPError) Error() string { return fmt.Sprintf("GET %s: HTTP %d", e.URL, e.Status) }

// IsNotFound reports whether err is a 404.
func IsNotFound(err error) bool {
	var he *HTTPError
	return errors.As(err, &he) && he.Status == http.StatusNotFound
}

// LatestTag queries the GitHub API for the newest published release tag.
func (d *Downloader) LatestTag(ctx context.Context) (Tag, error) {
	url := DefaultReleaseLatestURL
	if v := os.Getenv("EXPLORER_RELEASE_LATEST_URL"); v != "" {
		url = v
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) //nolint:gosec // G704: operator-configured release endpoint.
	if err != nil {
		return Tag{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "explorer-update")
	resp, err := d.Client.Do(req) //nolint:gosec // G704: operator-configured release endpoint.
	if err != nil {
		return Tag{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Tag{}, &HTTPError{URL: url, Status: resp.StatusCode}
	}
	var body struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxMetaBytes)).Decode(&body); err != nil {
		return Tag{}, fmt.Errorf("latest release: %w", err)
	}
	return ParseTag(body.TagName)
}

// FetchOptions selects and checks one release download.
type FetchOptions struct {
	Tag            Tag
	Arch           string
	Dir            string
	BaseURL        string
	Current        string
	AllowDowngrade bool
	Commit         string
}

// Fetched is a verified release on disk.
type Fetched struct {
	Tag          Tag
	Binary       string
	Manifest     Manifest
	Sums         Sums
	BinaryFile   *os.File
	BinarySHA256 string
}

// ErrDowngrade is returned when the requested release is older than the one
// installed and AllowDowngrade is false.
var ErrDowngrade = errors.New("downgrade refused")

// FetchRelease downloads and verifies one signed release before making its
// binary executable.
func FetchRelease(ctx context.Context, d *Downloader, v Verifier, o FetchOptions) (*Fetched, error) {
	if !SupportedArch(o.Arch) {
		return nil, fmt.Errorf("no explorer release is published for linux/%s (amd64 and arm64 are)", o.Arch)
	}
	if cur, ok := ParseVersion(o.Current); ok && !o.AllowDowngrade && o.Tag.Compare(cur) < 0 {
		return nil, fmt.Errorf("%w: %s is older than the installed %s (pass --allow-downgrade to roll back on purpose)", ErrDowngrade, o.Tag, cur)
	}
	if err := EnsurePrivateDir(o.Dir); err != nil {
		return nil, err
	}
	private, err := os.MkdirTemp("", "explorer-verify-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(private)

	base := o.BaseURL
	if base == "" {
		base = ReleaseBaseURL()
	}
	url := func(name string) string { return base + "/" + o.Tag.String() + "/" + name }
	get := func(name string, limit int64) error {
		if err := d.Get(ctx, url(name), filepath.Join(o.Dir, name), limit); err != nil {
			return fmt.Errorf("download %s: %w", name, err)
		}
		return nil
	}
	if err := get(SumsFile, maxMetaBytes); err != nil {
		return nil, err
	}
	if err := get(SumsFile+BundleSuffix, maxMetaBytes); err != nil {
		if IsNotFound(err) {
			return nil, fmt.Errorf("release %s has no signature for %s — refusing an unsigned release", o.Tag, SumsFile)
		}
		return nil, err
	}
	sums, err := verifiedSums(ctx, v, o.Dir, private)
	if err != nil {
		return nil, err
	}

	asset := BinaryAsset(o.Arch)
	if _, ok := sums[asset]; !ok {
		return nil, fmt.Errorf("the signed %s does not list %s", SumsFile, asset)
	}
	if err := get(asset, maxBinaryBytes); err != nil {
		return nil, err
	}
	if err := get(asset+BundleSuffix, maxMetaBytes); err != nil {
		if IsNotFound(err) {
			return nil, fmt.Errorf("release %s has no signature for %s — refusing it", o.Tag, asset)
		}
		return nil, err
	}
	bf, err := openVerifiedBinary(o.Dir, asset, sums[asset], o.Arch)
	if err != nil {
		return nil, err
	}
	defer bf.Close()
	binCopy := filepath.Join(private, asset)
	if err := copyFromFD(bf, binCopy, sums[asset]); err != nil {
		return nil, err
	}
	bundle, err := readPrivateFile(o.Dir, asset+BundleSuffix)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(binCopy+BundleSuffix, bundle, 0o600); err != nil {
		return nil, err
	}
	if err := v.VerifyBlob(ctx, binCopy, binCopy+BundleSuffix); err != nil {
		return nil, fmt.Errorf("%s: %w", asset, err)
	}

	if _, ok := sums[ManifestFile]; !ok {
		return nil, fmt.Errorf("the signed %s does not list %s", SumsFile, asset)
	}
	if err := get(ManifestFile, maxMetaBytes); err != nil {
		return nil, err
	}
	man, err := verifiedManifest(o.Dir, sums, o.Tag, o.Commit, o.Arch)
	if err != nil {
		return nil, err
	}
	if err := bf.Chmod(0o755); err != nil {
		return nil, err
	}
	return &Fetched{Tag: o.Tag, Binary: filepath.Join(o.Dir, asset), Manifest: man, Sums: sums, BinarySHA256: sums[asset]}, nil
}

// LoadVerifiedRelease re-reads and re-verifies a staging directory populated
// by FetchRelease or scripts/lib/release.sh (checking both SHA256SUMS and the
// binary's signature, release.json, and ELF architecture).
func LoadVerifiedRelease(ctx context.Context, v Verifier, dir string, tag Tag, arch, commit string) (*Fetched, error) {
	if err := CheckPrivateDir(dir); err != nil {
		return nil, err
	}
	private, err := os.MkdirTemp("", "explorer-verify-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(private)
	sums, err := verifiedSums(ctx, v, dir, private)
	if err != nil {
		return nil, err
	}
	m, err := verifiedManifest(dir, sums, tag, commit, arch)
	if err != nil {
		return nil, err
	}
	asset := BinaryAsset(arch)
	want, ok := sums[asset]
	if !ok {
		return nil, fmt.Errorf("the signed %s does not list %s", SumsFile, asset)
	}
	bf, err := openVerifiedBinary(dir, asset, want, arch)
	if err != nil {
		return nil, err
	}
	binCopy := filepath.Join(private, asset)
	if err := copyFromFD(bf, binCopy, want); err != nil {
		_ = bf.Close()
		return nil, err
	}
	bundle, err := readPrivateFile(dir, asset+BundleSuffix)
	if err != nil {
		_ = bf.Close()
		return nil, err
	}
	if err := os.WriteFile(binCopy+BundleSuffix, bundle, 0o600); err != nil {
		_ = bf.Close()
		return nil, err
	}
	if err := v.VerifyBlob(ctx, binCopy, binCopy+BundleSuffix); err != nil {
		_ = bf.Close()
		return nil, fmt.Errorf("%s: %w", asset, err)
	}
	return &Fetched{Tag: tag, Binary: filepath.Join(dir, asset), Manifest: m, Sums: sums, BinaryFile: bf, BinarySHA256: want}, nil
}

func verifiedSums(ctx context.Context, v Verifier, dir, private string) (Sums, error) {
	raw, err := readPrivateFile(dir, SumsFile)
	if err != nil {
		return nil, err
	}
	bundle, err := readPrivateFile(dir, SumsFile+BundleSuffix)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no signature for %s in %s — refusing an unsigned release", SumsFile, dir)
		}
		return nil, err
	}
	p := filepath.Join(private, SumsFile)
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(p+BundleSuffix, bundle, 0o600); err != nil {
		return nil, err
	}
	if err := v.VerifyBlob(ctx, p, p+BundleSuffix); err != nil {
		return nil, fmt.Errorf("%s: %w", SumsFile, err)
	}
	return ParseSums(raw)
}

func verifiedManifest(dir string, sums Sums, tag Tag, commit, arch string) (Manifest, error) {
	want, ok := sums[ManifestFile]
	if !ok {
		return Manifest{}, fmt.Errorf("the signed %s does not list %s", SumsFile, ManifestFile)
	}
	raw, err := readPrivateFile(dir, ManifestFile)
	if err != nil {
		return Manifest{}, err
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != want {
		return Manifest{}, fmt.Errorf("%s has SHA-256 %s but the signed %s says %s — refusing it", ManifestFile, got, SumsFile, want)
	}
	m, err := ParseManifest(raw, tag)
	if err != nil {
		return Manifest{}, err
	}
	if commit != "" && !strings.EqualFold(m.Commit, commit) {
		return Manifest{}, fmt.Errorf("%s says %s is commit %s, but the tag resolves to %s here — refusing a release whose tag was moved", ManifestFile, tag, m.Commit, commit)
	}
	if arch != "" && len(m.Binaries) > 0 {
		if b, ok := m.Binaries["linux/"+arch]; ok && b.SHA256 != "" {
			asset := BinaryAsset(arch)
			if b.Name != "" && b.Name != asset {
				return Manifest{}, fmt.Errorf("%s: linux/%s binary name %q != %q", ManifestFile, arch, b.Name, asset)
			}
			if !strings.EqualFold(b.SHA256, sums[asset]) {
				return Manifest{}, fmt.Errorf("%s: linux/%s sha256 %s != %s in %s", ManifestFile, arch, b.SHA256, sums[asset], SumsFile)
			}
		}
	}
	return m, nil
}

func openVerifiedBinary(dir, name, want, arch string) (*os.File, error) {
	f, err := openPrivate(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		_ = f.Close()
		return nil, err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		_ = f.Close()
		return nil, fmt.Errorf("%s has SHA-256 %s but the signed %s says %s — refusing it", name, got, SumsFile, want)
	}
	if err := checkELFArchFrom(f, name, arch); err != nil {
		_ = f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func readPrivateFile(dir, name string) ([]byte, error) {
	const limit = maxMetaBytes
	f, err := openPrivate(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes — refusing it", name, limit)
	}
	return raw, nil
}

func openPrivate(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: file inside checked private staging dir.
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || !ok || int(st.Uid) != os.Geteuid() || fi.Mode().Perm()&0o022 != 0 {
		_ = f.Close()
		return nil, fmt.Errorf("%s is not a private regular file owned by uid %d — refusing it", path, os.Geteuid())
	}
	return f, nil
}

func copyFromFD(src *os.File, dst, want string) error {
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // G304: private temp file.
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(out, h), src)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("the binary changed while it was being copied (%s, want %s)", got, want)
	}
	_, err = src.Seek(0, io.SeekStart)
	return err
}

func checkELFArchFrom(r io.ReaderAt, name, arch string) error {
	f, err := elf.NewFile(r)
	if err != nil {
		return fmt.Errorf("%s is not an ELF executable: %w", name, err)
	}
	want := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}[arch]
	if f.Machine != want {
		return fmt.Errorf("%s is built for %s, this box is linux/%s — refusing it", name, f.Machine, arch)
	}
	return nil
}

// EnsurePrivateDir creates dir (0700) when missing, tightens it to 0700 when
// owned by this user, and then verifies CheckPrivateDir.
func EnsurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if fi, err := os.Lstat(dir); err == nil && fi.IsDir() {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) == os.Geteuid() && fi.Mode().Perm() != 0o700 {
			if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: tightening directory permissions to 0700.
				return err
			}
		}
	}
	return CheckPrivateDir(dir)
}

// CheckPrivateDir requires dir to be a directory owned by this user, mode
// 0700, with every ancestor owned by root or this user and closed to
// group/other writes (or sticky).
func CheckPrivateDir(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return fmt.Errorf("staging dir %s: %w", dir, err)
	}
	euid := os.Geteuid()
	fi, err := os.Lstat(resolved) //nolint:gosec // G703: walking resolved path to enforce root/self ownership.
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || !ok || int(st.Uid) != euid || fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("staging dir %s must be a directory owned by uid %d with mode 0700 (is %v) — refusing it", resolved, euid, fi.Mode())
	}
	for p := filepath.Dir(resolved); ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p) //nolint:gosec // G703: walking ancestor directories to enforce ownership.
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || (st.Uid != 0 && int(st.Uid) != euid) {
			return fmt.Errorf("staging dir %s sits under %s, owned by uid %d — another user could replace it; use a dir under a root- or self-owned path", resolved, p, st.Uid)
		}
		if fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("staging dir %s sits under %s (mode %v), which others can write to — they could replace it; use a dir under a path only root writes", resolved, p, fi.Mode())
		}
		if p == "/" || p == filepath.Dir(p) {
			return nil
		}
	}
}
