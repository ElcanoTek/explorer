// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package ops

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type fakeVerifier struct {
	failOn string
	calls  []string
}

func (v *fakeVerifier) VerifyBlob(_ context.Context, path, bundle string) error {
	base := filepath.Base(path)
	v.calls = append(v.calls, base)
	raw, err := os.ReadFile(bundle)
	if err != nil {
		return err
	}
	if string(raw) != "sig:"+base {
		return fmt.Errorf("bad signature bundle for %s", base)
	}
	if v.failOn == base {
		return fmt.Errorf("signature verification failed for %s", base)
	}
	return nil
}

// minimalELF constructs a minimal 64-bit little-endian ELF header for machine.
func minimalELF(machine elf.Machine) []byte {
	buf := make([]byte, 64)
	copy(buf[0:4], []byte{0x7f, 'E', 'L', 'F'})
	buf[4] = byte(elf.ELFCLASS64)
	buf[5] = byte(elf.ELFDATA2LSB)
	buf[6] = byte(elf.EV_CURRENT)
	binary.LittleEndian.PutUint16(buf[16:18], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(buf[18:20], uint16(machine))
	binary.LittleEndian.PutUint32(buf[20:24], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint16(buf[52:54], 64)
	return buf
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

type releaseFixture struct {
	tag    Tag
	commit string
	files  map[string][]byte
}

func newReleaseFixture(t *testing.T, tagStr, commit string) *releaseFixture {
	t.Helper()
	tag, err := ParseTag(tagStr)
	if err != nil {
		t.Fatal(err)
	}
	amd64Bin := minimalELF(elf.EM_X86_64)
	arm64Bin := minimalELF(elf.EM_AARCH64)
	man := Manifest{
		Schema:  1,
		Tag:     tag.String(),
		Version: tag.Version(),
		Commit:  commit,
		BuiltAt: "2026-11-07T00:00:00Z",
		Binaries: map[string]ManifestBinary{
			"linux/amd64": {Name: "explorer-linux-amd64", SHA256: sha256Hex(amd64Bin)},
			"linux/arm64": {Name: "explorer-linux-arm64", SHA256: sha256Hex(arm64Bin)},
		},
	}
	manBytes, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	sums := fmt.Sprintf("%s  explorer-linux-amd64\n%s  explorer-linux-arm64\n%s  release.json\n",
		sha256Hex(amd64Bin), sha256Hex(arm64Bin), sha256Hex(manBytes))
	files := map[string][]byte{
		"explorer-linux-amd64":               amd64Bin,
		"explorer-linux-amd64.sigstore.json": []byte("sig:explorer-linux-amd64"),
		"explorer-linux-arm64":               arm64Bin,
		"explorer-linux-arm64.sigstore.json": []byte("sig:explorer-linux-arm64"),
		"release.json":                       manBytes,
		"SHA256SUMS":                         []byte(sums),
		"SHA256SUMS.sigstore.json":           []byte("sig:SHA256SUMS"),
	}
	return &releaseFixture{tag: tag, commit: commit, files: files}
}

func (fx *releaseFixture) server(t *testing.T) *httptest.Server {
	t.Helper()
	prefix := "/" + fx.tag.String() + "/"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/latest" {
			_ = json.NewEncoder(w).Encode(map[string]string{"tag_name": fx.tag.String()})
			return
		}
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.NotFound(w, r)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, prefix)
		data, ok := fx.files[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "explorer-release-test.")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestParseTagAndCompare(t *testing.T) {
	t1, err := ParseTag("v2026.11.07.1")
	if err != nil || t1.String() != "v2026.11.07.1" || t1.Version() != "2026.11.07.1" {
		t.Fatalf("t1 = %+v, err = %v", t1, err)
	}
	t2, err := ParseTag("v2026.11.07.2")
	if err != nil {
		t.Fatal(err)
	}
	t3, err := ParseTag("v2026.11.08.1")
	if err != nil {
		t.Fatal(err)
	}
	t1Copy := Tag{Year: 2026, Month: 11, Day: 7, N: 1}
	if t1.Compare(t2) >= 0 || t2.Compare(t1) <= 0 || t2.Compare(t3) >= 0 || t1.Compare(t1Copy) != 0 {
		t.Fatal("Tag.Compare ordering wrong")
	}
	for _, bad := range []string{"", "2026.11.07.1", "v2026.11.07.0", "v2026.11.7.1", "v2026.11.07.01", "v2026.11.07.1-rc1"} {
		if _, err := ParseTag(bad); err == nil {
			t.Errorf("ParseTag(%q) succeeded", bad)
		}
	}
	if v, ok := ParseVersion("2026.11.07.3+gabcdef0"); !ok || v.String() != "v2026.11.07.3" {
		t.Fatalf("ParseVersion = %+v, %v", v, ok)
	}
}

func TestParseSums(t *testing.T) {
	sumA := strings.Repeat("a", 64)
	sumB := strings.Repeat("B", 64)
	sums, err := ParseSums([]byte(sumA + "  explorer-linux-amd64\r\n" + sumB + " *release.json\n"))
	if err != nil {
		t.Fatal(err)
	}
	if sums["explorer-linux-amd64"] != sumA || sums["release.json"] != strings.ToLower(sumB) {
		t.Fatalf("sums = %v", sums)
	}
	for _, bad := range []string{
		"",
		"not-a-sum-line\n",
		strings.Repeat("z", 64) + "  explorer-linux-amd64\n",
		sumA + "  ../escape\n",
		sumA + "  sub/file\n",
		sumA + "  dup\n" + sumA + "  dup\n",
	} {
		if _, err := ParseSums([]byte(bad)); err == nil {
			t.Errorf("ParseSums(%q) succeeded", bad)
		}
	}
}

func TestCosignLockSyncedAndVerified(t *testing.T) {
	rootLock, err := os.ReadFile(filepath.Join("..", "..", "cosign.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rootLock, cosignLockFile) {
		t.Fatal("cosign.lock at repo root and internal/ops/cosign.lock differ")
	}
	pin := PinnedCosign()
	if pin.Version != "v3.1.4" || len(pin.SHA256["linux/amd64"]) != 64 || len(pin.SHA256["linux/arm64"]) != 64 {
		t.Fatalf("unexpected pin: %+v", pin)
	}

	fakeCosign := []byte("#!/bin/sh\nexit 0\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(fakeCosign)
	}))
	defer srv.Close()
	t.Setenv("EXPLORER_COSIGN_URL", srv.URL)
	t.Setenv("EXPLORER_COSIGN_BIN", "")

	cacheDir := filepath.Join(privateTempDir(t), "cosign")
	if _, err := EnsureCosign(context.Background(), NewDownloader(), cacheDir, "amd64"); err == nil || !strings.Contains(err.Error(), "cosign.lock pins") {
		t.Fatalf("wrong cosign digest accepted: %v", err)
	}
}

func TestCosignVerifyBlobArgv(t *testing.T) {
	dir := privateTempDir(t)
	argsFile := filepath.Join(dir, "args")
	fakeBin := filepath.Join(dir, "cosign")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argsFile + "\n"
	if err := os.WriteFile(fakeBin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	blob := filepath.Join(dir, "SHA256SUMS")
	bundle := blob + BundleSuffix
	if err := os.WriteFile(blob, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundle, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Cosign{Bin: fakeBin, Policy: Policy{Identity: SignerIdentity, Issuer: OIDCIssuer, TrustedRoot: "/tmp/root.json"}}
	if err := c.VerifyBlob(context.Background(), blob, bundle); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		"verify-blob",
		"--bundle", bundle,
		"--certificate-identity", SignerIdentity,
		"--certificate-oidc-issuer", OIDCIssuer,
		"--trusted-root", "/tmp/root.json",
		blob,
	}, "\n") + "\n"
	if string(got) != want {
		t.Fatalf("argv:\n%s\nwant:\n%s", got, want)
	}
}

func TestFetchReleaseAndLoadVerifiedRelease(t *testing.T) {
	const commit = "0123456789abcdef0123456789abcdef01234567"
	fx := newReleaseFixture(t, "v2026.11.07.2", commit)
	srv := fx.server(t)
	dl := NewDownloader()

	for _, arch := range []string{"amd64", "arm64"} {
		dir := filepath.Join(privateTempDir(t), arch)
		v := &fakeVerifier{}
		rel, err := FetchRelease(context.Background(), dl, v, FetchOptions{
			Tag:     fx.tag,
			Arch:    arch,
			Dir:     dir,
			BaseURL: srv.URL,
			Current: "v2026.11.07.1",
			Commit:  commit,
		})
		if err != nil {
			t.Fatalf("%s: %v", arch, err)
		}
		if rel.Manifest.Commit != commit || len(v.calls) != 2 {
			t.Fatalf("%s: rel=%+v calls=%v", arch, rel, v.calls)
		}
		fi, err := os.Stat(rel.Binary)
		if err != nil || fi.Mode().Perm() != 0o755 {
			t.Fatalf("%s binary mode: %v %v", arch, fi, err)
		}

		// LoadVerifiedRelease re-verifies the staged directory.
		v2 := &fakeVerifier{}
		loaded, err := LoadVerifiedRelease(context.Background(), v2, dir, fx.tag, arch, commit)
		if err != nil {
			t.Fatalf("%s LoadVerifiedRelease: %v", arch, err)
		}
		_ = loaded.BinaryFile.Close()
		if len(v2.calls) != 2 {
			t.Fatalf("%s LoadVerifiedRelease calls = %v", arch, v2.calls)
		}
	}

	// LatestTag resolves from /latest.
	t.Setenv("EXPLORER_RELEASE_LATEST_URL", srv.URL+"/latest")
	if got, err := dl.LatestTag(context.Background()); err != nil || got != fx.tag {
		t.Fatalf("LatestTag = %v, %v", got, err)
	}
}

func TestFetchReleaseRejectsTamperingAndDowngrades(t *testing.T) {
	const commit = "0123456789abcdef0123456789abcdef01234567"

	runCase := func(t *testing.T, mutate func(*releaseFixture, *fakeVerifier, *FetchOptions)) error {
		t.Helper()
		fx := newReleaseFixture(t, "v2026.11.07.2", commit)
		v := &fakeVerifier{}
		opts := FetchOptions{
			Tag:     fx.tag,
			Arch:    "amd64",
			Dir:     filepath.Join(privateTempDir(t), "stage"),
			Current: "v2026.11.07.1",
			Commit:  commit,
		}
		mutate(fx, v, &opts)
		srv := fx.server(t)
		opts.BaseURL = srv.URL
		_, err := FetchRelease(context.Background(), NewDownloader(), v, opts)
		return err
	}

	// 1. Tampered binary (SHA-256 mismatch).
	if err := runCase(t, func(fx *releaseFixture, _ *fakeVerifier, _ *FetchOptions) {
		fx.files["explorer-linux-amd64"] = append([]byte{}, fx.files["explorer-linux-amd64"]...)
		fx.files["explorer-linux-amd64"][63] ^= 0xff
	}); err == nil || !strings.Contains(err.Error(), "has SHA-256") {
		t.Fatalf("tampered binary: %v", err)
	}

	// 2. Missing SHA256SUMS signature bundle.
	if err := runCase(t, func(fx *releaseFixture, _ *fakeVerifier, _ *FetchOptions) {
		delete(fx.files, "SHA256SUMS.sigstore.json")
	}); err == nil || !strings.Contains(err.Error(), "no signature for SHA256SUMS") {
		t.Fatalf("missing sums sig: %v", err)
	}

	// 3. Missing binary signature bundle.
	if err := runCase(t, func(fx *releaseFixture, _ *fakeVerifier, _ *FetchOptions) {
		delete(fx.files, "explorer-linux-amd64.sigstore.json")
	}); err == nil || !strings.Contains(err.Error(), "no signature for explorer-linux-amd64") {
		t.Fatalf("missing binary sig: %v", err)
	}

	// 4. Bad signature on binary.
	if err := runCase(t, func(_ *releaseFixture, v *fakeVerifier, _ *FetchOptions) {
		v.failOn = "explorer-linux-amd64"
	}); err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("bad binary sig: %v", err)
	}

	// 5. Wrong ELF architecture (arm64 binary served as amd64).
	if err := runCase(t, func(fx *releaseFixture, _ *fakeVerifier, _ *FetchOptions) {
		arm := minimalELF(elf.EM_AARCH64)
		fx.files["explorer-linux-amd64"] = arm
		fx.files["SHA256SUMS"] = []byte(fmt.Sprintf("%s  explorer-linux-amd64\n%s  release.json\n",
			sha256Hex(arm), sha256Hex(fx.files["release.json"])))
	}); err == nil || !strings.Contains(err.Error(), "built for") {
		t.Fatalf("wrong ELF arch: %v", err)
	}

	// 6. Replay attack: release.json names a different tag.
	if err := runCase(t, func(fx *releaseFixture, _ *fakeVerifier, _ *FetchOptions) {
		replayed := bytes.ReplaceAll(fx.files["release.json"], []byte("v2026.11.07.2"), []byte("v2026.11.07.1"))
		fx.files["release.json"] = replayed
		fx.files["SHA256SUMS"] = []byte(fmt.Sprintf("%s  explorer-linux-amd64\n%s  release.json\n",
			sha256Hex(fx.files["explorer-linux-amd64"]), sha256Hex(replayed)))
	}); err == nil || !strings.Contains(err.Error(), "refusing a release served under another tag") {
		t.Fatalf("replayed tag: %v", err)
	}

	// 7. Moved-tag attack: release.json commit != local tag commit.
	if err := runCase(t, func(_ *releaseFixture, _ *fakeVerifier, o *FetchOptions) {
		o.Commit = "ffffffffffffffffffffffffffffffffffffffff"
	}); err == nil || !strings.Contains(err.Error(), "refusing a release whose tag was moved") {
		t.Fatalf("moved tag: %v", err)
	}

	// 8. Downgrade refused without AllowDowngrade, allowed with AllowDowngrade.
	if err := runCase(t, func(_ *releaseFixture, _ *fakeVerifier, o *FetchOptions) {
		o.Current = "v2026.11.08.1"
	}); !errors.Is(err, ErrDowngrade) {
		t.Fatalf("downgrade not refused: %v", err)
	}
	if err := runCase(t, func(_ *releaseFixture, _ *fakeVerifier, o *FetchOptions) {
		o.Current = "v2026.11.08.1"
		o.AllowDowngrade = true
	}); err != nil {
		t.Fatalf("AllowDowngrade failed: %v", err)
	}
}

func TestDoctorDoesNotRequireGoInSignedReleaseMode(t *testing.T) {
	fx := newDoctorFixture(t, healthyDotenv())
	fx.f.tools["git"] = true
	fx.f.tools["systemctl"] = true
	checks := fx.run(t)
	if _, hasGo := checks["go"]; hasGo {
		t.Fatalf("doctor checked for go in default signed-release mode: %+v", checks["go"])
	}
	if checks["git"].Status != "ok" || checks["systemctl"].Status != "ok" {
		t.Fatalf("git/systemctl checks: %+v %+v", checks["git"], checks["systemctl"])
	}

	// When EXPLORER_FROM_SOURCE=1, doctor requires go.
	fx.d.environ = func() map[string]string { return map[string]string{"EXPLORER_FROM_SOURCE": "1"} }
	checks = fx.run(t)
	if c, ok := checks["go"]; !ok || c.Status != "fail" {
		t.Fatalf("expected go check to fail when EXPLORER_FROM_SOURCE=1: %+v", c)
	}

	// Detached HEAD at a release tag is accepted by checkCheckout.
	_, _, clone := cloneBehindOrigin(t)
	gitT(t, clone, "tag", "v2026.11.07.1")
	gitT(t, clone, "checkout", "--detach", "-q", "v2026.11.07.1")
	if c := branchCheck(t, clone); c.Status != "ok" || !strings.Contains(c.Detail, "v2026.11.07.1") {
		t.Fatalf("detached at release tag: %+v", c)
	}
}

func TestParseUpdateArgsReleaseFlags(t *testing.T) {
	t.Setenv("EXPLORER_FROM_SOURCE", "")
	t.Setenv("EXPLORER_UPDATE_FROM_SOURCE", "")
	t.Setenv("EXPLORER_RELEASE_TAG", "")
	t.Setenv("EXPLORER_UPDATE_TAG", "")
	t.Setenv("EXPLORER_UPDATE_ALLOW_DOWNGRADE", "")

	o, err := parseUpdateArgs([]string{"--tag", "v2026.11.07.1", "--allow-downgrade", "--from-source"}, false)
	if err != nil || o.tag != "v2026.11.07.1" || !o.allowDowngrade || !o.fromSource || !o.modeExplicit {
		t.Fatalf("o=%+v err=%v", o, err)
	}
	o, err = parseUpdateArgs([]string{"--tag=v2026.11.07.2", "--artifact"}, false)
	if err != nil || o.tag != "v2026.11.07.2" || o.fromSource || !o.modeExplicit {
		t.Fatalf("o=%+v err=%v", o, err)
	}
	if _, err := parseUpdateArgs([]string{"--tag"}, false); err == nil {
		t.Fatal("missing --tag value accepted")
	}
}

func TestResolveAndStageSignedReleaseWithoutGo(t *testing.T) {
	_, seed, clone := cloneBehindOrigin(t)
	gitT(t, seed, "tag", "v2026.11.07.1")
	gitT(t, seed, "push", "-q", "origin", "refs/tags/v2026.11.07.1")
	pushSeed(t, seed, "release two\n")
	commit2 := gitT(t, seed, "rev-parse", "HEAD")
	gitT(t, seed, "tag", "v2026.11.07.2")
	gitT(t, seed, "push", "-q", "origin", "refs/tags/v2026.11.07.2")

	fx := newReleaseFixture(t, "v2026.11.07.2", commit2)
	srv := fx.server(t)
	t.Setenv("EXPLORER_RELEASE_BASE_URL", srv.URL)
	t.Setenv("EXPLORER_RELEASE_LATEST_URL", srv.URL+"/latest")
	t.Setenv("EXPLORER_RELEASE_STAGING", "")

	origVerifier := newReleaseVerifier
	t.Cleanup(func() { newReleaseVerifier = origVerifier })
	newReleaseVerifier = func(context.Context, *Downloader, Paths, string) (Verifier, error) {
		return &fakeVerifier{}, nil
	}

	r := newFake("git")
	r.real["git"] = true
	p := Paths{SrcDir: clone, AppDir: filepath.Join(t.TempDir(), "app"), BuildCache: filepath.Join(t.TempDir(), "cache")}
	u, _ := testUI()
	before := gitT(t, clone, "rev-parse", "HEAD")
	targetTag, after, err := resolveReleaseTarget(context.Background(), u, r, p, updateOpts{yes: true}, before, before, "v2026.11.07.1", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if targetTag.String() != "v2026.11.07.2" || after != commit2 {
		t.Fatalf("targetTag=%s after=%s want %s", targetTag, after, commit2)
	}

	staging := privateTempDir(t)
	dst := filepath.Join(staging, "explorer")
	if err := stageSignedRelease(context.Background(), p, targetTag, after, "v2026.11.07.1", false, staging, dst); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dst); err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("staged binary: %v %v", fi, err)
	}
}

func TestVersionAndReleaseScriptsContract(t *testing.T) {
	scriptsDir := filepath.Join("..", "..", "scripts")
	out, err := exec.Command("bash", filepath.Join(scriptsDir, "version.sh"), "filter").CombinedOutput()
	if err != nil {
		t.Fatalf("version.sh filter: %v %s", err, out)
	}
	cmd := exec.Command("bash", filepath.Join(scriptsDir, "version.sh"), "filter")
	cmd.Stdin = strings.NewReader("v2026.11.07.1\nv1.2.3\nv2026.11.07.0\nv2026.11.07.12\n")
	filtered, err := cmd.CombinedOutput()
	if err != nil || string(filtered) != "v2026.11.07.1\nv2026.11.07.12\n" {
		t.Fatalf("filtered = %q, err = %v", filtered, err)
	}

	// release-push-rejection.sh classifies contention, workflow-permission, and other.
	dir := t.TempDir()
	for name, tc := range map[string]struct{ log, want string }{
		"contention":          {"! [rejected] v2026.11.07.1 -> v2026.11.07.1 (already exists)\n", "contention"},
		"workflow-permission": {"! [remote rejected] (refusing to allow a GitHub App to create or update workflow `.github/workflows/ci.yml` without `workflows` permission)\n", "workflow-permission"},
		"other":               {"remote: error: GH006: Protected branch update failed\n", "other"},
	} {
		logFile := filepath.Join(dir, name+".log")
		writeFile(t, logFile, tc.log, 0o644)
		got, err := exec.Command("bash", filepath.Join(scriptsDir, "release-push-rejection.sh"), logFile).CombinedOutput()
		if err != nil || strings.TrimSpace(string(got)) != tc.want {
			t.Fatalf("%s: got %q, err %v (want %q)", name, got, err, tc.want)
		}
	}

	// retry-transient.sh retries transient failures and stops on permanent ones.
	counter := filepath.Join(dir, "count")
	flaky := filepath.Join(dir, "flaky.sh")
	writeFile(t, flaky, "#!/bin/sh\nc=$(cat "+counter+" 2>/dev/null || echo 0)\nc=$((c+1))\necho $c > "+counter+"\nif [ $c -lt 2 ]; then echo 'HTTP 503 Service Unavailable' >&2; exit 1; fi\n", 0o755)
	retryCmd := exec.Command("bash", filepath.Join(scriptsDir, "retry-transient.sh"), flaky)
	retryCmd.Env = append(os.Environ(), "RETRY_BASE_DELAY=0", "RETRY_ATTEMPTS=3")
	if out, err := retryCmd.CombinedOutput(); err != nil {
		t.Fatalf("retry-transient.sh failed: %v\n%s", err, out)
	}
	perm := filepath.Join(dir, "perm.sh")
	writeFile(t, perm, "#!/bin/sh\necho 'HTTP 403 Forbidden' >&2\nexit 1\n", 0o755)
	permCmd := exec.Command("bash", filepath.Join(scriptsDir, "retry-transient.sh"), perm)
	permCmd.Env = append(os.Environ(), "RETRY_BASE_DELAY=0", "RETRY_ATTEMPTS=3")
	if out, err := permCmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "retrying cannot fix") {
		t.Fatalf("expected permanent error not to retry: %v\n%s", err, out)
	}

	// .github/workflows/release.yml pins SignerIdentity and cosign.lock.
	wf, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		SignerIdentity,
		OIDCIssuer,
		"github.com/ElcanoTek/explorer/internal/version.revision=",
		"scripts/retry-transient.sh",
		"scripts/release-push-rejection.sh",
		"scripts/release-newer-published.sh",
	} {
		if !bytes.Contains(wf, []byte(want)) {
			t.Errorf("release.yml missing %q", want)
		}
	}
}
