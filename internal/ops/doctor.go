// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package ops

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ElcanoTek/explorer/deploy"
	"github.com/ElcanoTek/explorer/internal/centralauth"
	"github.com/ElcanoTek/explorer/internal/config"
	"github.com/ElcanoTek/explorer/internal/dotenv"
	"github.com/ElcanoTek/explorer/internal/version"
)

// Check is one doctor finding. Status is "ok", "warn" or "fail"; Detail is
// what passed, or the remedy when it did not.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// doctor holds every probe the checks use, so tests can replace any of
// them. Doctor is strictly read-only: it never writes, fetches, restarts or
// executes anything from a service-writable path.
type doctor struct {
	p   Paths
	r   Runner
	now func() time.Time
	// httpStatus GETs a URL and returns its status code.
	httpStatus func(ctx context.Context, url string) (int, error)
	// certExpiry verifies host's served certificate and returns its expiry.
	certExpiry func(ctx context.Context, host string) (time.Time, error)
	osRelease  func() (map[string]string, error)
	fedoraFeed func(ctx context.Context) ([]byte, error)
	diskFree   func(path string) (uint64, error)
	euid       func() int
	environ    func() map[string]string
	selfPath   func() (string, error)
	selfRev    string

	checks []Check
}

func newDoctor(p Paths, r Runner) *doctor {
	return &doctor{
		p: p, r: r, now: time.Now,
		httpStatus: func(ctx context.Context, u string) (int, error) {
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
			if err != nil {
				return 0, err
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return 0, err
			}
			_ = resp.Body.Close()
			return resp.StatusCode, nil
		},
		certExpiry: func(ctx context.Context, host string) (time.Time, error) {
			leaf, verr, err := certInfo(ctx, host)
			if err != nil {
				return time.Time{}, err
			}
			if verr != nil {
				return time.Time{}, verr
			}
			return leaf.NotAfter, nil
		},
		osRelease: func() (map[string]string, error) { return readOSRelease("/etc/os-release") },
		fedoraFeed: func(ctx context.Context) ([]byte, error) {
			ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://fedoraproject.org/releases.json", nil)
			if err != nil {
				return nil, err
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
			}
			buf := make([]byte, 0, 1<<16)
			tmp := make([]byte, 1<<15)
			for len(buf) < 8<<20 {
				n, rerr := resp.Body.Read(tmp)
				buf = append(buf, tmp[:n]...)
				if rerr != nil {
					break
				}
			}
			return buf, nil
		},
		diskFree: func(path string) (uint64, error) {
			var st syscall.Statfs_t
			if err := syscall.Statfs(path, &st); err != nil {
				return 0, err
			}
			return st.Bavail * uint64(st.Bsize), nil //nolint:gosec // G115: statfs block sizes are positive.
		},
		euid:     os.Geteuid,
		environ:  dotenv.Environ,
		selfPath: os.Executable,
		selfRev:  version.Revision(),
	}
}

func (d *doctor) add(name string, good bool, detail, remedy string, warning bool) {
	c := Check{Name: name, Status: "ok", Detail: detail}
	if !good {
		c.Detail = remedy
		c.Status = "fail"
		if warning {
			c.Status = "warn"
		}
	}
	d.checks = append(d.checks, c)
}

func (d *doctor) run(ctx context.Context, c Cmd) Result {
	if c.Timeout == 0 {
		c.Timeout = 15 * time.Second
	}
	return d.r.Run(ctx, c)
}

func (d *doctor) has(name string) bool { _, ok := d.r.LookPath(name); return ok }

func readOSRelease(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: a path the installer chose, not request input.
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		out[k] = strings.Trim(v, `"'`)
	}
	return out, nil
}

// Diagnose runs every check.
func (d *doctor) Diagnose(ctx context.Context) []Check {
	d.checks = nil
	for _, tool := range []string{"git", "go", "systemctl"} {
		remedy := "Run bootstrap to install " + tool
		if tool == "go" {
			remedy = "the Go toolchain is missing, so explorer update cannot build — run: dnf install -y golang"
		}
		d.add(tool, d.has(tool), "installed", remedy, false)
	}
	d.checkBinary(ctx)
	merged, dotenvOK := d.checkEnvFiles()
	d.checkConfiguration(merged, dotenvOK)
	d.checkService(ctx)
	d.checkCaddy(ctx)
	d.checkInstalledFiles()
	d.checkHost(ctx)
	d.checkCheckout(ctx)
	return d.checks
}

func (d *doctor) checkBinary(ctx context.Context) {
	bin := d.p.BinPath()
	fi, err := os.Lstat(bin)
	switch {
	case err != nil:
		d.add("binary", false, "", bin+" missing — run explorer rebuild", false)
	case !fi.Mode().IsRegular() || statT(fi).Uid != trustedUID || fi.Mode().Perm() != 0o755:
		d.add("binary", false, "", bin+" must be a root-owned 0755 regular file — run explorer rebuild", false)
	default:
		d.add("binary", true, bin+" root-owned 0755", "", false)
	}

	marker, _ := os.ReadFile(d.p.RevisionFile())
	installed := strings.TrimSpace(string(marker))
	head := ""
	if res := d.run(ctx, d.gitCmd("rev-parse", "HEAD")); res.Code == 0 {
		head = strings.TrimSpace(res.Stdout)
	}
	self, _ := d.selfPath()
	isInstalled := self != "" && sameFile(self, bin)
	switch {
	case installed == "":
		d.add("revision", false, "", d.p.RevisionFile()+" missing — run explorer rebuild", false)
	case isInstalled && d.selfRev != installed:
		d.add("revision", false, "", fmt.Sprintf("the installed binary reports %s but the marker says %s — run explorer rebuild", short(d.selfRev), short(installed)), false)
	case head != "" && head != installed:
		d.add("revision", false, "", fmt.Sprintf("installed %s but the checkout is at %s — run explorer rebuild", short(installed), short(head)), true)
	default:
		d.add("revision", true, "installed "+short(installed), "", false)
	}
}

func sameFile(a, b string) bool {
	x, err1 := os.Stat(a)
	y, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(x, y)
}

// checkEnvFiles checks every dotenv the service loads (lstat only: never
// through a symlink, never opening a fifo) and returns their merged values
// as the service sees them.
func (d *doctor) checkEnvFiles() (map[string]string, bool) {
	texts := map[string]string{}
	for _, f := range []struct{ path, check string }{
		{d.p.EnvFile(), "env-permissions"},
		{d.p.SharedEnvFile(), "env-shared-permissions"},
	} {
		fi, err := os.Lstat(f.path)
		if err != nil {
			if f.path == d.p.EnvFile() {
				d.add(f.check, false, "", f.path+" missing — run bootstrap.sh", false)
			}
			continue
		}
		st := statT(fi)
		isLink := fi.Mode()&fs.ModeSymlink != 0
		isReg := fi.Mode().IsRegular()
		owner := strconv.FormatUint(uint64(st.Uid), 10)
		if u, err := user.LookupId(owner); err == nil {
			owner = u.Username
		}
		mode := fi.Mode().Perm()
		var problems []string
		if isLink {
			problems = append(problems, f.path+" is a symlink — replace it with a regular file")
		}
		if !isReg {
			problems = append(problems, f.path+" is not a regular file")
		}
		if st.Nlink > 1 {
			problems = append(problems, fmt.Sprintf("%s has %d hard links — want exactly 1", f.path, st.Nlink))
		}
		if mode != 0o600 {
			problems = append(problems, "chmod 600 "+f.path)
		}
		if owner != d.p.AppUser {
			problems = append(problems, fmt.Sprintf("chown %s:%s %s", d.p.AppUser, d.p.AppUser, f.path))
		}
		problems = append(problems, "(the installer requires a single-link regular file, owner-only)")
		good := isReg && !isLink && st.Nlink == 1 && mode == 0o600 && owner == d.p.AppUser
		d.add(f.check, good, owner+"-owned 0600, one link", strings.Join(problems, "; "), false)
		// A permissions fault must not hide a configuration fault, so read
		// what is safely readable regardless of the verdict above.
		if isReg && !isLink {
			if raw, err := os.ReadFile(f.path); err == nil {
				texts[f.path] = string(raw)
			}
		}
	}
	merged := d.environ()
	if t, ok := texts[d.p.SharedEnvFile()]; ok {
		for k, v := range dotenv.Resolve(dotenv.Parse(t), merged, false) {
			if _, set := merged[k]; !set && v.Set {
				merged[k] = v.S
			}
		}
	}
	t, ok := texts[d.p.EnvFile()]
	if ok {
		for k, v := range dotenv.Resolve(dotenv.Parse(t), merged, true) {
			if v.Set {
				merged[k] = v.S
			}
		}
	}
	return merged, ok
}

// centralProblems is every central-mode value a restart would refuse, from
// the same validators the auth client runs at startup. Absent keys are the
// configuration check's "missing" list, so only present values are judged.
// Messages name the key and the rule, never the value.
func centralProblems(env map[string]string) []string {
	var errs []error
	allowHTTP := config.Truthy(env["AUTH_ALLOW_INSECURE_HTTP"])
	for _, k := range []string{"AUTH_ISSUER_URL", "EXPLORER_PUBLIC_URL"} {
		if env[k] != "" {
			if _, err := centralauth.ValidateOrigin(k, env[k], allowHTTP); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if strings.TrimSpace(env["AUTH_CLIENT_ID"]) != "" {
		if _, err := centralauth.ValidateClientID(env["AUTH_CLIENT_ID"]); err != nil {
			errs = append(errs, err)
		}
	}
	if env["AUTH_CLIENT_SECRET"] != "" {
		if err := centralauth.ValidateClientSecret(env["AUTH_CLIENT_SECRET"]); err != nil {
			errs = append(errs, err)
		}
	}
	if raw, ok := env["AUTH_HTTP_TIMEOUT_SECONDS"]; ok {
		if _, err := centralauth.ParseTimeout(raw); err != nil {
			errs = append(errs, err)
		}
	}
	out := make([]string, 0, len(errs))
	for _, err := range errs {
		out = append(out, err.Error())
	}
	return out
}

func (d *doctor) checkConfiguration(merged map[string]string, dotenvOK bool) {
	mode := strings.TrimSpace(merged["EXPLORER_AUTH_MODE"])
	if mode == "" {
		mode = "elcano"
	}
	var missing []string
	if merged["AUTH_SIGNING_PUBKEY"] == "" {
		missing = append(missing, "AUTH_SIGNING_PUBKEY")
	}
	var central []string
	if mode == "central" {
		for _, k := range []string{"AUTH_ISSUER_URL", "EXPLORER_PUBLIC_URL", "AUTH_CLIENT_ID", "AUTH_CLIENT_SECRET"} {
			if merged[k] == "" {
				missing = append(missing, k)
			}
		}
		central = centralProblems(merged)
	}
	raw, err := base64.StdEncoding.DecodeString(merged["AUTH_SIGNING_PUBKEY"])
	keyOK := err == nil && len(raw) == 32
	modeOK := mode == "elcano" || mode == "central"
	_, cfgErr := config.FromEnv(merged)

	var problems []string
	if !dotenvOK {
		problems = append(problems, "could not parse .env; run doctor with sudo or restore .env")
	} else {
		if len(missing) > 0 {
			problems = append(problems, "missing: "+strings.Join(missing, ", "))
		}
		if !keyOK && merged["AUTH_SIGNING_PUBKEY"] != "" {
			problems = append(problems, "AUTH_SIGNING_PUBKEY is set but is not a 32-byte base64 Ed25519 key")
		}
		if !modeOK {
			problems = append(problems, fmt.Sprintf("EXPLORER_AUTH_MODE must be 'elcano' or 'central' (got '%s')", mode))
		}
		problems = append(problems, central...)
		if cfgErr != nil {
			problems = append(problems, cfgErr.Error())
		}
	}
	good := dotenvOK && len(missing) == 0 && keyOK && modeOK && len(central) == 0 && cfgErr == nil
	d.add("configuration", good, "auth signing key and auth mode configured", strings.Join(problems, "; "), false)
	if !dotenvOK {
		return
	}
	if len(merged["EXPLORER_SESSION_SECRET"]) < 32 {
		d.add("session-secret", false, "", "EXPLORER_SESSION_SECRET is shorter than 32 bytes — generate a longer one: openssl rand -hex 32, then: explorer env edit && explorer restart", false)
	} else {
		d.add("session-secret", true, "session secret >= 32 chars", "", false)
	}
	d.add("s3-archive", merged["EMAIL_S3_BUCKET"] != "", "EMAIL_S3_BUCKET set",
		"EMAIL_S3_BUCKET unset — every S3-backed feature errors; set it with: explorer env edit && explorer restart", true)
	key, secret := merged["AWS_ACCESS_KEY_ID"] != "", merged["AWS_SECRET_ACCESS_KEY"] != ""
	switch {
	case key != secret:
		d.add("aws-credentials", false, "", "Only one of AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY is set — fix both or clear both (the ambient credential chain is used when blank)", true)
	case !key:
		d.add("aws-credentials", false, "", "No static AWS keys — relying on the ambient credential chain (instance role, ~/.aws, AWS_PROFILE); ignore if that is intended", true)
	default:
		d.add("aws-credentials", true, "static AWS credentials configured", "", false)
	}
	if mode == "central" {
		db := merged["EXPLORER_ACCESS_DB"]
		if db == "" {
			db = filepath.Join(d.p.StateDir, "access.db")
		}
		fi, err := os.Lstat(db)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			d.add("access-db", false, "", db+" does not exist yet — it is created on first start; then grant users with: explorer access grant EMAIL", true)
		case err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600:
			d.add("access-db", false, "", db+" must be a regular file, mode 0600, owned by "+d.p.AppUser, true)
		default:
			owner := strconv.FormatUint(uint64(statT(fi).Uid), 10)
			if u, err := user.LookupId(owner); err == nil {
				owner = u.Username
			}
			d.add("access-db", owner == d.p.AppUser, db+" "+owner+"-owned 0600", db+" must be owned by "+d.p.AppUser+": chown "+d.p.AppUser+": "+db, true)
		}
	}
}

func (d *doctor) checkService(ctx context.Context) {
	active := d.run(ctx, Cmd{Name: "systemctl", Args: []string{"is-active", "--quiet", d.p.Service}}).Code == 0
	d.add("service", active, d.p.Service+" active", "Inspect explorer logs; then explorer restart", false)
	// Enablement is independent of activity: inactive AND disabled is two
	// faults, and a restart alone leaves the second (no start on boot).
	switch {
	case d.run(ctx, Cmd{Name: "systemctl", Args: []string{"is-enabled", "--quiet", d.p.Service}}).Code == 0:
		d.add("service-enabled", true, d.p.Service+" enabled", "", false)
	case active:
		d.add("service-enabled", false, "", d.p.Service+" is active but DISABLED — it will not start on boot: systemctl enable "+d.p.Service, true)
	default:
		d.add("service-enabled", false, "", d.p.Service+" is DISABLED and inactive — it will not start on boot: systemctl enable --now "+d.p.Service, true)
	}
	code, err := d.httpStatus(ctx, d.p.HealthURL)
	d.add("readiness", err == nil && code == http.StatusOK, "/health returns 200", "Readiness failed; inspect explorer logs", false)
	res := d.run(ctx, Cmd{Name: "systemctl", Args: []string{"show", "--property=MainPID", "--value", d.p.Service}})
	pid, perr := strconv.Atoi(strings.TrimSpace(res.Stdout))
	if res.Code == 0 && perr == nil && pid > 0 {
		d.add("running-binary", sameFile(fmt.Sprintf("/proc/%d/exe", pid), d.p.BinPath()),
			"running binary matches the installed binary", "Run explorer restart; the running binary is stale or inaccessible", false)
	}
	if exists(d.p.legacyUnits()[0]) || exists(d.p.legacyUnits()[1]) {
		d.add("legacy-units", false, "", "the Python-era explorer-attachment-cleanup timer is still installed — run explorer update (it removes it)", true)
	}
}

func (d *doctor) checkCaddy(ctx context.Context) {
	if d.has("nginx") && d.run(ctx, Cmd{Name: "systemctl", Args: []string{"is-active", "--quiet", "nginx.service"}}).Code == 0 {
		d.add("legacy-nginx", false, "", "nginx.service is active — Explorer standardizes on Caddy; rerun explorer bootstrap with a hostname and remove nginx/certbot", true)
	}
	snippet, host := caddySiteHost(d.p.Caddyfile)
	if snippet == "" {
		if d.has("caddy") {
			d.add("caddy", false, "", "no marker-owned Explorer Caddy site block found under "+d.p.Caddyfile+" — rerun explorer bootstrap with a hostname", true)
		}
		return
	}
	if !d.has("caddy") {
		// A configured site with no binary is an outage in waiting.
		d.add("caddy", false, "", "Explorer Caddy site block is installed at "+snippet+" but the caddy binary is missing — dnf install caddy, then rerun bootstrap", false)
		return
	}
	d.add("caddy", d.run(ctx, Cmd{Name: "systemctl", Args: []string{"is-active", "--quiet", "caddy.service"}}).Code == 0,
		"caddy.service active", "Inspect journalctl -u caddy", false)
	d.add("caddy-config", d.run(ctx, Cmd{Name: "caddy", Args: []string{"validate", "--config", d.p.Caddyfile, "--adapter", "caddyfile"}, Timeout: 30 * time.Second}).Code == 0,
		d.p.Caddyfile+" validates", "Caddy configuration invalid — run: caddy validate --config "+d.p.Caddyfile+" --adapter caddyfile", false)
	if host == "" {
		return
	}
	expiry, err := d.certExpiry(ctx, host)
	if err != nil {
		d.add("tls-cert", false, "", "could not verify the certificate for "+host+" — TLS verification failed or the host is unreachable; check DNS, firewall and the served certificate", true)
		return
	}
	day := expiry.UTC().Format("2006-01-02")
	days := int(expiry.Sub(d.now()).Hours() / 24)
	d.add("tls-cert", days > 30, fmt.Sprintf("%s cert expires %s (%d days)", host, day, days),
		fmt.Sprintf("certificate for %s expired or expires within 30 days (%s)", host, day), days > 0 && days <= 30)
}

func (d *doctor) checkInstalledFiles() {
	for _, f := range []struct {
		name, path string
		want       []byte
	}{
		{"units", d.p.UnitPath(), deploy.ServiceUnit},
		{"units", d.p.TmpfilesPath(), deploy.TmpfilesConf},
	} {
		switch {
		case !exists(f.path):
			d.add(f.name, false, "", filepath.Base(f.path)+" missing ("+f.path+") — rerun bootstrap.sh", false)
		default:
			d.add(f.name, fileEquals(f.path, f.want), filepath.Base(f.path)+" matches this release", filepath.Base(f.path)+" drifted from this release — run explorer update", false)
		}
	}
	// The CLI is how operators restart, update and grant access: missing is
	// a fault, not a skip.
	if !exists(d.p.CLITarget) || !exists(d.p.BinPath()) {
		d.add("operator-cli", false, "", "operator CLI missing ("+d.p.CLITarget+" or "+d.p.BinPath()+") — rerun bootstrap.sh or explorer update", false)
	} else {
		d.add("operator-cli", sameContent(d.p.CLITarget, d.p.BinPath()), d.p.CLITarget+" matches "+d.p.BinPath(),
			"operator CLI drifted from the installed binary — run explorer update", false)
	}
	free, err := d.diskFree(d.p.AppDir)
	if err != nil {
		d.add("disk", false, "", "Application directory is missing or inaccessible", false)
	} else {
		d.add("disk", free >= 1<<30, fmt.Sprintf("%.1f GiB available", float64(free)/(1<<30)),
			"Less than 1 GiB free; updates need room to build (Go caches live in "+d.p.BuildCache+")", false)
	}
}

// sshdPasswordCheck is nil when it cannot tell (not root, no sshd, or
// `sshd -T` failed), else whether sshd is key-only.
func (d *doctor) sshdPasswordCheck(ctx context.Context) *bool {
	if d.euid() != 0 || !d.has("sshd") {
		return nil
	}
	res := d.run(ctx, Cmd{Name: "sshd", Args: []string{"-T"}})
	if res.Code != 0 {
		return nil
	}
	keyOnly := !sshdAcceptsPasswords(res.Stdout)
	return &keyOnly
}

func (d *doctor) checkHost(ctx context.Context) {
	rel, err := d.osRelease()
	switch {
	case err != nil:
		d.add("os-support", false, "", "Cannot read OS lifecycle metadata", true)
	case rel["SUPPORT_END"] == "":
		d.add("os-support", false, "", "OS does not publish SUPPORT_END; verify vendor lifecycle", true)
	default:
		end, perr := time.Parse("2006-01-02", rel["SUPPORT_END"])
		if perr != nil {
			d.add("os-support", false, "", "Cannot read OS lifecycle metadata", true)
			break
		}
		days := int(end.Sub(d.now()).Hours() / 24)
		d.add("os-support", days >= 30, "support ends "+rel["SUPPORT_END"], "OS support ends "+rel["SUPPORT_END"]+"; plan host upgrade", true)
	}
	if keyOnly := d.sshdPasswordCheck(ctx); keyOnly != nil {
		d.add("sshd", *keyOnly, "key-only (no password login)", "sshd accepts passwords — see production-support README, Access: SSH keys", true)
	}
	if d.has("dnf") {
		switch d.run(ctx, Cmd{Name: "dnf", Args: []string{"--refresh", "check-update"}, Timeout: 90 * time.Second}).Code {
		case 0:
			d.add("packages", true, "no pending dnf updates", "", false)
		case 100: // dnf's "updates available"
			d.add("packages", false, "", "dnf updates available — run: sudo dnf upgrade --refresh", true)
		default:
			d.add("packages", false, "", "dnf check-update failed (network or repo issue)", true)
		}
		if rel != nil && rel["ID"] == "fedora" {
			if current, err := strconv.Atoi(rel["VERSION_ID"]); err == nil {
				d.checkFedora(ctx, current)
			}
		}
	} else {
		d.add("packages", false, "", "dnf not found; keep host packages current manually", true)
	}
	d.checkReboot(ctx)
}

func (d *doctor) checkFedora(ctx context.Context, current int) {
	latest := -1
	if raw, err := d.fedoraFeed(ctx); err == nil {
		var releases []struct {
			Version any `json:"version"`
		}
		if json.Unmarshal(raw, &releases) == nil {
			for _, r := range releases {
				s, ok := r.Version.(string)
				if !ok {
					continue
				}
				if n, err := strconv.Atoi(s); err == nil && isDigits(s) && n > latest {
					latest = n
				}
			}
		}
	}
	switch {
	case latest < 0:
		d.add("fedora", false, "", "could not read the Fedora release feed", true)
	case latest > current:
		d.add("fedora", false, "", fmt.Sprintf("Fedora %d vs latest stable %d — plan a distro upgrade", current, latest), true)
	default:
		d.add("fedora", true, fmt.Sprintf("Fedora %d (latest stable: %d)", current, latest), "", false)
	}
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

// checkReboot walks every installed tier: one "yes" wins over any number
// of "no" (a stale tier can disagree), unanimity of "no" passes, and only
// when no tier can answer is the verdict unknown. Exit codes other than 0/1
// (including a timeout) mean "this tier cannot say".
func (d *doctor) checkReboot(ctx context.Context) {
	var answers []bool
	if d.has("needs-restarting") {
		if c := d.run(ctx, Cmd{Name: "needs-restarting", Args: []string{"-r"}, Timeout: 10 * time.Second}).Code; c == 0 || c == 1 {
			answers = append(answers, c == 1)
		}
	}
	if d.has("dnf") {
		if c := d.run(ctx, Cmd{Name: "dnf", Args: []string{"needs-restarting", "-r"}, Timeout: 10 * time.Second}).Code; c == 0 || c == 1 {
			answers = append(answers, c == 1)
		}
	}
	if d.has("uname") && d.has("rpm") {
		running := d.run(ctx, Cmd{Name: "uname", Args: []string{"-r"}, Timeout: 10 * time.Second})
		installed := d.run(ctx, Cmd{Name: "rpm", Args: []string{"-q", "kernel", "--last"}, Timeout: 10 * time.Second})
		r, in := strings.TrimSpace(running.Stdout), strings.TrimSpace(installed.Stdout)
		if running.Code == 0 && installed.Code == 0 && r != "" && in != "" {
			newest := strings.TrimPrefix(strings.Fields(strings.SplitN(in, "\n", 2)[0])[0], "kernel-")
			answers = append(answers, r != newest)
		}
	}
	anyYes := false
	for _, a := range answers {
		anyYes = anyYes || a
	}
	switch {
	case anyYes:
		d.add("reboot", false, "", "kernel or core libraries updated — reboot the host when convenient", true)
	case len(answers) > 0:
		d.add("reboot", true, "no reboot pending", "", false)
	default:
		d.add("reboot", false, "", "could not determine reboot status — needs-restarting, dnf needs-restarting and rpm/uname all unavailable or failed", true)
	}
}

func (d *doctor) gitCmd(args ...string) Cmd {
	return Cmd{Name: "git", Args: append([]string{"-c", "safe.directory=" + d.p.SrcDir, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-C", d.p.SrcDir}, args...),
		Env: append(os.Environ(), "GIT_TERMINAL_PROMPT=0")}
}

func (d *doctor) git(ctx context.Context, args ...string) (int, string) {
	c := d.gitCmd(args...)
	c.Timeout = 10 * time.Second
	res := d.run(ctx, c)
	return res.Code, strings.TrimSpace(res.Stdout)
}

// checkCheckout compares the checkout with the LIVE remote using ls-remote:
// a fetch would write FETCH_HEAD and move refs, and doctor never mutates
// what it diagnoses. Direction comes from local ancestry, so a checkout
// that is ahead is never called behind.
func (d *doctor) checkCheckout(ctx context.Context) {
	if !exists(filepath.Join(d.p.SrcDir, ".git")) {
		d.add("checkout", false, "", "no source checkout at "+d.p.SrcDir+" — explorer update will not work", true)
		return
	}
	code, dirty := d.git(ctx, "status", "--porcelain")
	d.add("checkout", code == 0 && dirty == "", "clean", "Resolve local source changes before explorer update", false)
	code, branch := d.git(ctx, "rev-parse", "--abbrev-ref", "HEAD")
	if code == 0 && branch != "main" {
		d.add("branch", false, "", fmt.Sprintf("checkout is on '%s', not main — run explorer update or: git -C %s checkout main", branch, d.p.SrcDir), true)
		return
	}
	codeHead, head := d.git(ctx, "rev-parse", "HEAD")
	codeRemote, remote := d.git(ctx, "ls-remote", "origin", "main")
	remoteSHA := ""
	if codeRemote == 0 && remote != "" {
		remoteSHA = strings.Fields(remote)[0]
	}
	if codeHead != 0 || remoteSHA == "" {
		d.add("branch", false, "", "could not reach origin — cannot compare with upstream; check network or remote credentials", true)
		return
	}
	if head == remoteSHA {
		d.add("branch", true, "on main, up to date with origin", "", false)
		return
	}
	direction := ""
	code3, localRef := d.git(ctx, "rev-parse", "origin/main")
	if code3 == 0 && localRef != "" {
		if localRef == head {
			direction = "behind"
		} else {
			c4, _ := d.git(ctx, "merge-base", "--is-ancestor", "HEAD", "origin/main")
			c5, _ := d.git(ctx, "merge-base", "--is-ancestor", "origin/main", "HEAD")
			switch {
			case c4 == 0 && c5 != 0:
				direction = "behind"
			case c5 == 0 && c4 != 0:
				direction = "ahead"
			case c4 != 0 && c5 != 0:
				direction = "diverged"
			}
		}
	}
	switch direction {
	case "behind":
		detail := "checkout is behind origin/main — run explorer update"
		if localRef == remoteSHA {
			if _, n := d.git(ctx, "rev-list", "--count", "HEAD..origin/main"); isDigits(n) && n != "0" {
				detail = "checkout is " + n + " commit(s) behind origin/main — run explorer update"
			}
		}
		d.add("branch", false, "", detail, true)
	case "ahead":
		count := ""
		if _, n := d.git(ctx, "rev-list", "--count", "origin/main..HEAD"); isDigits(n) && n != "0" {
			count = n + " "
		}
		d.add("branch", false, "", "checkout has "+count+"local commit(s) not on origin/main — investigate before update", true)
	case "diverged":
		d.add("branch", false, "", "checkout and origin/main have diverged — investigate before update", true)
	default:
		d.add("branch", false, "", "checkout differs from origin/main and local ancestry is undeterminable — investigate before update", true)
	}
}

// runDoctorCLI prints the report and returns 1 when any check failed (or,
// with --strict, warned).
func runDoctorCLI(ctx context.Context, u *ui, r Runner, p Paths, args []string) int {
	asJSON, strict := false, false
	for _, a := range args {
		switch a {
		case "--json":
			asJSON = true
		case "--strict":
			strict = true
		case "--check":
			// Read-only is the only mode; accepted for the shared convention.
		case "-h", "--help":
			fmt.Fprintln(u.out, "usage: explorer doctor [--json] [--strict] [--check]\nRead-only diagnostics; exits 1 when a check fails (or warns, with --strict).")
			return 0
		default:
			fmt.Fprintln(u.errw, "error: unknown doctor flag: "+a)
			return 2
		}
	}
	checks := newDoctor(p, r).Diagnose(ctx)
	failed := false
	for _, c := range checks {
		if c.Status == "fail" || (strict && c.Status == "warn") {
			failed = true
		}
	}
	if asJSON {
		out, _ := json.MarshalIndent(struct {
			OK     bool    `json:"ok"`
			Checks []Check `json:"checks"`
		}{!failed, checks}, "", "  ")
		fmt.Fprintln(u.out, string(out))
	} else {
		colors := map[string]string{"ok": "\033[0;32m", "warn": "\033[0;33m", "fail": "\033[0;31m"}
		for _, c := range checks {
			fmt.Fprintf(u.out, "%s %s: %s\n", u.paint(colors[c.Status], fmt.Sprintf("%-4s", strings.ToUpper(c.Status))), c.Name, c.Detail)
		}
		fmt.Fprintln(u.out, "\nHost packages: sudo dnf upgrade --refresh. Doctor changes nothing.")
	}
	if failed {
		return 1
	}
	return 0
}
