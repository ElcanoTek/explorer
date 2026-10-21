// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package ops

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Host conventions every Elcano bootstrap applies (production-support's
// README, "Host conventions"). Bootstrap only: update never renames a box,
// touches sshd or removes packages. Each step honours DRY_RUN=1, never
// fails the install, and takes test-only path overrides.

type hostEnv struct {
	u      *ui
	r      Runner
	dryRun bool
	// Test-only roots, as the shell helpers had.
	sshRoot   string // SSH_KEY_ONLY_ROOT
	hostsFile string // EXPLORER_HOSTS_FILE
	cloudDir  string // EXPLORER_CLOUD_DIR
}

func hostEnvFromEnv(u *ui, r Runner) hostEnv {
	return hostEnv{
		u: u, r: r,
		dryRun:    os.Getenv("DRY_RUN") == "1",
		sshRoot:   os.Getenv("SSH_KEY_ONLY_ROOT"),
		hostsFile: envOr("/etc/hosts", "EXPLORER_HOSTS_FILE"),
		cloudDir:  envOr("/etc/cloud", "EXPLORER_CLOUD_DIR"),
	}
}

// removeCockpit uninstalls Cockpit: the Vultr Fedora image ships its
// root-capable web login on :9090, and these boxes are administered over
// ssh only. EXPLORER_KEEP_COCKPIT=1 keeps it.
func (h hostEnv) removeCockpit(ctx context.Context) {
	if os.Getenv("EXPLORER_KEEP_COCKPIT") == "1" {
		h.u.infof("EXPLORER_KEEP_COCKPIT=1 — leaving Cockpit installed")
		return
	}
	if _, ok := h.r.LookPath("rpm"); !ok {
		return
	}
	if h.r.Run(ctx, Cmd{Name: "rpm", Args: []string{"-q", "cockpit-ws"}, Timeout: time.Minute}).Code != 0 {
		return
	}
	if h.dryRun {
		h.u.infof("[dry-run] dnf -y remove 'cockpit*'")
		return
	}
	if h.r.Run(ctx, Cmd{Name: "dnf", Args: []string{"-y", "remove", "cockpit*"}, Timeout: 10 * time.Minute}).Code == 0 {
		h.u.okf("removed Cockpit — no web console on :9090")
	} else {
		h.u.warnf("could not remove Cockpit — run: dnf -y remove 'cockpit*'")
	}
}

// sshKeyOnlyConf is the drop-in production-support's Vultr startup script
// also writes. It sorts before cloud-init's 50-cloud-init.conf, and sshd
// keeps the first value it reads.
const sshKeyOnlyConf = `# Key-only SSH: no passwords, root by key only. Sorts before cloud-init's
# 50-cloud-init.conf so it wins (sshd keeps the first value it reads).
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
`

var reAuthorizedKey = regexp.MustCompile(`^[ \t\f\v\r]*(ssh-|ecdsa-|sk-)[^ \t\f\v\r]+[ \t\f\v\r]+AAAA[A-Za-z0-9+/]+=*([ \t\f\v\r]|$)`)

func (h hostEnv) sshdEffective(ctx context.Context) string {
	return h.r.Run(ctx, Cmd{Name: "sshd", Args: []string{"-T"}, Timeout: 30 * time.Second}).Stdout
}

// countAuthorizedKeys counts the public keys sshd would accept for root and
// /home/* users, honouring the effective AuthorizedKeysFile. It is the
// lockout guard: no key, no key-only switch.
func (h hostEnv) countAuthorizedKeys(ctx context.Context) int {
	eff := h.sshdEffective(ctx)
	var files []string
	for _, line := range strings.Split(eff, "\n") {
		l := strings.TrimRight(line, "\r")
		if strings.EqualFold(l, "pubkeyauthentication no") {
			return 0
		}
		if fields := strings.Fields(l); len(fields) > 1 && strings.EqualFold(fields[0], "authorizedkeysfile") && files == nil {
			files = fields[1:]
		}
	}
	if len(files) == 0 {
		files = []string{".ssh/authorized_keys", ".ssh/authorized_keys2"}
	}
	homes := []string{filepath.Join(h.sshRoot, "/root")}
	if more, err := filepath.Glob(filepath.Join(h.sshRoot, "/home/*")); err == nil {
		homes = append(homes, more...)
	}
	count := 0
	for _, home := range homes {
		if fi, err := os.Stat(home); err != nil || !fi.IsDir() {
			continue
		}
		rel := strings.TrimPrefix(home, h.sshRoot)
		for _, f := range files {
			if f == "none" {
				continue
			}
			path := strings.ReplaceAll(f, "%h", rel)
			path = strings.ReplaceAll(path, "%u", filepath.Base(rel))
			if !strings.HasPrefix(path, "/") {
				path = rel + "/" + path
			}
			fh, err := os.Open(h.sshRoot + path) //nolint:gosec // G304: a path the installer chose, not request input.
			if err != nil {
				continue
			}
			sc := bufio.NewScanner(fh)
			for sc.Scan() {
				if reAuthorizedKey.MatchString(sc.Text()) {
					count++
				}
			}
			_ = fh.Close()
		}
	}
	return count
}

// sshKeyOnly installs the key-only drop-in, validates it with `sshd -t`
// (reverting on failure) and reloads sshd. EXPLORER_KEEP_SSH_PASSWORDS=1
// skips it; with no authorized key installed it refuses, so nobody is
// locked out.
func (h hostEnv) sshKeyOnly(ctx context.Context) {
	if os.Getenv("EXPLORER_KEEP_SSH_PASSWORDS") == "1" {
		h.u.infof("EXPLORER_KEEP_SSH_PASSWORDS=1 — leaving sshd's password settings alone")
		return
	}
	dir := filepath.Join(h.sshRoot, "/etc/ssh/sshd_config.d")
	conf := filepath.Join(dir, "01-no-password-login.conf")
	if _, ok := h.r.LookPath("sshd"); !ok {
		return
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return
	}
	if fileEquals(conf, []byte(sshKeyOnlyConf)) {
		h.checkSSHEffective(ctx)
		return
	}
	if h.countAuthorizedKeys(ctx) < 1 {
		h.u.warnf("no SSH authorized keys found — leaving password login on so nobody is locked out; add a key, then re-run bootstrap")
		return
	}
	if h.dryRun {
		h.u.infof("[dry-run] would write %s (key-only SSH), check it with sshd -t and reload sshd", conf)
		return
	}
	old, hadOld := []byte(nil), false
	if raw, err := os.ReadFile(conf); err == nil { //nolint:gosec // G304: a path the installer chose, not request input.
		old, hadOld = raw, true
	}
	// Written in place, not renamed from elsewhere, so the file keeps the
	// SELinux label of /etc/ssh.
	if err := os.WriteFile(conf, []byte(sshKeyOnlyConf), 0o600); err != nil {
		h.u.warnf("could not write %s — SSH still accepts passwords", conf)
		return
	}
	_ = os.Chmod(conf, 0o600)
	if h.r.Run(ctx, Cmd{Name: "sshd", Args: []string{"-t"}, Timeout: 30 * time.Second}).Code != 0 {
		if hadOld {
			_ = os.WriteFile(conf, old, 0o600) //nolint:gosec // G703: a path the installer chose, not request input.
		} else {
			_ = os.Remove(conf)
		}
		h.u.warnf("sshd -t rejected the key-only drop-in — reverted %s; sshd left as it was", conf)
		return
	}
	if h.r.Run(ctx, Cmd{Name: "systemctl", Args: []string{"reload", "sshd"}, Timeout: time.Minute}).Code == 0 ||
		h.r.Run(ctx, Cmd{Name: "systemctl", Args: []string{"reload", "ssh"}, Timeout: time.Minute}).Code == 0 {
		h.u.okf("SSH is key-only: passwords off, root by key (%s)", conf)
	} else {
		h.u.warnf("wrote %s but could not reload sshd — run: systemctl reload sshd", conf)
	}
	h.checkSSHEffective(ctx)
}

// checkSSHEffective warns when an earlier directive still lets passwords in.
// Read-only; never edits sshd_config.
func (h hostEnv) checkSSHEffective(ctx context.Context) {
	if sshdAcceptsPasswords(h.sshdEffective(ctx)) {
		h.u.warnf("sshd still accepts passwords: an earlier directive wins (e.g. 'PermitRootLogin yes' above the Include line in /etc/ssh/sshd_config) — fix it by hand")
	}
}

func sshdAcceptsPasswords(effective string) bool {
	for _, line := range strings.Split(strings.ToLower(effective), "\n") {
		switch strings.TrimSpace(line) {
		case "passwordauthentication yes", "permitrootlogin yes":
			return true
		}
	}
	return false
}

// ── hostname ────────────────────────────────────────────────────────────

const preserveHostnameCfg = `# The hostname is set by hand; do not let cloud-init reset it from Vultr metadata.
preserve_hostname: true
manage_etc_hosts: false`

var reFQDN = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
var reDigitsDots = regexp.MustCompile(`^[0-9.]+$`)

// hostnameIsDefault is true only for an unset cloud-image default.
func hostnameIsDefault(name string) bool {
	switch name {
	case "vultr.guest", "localhost", "localhost.localdomain":
		return true
	}
	return false
}

// hostsRewrite returns the hosts file with, on each 127.0.0.1/::1 line, the
// old hostname token (and old's short form) replaced in place by
// "fqdn short", every other alias kept; then both loopback lines appended
// when no line names fqdn. An empty old replaces nothing.
func hostsRewrite(text, old, fqdn string) string {
	short, _, _ := strings.Cut(fqdn, ".")
	oldShort := ""
	if i := strings.Index(old, "."); i >= 0 {
		oldShort = old[:i]
	}
	isOld := func(t string) bool { return t == old || (oldShort != "" && t == oldShort) }
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if text == "" {
		lines = nil
	}
	var out []string
	seen := false
	for _, line := range lines {
		f := strings.Fields(line)
		names := func(n string) bool {
			for _, t := range f[1:] {
				if strings.HasPrefix(t, "#") {
					break
				}
				if t == n {
					return true
				}
			}
			return false
		}
		hasOld := false
		if len(f) > 0 {
			for _, t := range f[1:] {
				if strings.HasPrefix(t, "#") {
					break
				}
				if isOld(t) {
					hasOld = true
					break
				}
			}
		}
		if len(f) > 0 && (f[0] == "127.0.0.1" || f[0] == "::1") && old != "" && hasOld {
			rebuilt := f[0]
			placed, cmt := false, false
			for _, t := range f[1:] {
				if strings.HasPrefix(t, "#") {
					cmt = true
				}
				if !cmt && isOld(t) {
					if !placed {
						rebuilt += " " + fqdn
						if short != fqdn {
							rebuilt += " " + short
						}
						placed = true
					}
					continue
				}
				if !cmt && (t == fqdn || t == short) {
					continue
				}
				rebuilt += " " + t
			}
			out = append(out, rebuilt)
			seen = true
			continue
		}
		if len(f) > 0 && !strings.HasPrefix(f[0], "#") && names(fqdn) {
			seen = true
		}
		out = append(out, line)
	}
	if !seen {
		out = append(out, "127.0.0.1 "+fqdn+" "+short, "::1 "+fqdn+" "+short)
	}
	return strings.Join(out, "\n") + "\n"
}

// setHostname names a new box after its public FQDN, but only when the
// current name is an unset cloud default. EXPLORER_SET_HOSTNAME=1 forces,
// =0 skips.
func (h hostEnv) setHostname(ctx context.Context, target string) {
	fqdn := strings.ToLower(target)
	setting := os.Getenv("EXPLORER_SET_HOSTNAME")
	if setting == "0" {
		h.u.infof("EXPLORER_SET_HOSTNAME=0 — leaving the hostname alone")
		return
	}
	if _, ok := h.r.LookPath("hostnamectl"); !ok {
		return
	}
	if !reFQDN.MatchString(fqdn) || reDigitsDots.MatchString(fqdn) {
		h.u.infof("hostname: '%s' is not a dotted FQDN — leaving the hostname alone", target)
		return
	}
	current := strings.TrimSpace(h.r.Run(ctx, Cmd{Name: "hostnamectl", Args: []string{"--static"}, Timeout: 30 * time.Second}).Stdout)
	old := ""
	label := current
	if label == "" {
		label = "<unset>"
	}
	switch {
	case current == fqdn:
		h.u.okf("hostname already %s", fqdn)
	case setting != "1" && !hostnameIsDefault(current):
		h.u.infof("hostname is %s, not %s — left as is; to rename: hostnamectl set-hostname %s (or EXPLORER_SET_HOSTNAME=1)", label, fqdn, fqdn)
		return
	case h.dryRun:
		h.u.infof("[dry-run] hostnamectl set-hostname %s", fqdn)
		if current != "localhost" && current != "localhost.localdomain" {
			old = current
		}
	case h.r.Run(ctx, Cmd{Name: "hostnamectl", Args: []string{"set-hostname", fqdn}, Timeout: time.Minute}).Code == 0:
		if current != "localhost" && current != "localhost.localdomain" {
			old = current
		}
		h.u.okf("hostname %s → %s", label, fqdn)
	default:
		h.u.warnf("could not set the hostname — run: hostnamectl set-hostname %s", fqdn)
		return
	}

	if fi, err := os.Stat(h.cloudDir); err == nil && fi.IsDir() {
		cfg := filepath.Join(h.cloudDir, "cloud.cfg.d", "99-preserve-hostname.cfg")
		raw, _ := os.ReadFile(cfg) //nolint:gosec // G304: a path the installer chose, not request input.
		if strings.TrimRight(string(raw), "\n") != preserveHostnameCfg {
			switch {
			case h.dryRun:
				h.u.infof("[dry-run] would write %s (preserve_hostname: true, manage_etc_hosts: false)", cfg)
			case os.MkdirAll(filepath.Dir(cfg), 0o755) == nil && os.WriteFile(cfg, []byte(preserveHostnameCfg+"\n"), 0o644) == nil: //nolint:gosec // G301: a public, root-owned directory by design.
				h.u.okf("cloud-init keeps the hostname (%s)", cfg)
			default:
				h.u.warnf("could not write %s — cloud-init may reset the hostname on reboot", cfg)
			}
		}
	}

	raw, err := os.ReadFile(h.hostsFile)
	if err != nil {
		return
	}
	short, _, _ := strings.Cut(fqdn, ".")
	rewritten := hostsRewrite(string(raw), old, fqdn)
	if strings.TrimRight(rewritten, "\n") == strings.TrimRight(string(raw), "\n") {
		return
	}
	switch {
	case h.dryRun:
		h.u.infof("[dry-run] would point %s's loopback lines at %s", h.hostsFile, fqdn)
	case os.WriteFile(h.hostsFile, []byte(rewritten), 0o644) == nil: //nolint:gosec // G306: a world-readable system file by design.
		h.u.okf("%s names %s on 127.0.0.1 and ::1", h.hostsFile, fqdn)
	default:
		h.u.warnf("could not update %s — add: 127.0.0.1 %s %s", h.hostsFile, fqdn, short)
	}
}
