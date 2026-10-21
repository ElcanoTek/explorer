// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package ops

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Bundles are `openssl enc -aes-256-cbc -pbkdf2 -iter 600000` output:
// "Salted__" + 8-byte salt + AES-256-CBC ciphertext, key and IV derived
// with PBKDF2-HMAC-SHA256 (OpenSSL's default digest since 1.1.0).
const (
	bundleIterations = 600000
	opensslMagic     = "Salted__"
)

var errDecrypt = errors.New("decryption failed — wrong passphrase?")

// decryptBundle decrypts an OpenSSL `enc -pbkdf2` file natively, so a box
// needs no openssl binary.
func decryptBundle(data []byte, passphrase string) ([]byte, error) {
	if len(data) < 16+aes.BlockSize || string(data[:8]) != opensslMagic {
		return nil, errors.New("not an OpenSSL salted bundle")
	}
	salt, body := data[8:16], data[16:]
	if len(body)%aes.BlockSize != 0 {
		return nil, errDecrypt
	}
	keyIV, err := pbkdf2.Key(sha256.New, passphrase, salt, bundleIterations, 48)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(keyIV[:32])
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(body))
	cipher.NewCBCDecrypter(block, keyIV[32:]).CryptBlocks(out, body)
	pad := int(out[len(out)-1])
	if pad < 1 || pad > aes.BlockSize || pad > len(out) {
		return nil, errDecrypt
	}
	for _, b := range out[len(out)-pad:] {
		if int(b) != pad {
			return nil, errDecrypt
		}
	}
	return out[:len(out)-pad], nil
}

// passphraseLine is what `openssl -pass stdin` reads: the first line.
func passphraseLine(s string) string {
	s = strings.TrimRight(s, "\n")
	line, _, _ := strings.Cut(s, "\n")
	return line
}

type provisionOpts struct {
	client         string
	restart        bool
	nonInteractive bool
}

func parseProvisionArgs(args []string) (provisionOpts, error) {
	o := provisionOpts{client: os.Getenv("EXPLORER_PROVISION_CLIENT"), restart: true}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case strings.HasPrefix(a, "--client="):
			o.client = strings.TrimPrefix(a, "--client=")
		case a == "--client":
			if i+1 >= len(args) {
				return o, usageError{"--client needs a value"}
			}
			i++
			o.client = args[i]
		case a == "--no-restart":
			o.restart = false
		case a == "--restart":
			o.restart = true
		case a == "--non-interactive":
			o.nonInteractive = true
		case a == "-h" || a == "--help":
			return o, usageError{"usage: explorer provision [--client=NAME] [--no-restart] [--non-interactive]\n" +
				"Decrypts provision/clients/<NAME>.env.enc from the source checkout and merges it into .env " +
				"inside a marked block. Passphrase: EXPLORER_PROVISION_PASSPHRASE, else /etc/elcano/passphrase " +
				"(ELCANO_PASSPHRASE_FILE), else a prompt."}
		default:
			return o, usageError{"unknown flag: " + a}
		}
	}
	return o, nil
}

var reClientName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func listBundles(dir string) []string {
	matches, _ := filepath.Glob(filepath.Join(dir, "*.env.enc"))
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, strings.TrimSuffix(filepath.Base(m), ".env.enc"))
	}
	sort.Strings(out)
	return out
}

func runProvision(ctx context.Context, u *ui, r Runner, p Paths, args []string) error {
	o, err := parseProvisionArgs(args)
	if err != nil {
		return err
	}
	return provision(ctx, u, r, p, o, newPrompter(u, o.nonInteractive))
}

// provision merges a decrypted bundle into .env inside a block it owns.
// Lines outside the block (the bootstrap-managed session secret, operator
// overrides) are never touched.
func provision(ctx context.Context, u *ui, r Runner, p Paths, o provisionOpts, pr *prompter) error {
	if os.Geteuid() != 0 {
		return errors.New("run as root: sudo explorer provision")
	}
	clientsDir := filepath.Join(p.SrcDir, "provision", "clients")
	if fi, err := os.Stat(clientsDir); err != nil || !fi.IsDir() {
		return fmt.Errorf("no %s — is %s a checkout?", clientsDir, p.SrcDir)
	}
	// The env file is service-owned data that root rewrites; require the
	// hardened layout so a compromised service cannot redirect the write.
	fi, err := os.Lstat(p.AppDir)
	if err != nil || !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s must be a real directory", p.AppDir)
	}
	if st := statT(fi); st.Uid != trustedUID || st.Gid != trustedUID || fi.Mode().Perm() != 0o755 {
		return fmt.Errorf("%s must be root:root 0755; run 'explorer rebuild' to migrate the install first", p.AppDir)
	}
	if _, err := requireSingleRegular(p.EnvFile()); err != nil {
		return err
	}
	available := listBundles(clientsDir)
	if len(available) == 0 {
		return fmt.Errorf("no encrypted client files in %s (looked for *.env.enc)", clientsDir)
	}
	client, err := chooseClient(u, o, pr, available)
	if err != nil {
		return err
	}
	encFile := filepath.Join(clientsDir, client+".env.enc")
	data, err := os.ReadFile(encFile) //nolint:gosec // G304: a path the installer chose, not request input.
	if err != nil {
		return fmt.Errorf("no encrypted bundle for client '%s' at %s", client, encFile)
	}

	pass, source, err := readPassphrase(u, o, pr, client)
	if err != nil {
		return err
	}

	u.stepf("Decrypting %s.env.enc (passphrase from %s)", client, source)
	plain, err := decryptBundle(data, passphraseLine(pass))
	if err != nil {
		return err
	}
	u.okf("decrypted %d line(s)", bytes.Count(plain, []byte("\n")))

	u.stepf("Merging into %s", p.EnvFile())
	current, _, err := readEnvForRewrite(p.EnvFile())
	if err != nil {
		return err
	}
	merged, provisioned, collisions := mergeProvisionBlock(current, string(plain), client)
	uid, gid := -1, -1
	if acct, err := lookupAccount(p.AppUser); err == nil {
		uid, gid = acct.uid, acct.gid
	}
	if err := writeFileAtomic(p.EnvFile(), []byte(merged), 0o600, uid, gid); err != nil {
		return err
	}
	u.okf("merged: %d key(s) provisioned", provisioned)
	if len(collisions) > 0 {
		u.warnf("%d bundle key(s) also set outside the managed block:", len(collisions))
		for _, k := range collisions {
			u.warnf("    • %s", k)
		}
	}

	if o.restart {
		if r.Run(ctx, Cmd{Name: "systemctl", Args: []string{"list-unit-files", p.Service}, Timeout: 30 * time.Second}).Code == 0 {
			u.stepf("Restarting %s", p.Service)
			if r.Run(ctx, Cmd{Name: "systemctl", Args: []string{"restart", p.Service}, Timeout: 2 * time.Minute}).Code == 0 {
				u.okf("%s restarted", p.Service)
			} else {
				u.warnf("restart failed — check: journalctl -u %s -n 50", p.Service)
			}
		} else {
			u.infof("%s not installed yet — skipping restart", p.Service)
		}
	} else {
		u.infof("skipping restart (--no-restart). Apply with: sudo systemctl restart %s", p.Service)
	}
	u.sayf("")
	u.okf("provision complete (client=%s)", client)
	return nil
}

// chooseClient picks the bundle: --client, the only one, or a prompt.
func chooseClient(u *ui, o provisionOpts, pr *prompter, available []string) (string, error) {
	client := o.client
	if client == "" {
		if o.nonInteractive || pr.nonInteractive {
			if len(available) != 1 {
				return "", errors.New("non-interactive + multiple clients: pass --client=NAME")
			}
			client = available[0]
		} else {
			u.sayf("")
			u.sayf("%s", u.bold("Available clients:"))
			for _, c := range available {
				u.sayf("  • %s", c)
			}
			def := available[0]
			for _, c := range available {
				if c == "elcano" {
					def = c
				}
			}
			client, _ = pr.value("", "EXPLORER_PROVISION_CLIENT", "Which client?", def, false)
		}
	}
	if !reClientName.MatchString(client) {
		return "", fmt.Errorf("invalid client name: %q", client)
	}
	return client, nil
}

// readPassphrase takes EXPLORER_PROVISION_PASSPHRASE, else the passphrase
// file, else asks (and offers to save it, 0600).
func readPassphrase(u *ui, o provisionOpts, pr *prompter, client string) (pass, source string, err error) {
	passFile := envOr("/etc/elcano/passphrase", "ELCANO_PASSPHRASE_FILE")
	switch {
	case os.Getenv("EXPLORER_PROVISION_PASSPHRASE") != "":
		pass, source = os.Getenv("EXPLORER_PROVISION_PASSPHRASE"), "env"
	case exists(passFile):
		raw, err := os.ReadFile(passFile) //nolint:gosec // G304: a path the installer chose, not request input.
		if err != nil {
			return "", "", err
		}
		pass, source = string(raw), passFile
	case o.nonInteractive || pr.nonInteractive:
		return "", "", fmt.Errorf("non-interactive + no passphrase: set EXPLORER_PROVISION_PASSPHRASE or write one to %s", passFile)
	default:
		pass, err = pr.secret("", "passphrase", "Passphrase for "+client+".env.enc", true)
		if err != nil {
			return "", "", err
		}
		source = "prompt"
		if yes(pr.ask("Save passphrase to " + passFile + " for future runs? " + u.dim("(y/N)"))) {
			if err := os.MkdirAll(filepath.Dir(passFile), 0o700); err != nil {
				return "", "", err
			}
			if err := writeFileAtomic(passFile, []byte(pass), 0o600, -1, -1); err != nil {
				return "", "", err
			}
			u.okf("saved → %s (mode 0600)", passFile)
		}
	}

	return pass, source, nil
}

func readEnvForRewrite(path string) (string, bool, error) {
	if _, err := requireSingleRegular(path); err != nil {
		return "", false, err
	}
	raw, err := os.ReadFile(path) //nolint:gosec // G304: a path the installer chose, not request input.
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	return string(raw), err == nil, err
}

func provisionMarkers(client string) (string, string) {
	return "# ── managed by explorer provision (" + client + ") — do not edit, run `explorer provision` to refresh ──",
		"# ── end explorer provision (" + client + ") ──"
}

// mergeProvisionBlock replaces this client's block (dropping blank lines
// that only padded it) and appends the new one. It returns the new text, the
// number of keys new to the file, and the keys also set outside the block.
func mergeProvisionBlock(current, plain, client string) (string, int, []string) {
	begin, end := provisionMarkers(client)
	lines := strings.Split(strings.TrimSuffix(current, "\n"), "\n")
	if current == "" {
		lines = nil
	}
	var kept []string
	if strings.Contains(current, begin) {
		blank, skip := 0, false
		for _, l := range lines {
			switch {
			case l == begin:
				skip, blank = true, 0
				continue
			case skip && l == end:
				skip = false
				continue
			case skip:
				continue
			case l == "":
				blank++
				continue
			}
			for ; blank > 0; blank-- {
				kept = append(kept, "")
			}
			kept = append(kept, l)
		}
	} else {
		kept = lines
		for len(kept) > 0 && kept[len(kept)-1] == "" {
			kept = kept[:len(kept)-1]
		}
	}
	block := []string{begin}
	newCount := 0
	var collisions []string
	for _, line := range strings.Split(strings.ReplaceAll(plain, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || !strings.Contains(line, "=") {
			continue
		}
		key, _, _ := strings.Cut(line, "=")
		key = strings.Join(strings.Fields(key), "")
		if key == "" {
			continue
		}
		block = append(block, line)
		found := false
		for _, k := range kept {
			if strings.HasPrefix(strings.TrimLeft(k, " \t"), key+"=") {
				found = true
				break
			}
		}
		if found {
			collisions = append(collisions, key)
		} else {
			newCount++
		}
	}
	block = append(block, end)
	text := strings.Join(kept, "\n")
	if len(kept) > 0 {
		text += "\n"
	}
	text += "\n" + strings.Join(block, "\n") + "\n"
	return text, newCount, collisions
}
