// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package ops

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"
)

var reSecretLine = regexp.MustCompile(`TOKEN|KEY|SECRET|PASSWORD`)
var reCommentLine = regexp.MustCompile(`^[ \t\n\v\f\r]*#`)

// redactEnv prints a dotenv file for an operator: comments and lines with
// no '=' are dropped, and any line naming a token, key, secret or password
// shows only its name.
func redactEnv(text string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		if reCommentLine.MatchString(line) {
			continue
		}
		name, _, hasEq := strings.Cut(line, "=")
		switch {
		case reSecretLine.MatchString(line):
			b.WriteString(name + "=[REDACTED]\n")
		case hasEq:
			b.WriteString(line + "\n")
		}
	}
	return b.String()
}

const envHelp = `explorer env              print /opt/explorer/.env (secrets redacted)
explorer env edit         edit /opt/explorer/.env
`

func runEnv(ctx context.Context, u *ui, r Runner, p Paths, args []string) int {
	sub := "show"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "show", "print", "":
		if code, done := elevate("env", args); done {
			return code
		}
		text, ok, err := readEnvForRewrite(p.EnvFile())
		if err != nil {
			u.fail(err.Error())
			return 1
		}
		if !ok {
			u.fail(p.EnvFile() + " missing — run bootstrap.sh")
			return 1
		}
		fmt.Fprint(u.out, redactEnv(text))
		return 0
	case "edit":
		if code, done := elevate("env", args); done {
			return code
		}
		present, err := requireSingleRegular(p.EnvFile())
		if err != nil {
			u.fail(err.Error())
			return 1
		}
		if !present {
			acct, err := lookupAccount(p.AppUser)
			if err != nil {
				u.fail(err.Error())
				return 1
			}
			if err := writeFileAtomic(p.EnvFile(), nil, 0o600, acct.uid, acct.gid); err != nil {
				u.fail(err.Error())
				return 1
			}
		}
		editor := envOr("vi", "EDITOR", "VISUAL")
		fields := strings.Fields(editor)
		if len(fields) == 0 {
			fields = []string{"vi"}
		}
		code := r.Interactive(ctx, Cmd{Name: fields[0], Args: append(fields[1:], p.EnvFile())})
		if code == 0 {
			u.infof("apply the change with: explorer restart")
		}
		return code
	default:
		fmt.Fprint(u.out, envHelp)
		if sub == "help" || sub == "--help" || sub == "-h" {
			return 0
		}
		return 2
	}
}

const tlsHelp = `explorer tls status     show hostname + certificate validity + Caddy state
explorer tls reload     reload /etc/caddy/Caddyfile without dropping connections
explorer tls restart    restart the Caddy service
`

// certInfo dials host:443 with normal verification and returns the served
// leaf plus the verification error, if any. A certificate that does not
// verify is still returned (Go hands back the served chain in
// tls.CertificateVerificationError), so status can show what is wrong
// without ever turning verification off.
func certInfo(ctx context.Context, host string) (*x509.Certificate, error, error) {
	return certInfoAt(ctx, host, net.JoinHostPort(host, "443"))
}

func certInfoAt(ctx context.Context, host, addr string) (*x509.Certificate, error, error) {
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		var verr *tls.CertificateVerificationError
		if errors.As(err, &verr) && len(verr.UnverifiedCertificates) > 0 {
			return verr.UnverifiedCertificates[0], verr.Err, nil
		}
		return nil, nil, err
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, nil, fmt.Errorf("%s served no certificate", host)
	}
	return state.PeerCertificates[0], nil, nil
}

func runTLS(ctx context.Context, u *ui, r Runner, p Paths, args []string) int {
	sub := "status"
	if len(args) > 0 {
		sub = args[0]
	}
	if _, ok := r.LookPath("caddy"); !ok && sub != "help" {
		u.fail("Caddy not installed — re-run bootstrap with a hostname to set up TLS")
		return 1
	}
	switch sub {
	case "status":
		snippet, host := caddySiteHost(p.Caddyfile)
		if snippet == "" {
			u.sayf("No marker-owned Explorer Caddy site block found")
		} else {
			u.sayf("Host: %s", host)
			u.sayf("Site: %s", snippet)
			leaf, verr, err := certInfo(ctx, host)
			if err != nil {
				u.sayf("(could not reach %s:443 — check DNS + firewall: %v)", host, err)
			} else {
				printCert(u.out, leaf, verr)
			}
		}
		res := r.Run(ctx, Cmd{Name: "systemctl", Args: []string{"is-active", "caddy.service"}, Timeout: 30 * time.Second})
		u.sayf("caddy.service: %s", strings.TrimSpace(res.Stdout+res.Stderr))
		return 0
	case "reload":
		if code, done := elevate("tls", args); done {
			return code
		}
		return r.Interactive(ctx, Cmd{Name: "caddy", Args: []string{"reload", "--config", p.Caddyfile}})
	case "restart":
		if code, done := elevate("tls", args); done {
			return code
		}
		return r.Interactive(ctx, Cmd{Name: "systemctl", Args: []string{"restart", "caddy.service"}})
	default:
		fmt.Fprint(u.out, tlsHelp)
		if sub == "help" || sub == "--help" || sub == "-h" {
			return 0
		}
		return 2
	}
}

func printCert(w io.Writer, leaf *x509.Certificate, verr error) {
	fmt.Fprintf(w, "subject=%s\n", leaf.Subject.String())
	fmt.Fprintf(w, "issuer=%s\n", leaf.Issuer.String())
	fmt.Fprintf(w, "notBefore=%s\n", leaf.NotBefore.UTC().Format(time.RFC1123))
	fmt.Fprintf(w, "notAfter=%s\n", leaf.NotAfter.UTC().Format(time.RFC1123))
	if verr != nil {
		fmt.Fprintf(w, "verification: FAILED (%v)\n", verr)
	} else {
		fmt.Fprintf(w, "verification: ok (%d days left)\n", int(time.Until(leaf.NotAfter).Hours()/24))
	}
}
