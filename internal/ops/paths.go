// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package ops

import (
	"os"
	"path/filepath"
	"strconv"
)

// Paths is every location the operator tooling touches. Each is overridable
// through the environment, as the shell tooling's were, which is also how
// the lifecycle tests point it at a scratch tree.
type Paths struct {
	SrcDir         string // EXPLORER_SRC_DIR / SRC_DIR: root-owned git checkout
	AppDir         string // EXPLORER_APP_DIR / APP_DIR: installed binary + dotenv files
	AppUser        string // APP_USER: the service account
	StateDir       string // EXPLORER_STATE_DIR: access database directory
	BuildCache     string // EXPLORER_BUILD_CACHE: root-owned Go caches
	SystemdDir     string // EXPLORER_SYSTEMD_DIR
	TmpfilesDir    string // EXPLORER_TMPFILES_DIR
	CLITarget      string // EXPLORER_CLI_TARGET
	MotdTarget     string // EXPLORER_MOTD_TARGET
	LockFile       string // EXPLORER_UPDATE_LOCK
	HealthURL      string // EXPLORER_HEALTH_URL
	HealthAttempts int    // EXPLORER_HEALTH_ATTEMPTS
	Service        string // EXPLORER_SERVICE
	Caddyfile      string // EXPLORER_CADDYFILE
}

func envOr(def string, names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return def
}

// PathsFromEnv resolves Paths from the environment and the defaults.
func PathsFromEnv() Paths {
	attempts, err := strconv.Atoi(envOr("10", "EXPLORER_HEALTH_ATTEMPTS"))
	if err != nil || attempts < 1 {
		attempts = 10
	}
	return Paths{
		SrcDir:         envOr("/opt/explorer-src", "EXPLORER_SRC_DIR", "SRC_DIR"),
		AppDir:         envOr("/opt/explorer", "EXPLORER_APP_DIR", "APP_DIR"),
		AppUser:        envOr("explorer", "APP_USER"),
		StateDir:       envOr("/var/lib/explorer", "EXPLORER_STATE_DIR"),
		BuildCache:     envOr("/var/cache/explorer-build", "EXPLORER_BUILD_CACHE"),
		SystemdDir:     envOr("/etc/systemd/system", "EXPLORER_SYSTEMD_DIR"),
		TmpfilesDir:    envOr("/etc/tmpfiles.d", "EXPLORER_TMPFILES_DIR"),
		CLITarget:      envOr("/usr/local/bin/explorer", "EXPLORER_CLI_TARGET"),
		MotdTarget:     envOr("/etc/motd", "EXPLORER_MOTD_TARGET"),
		LockFile:       envOr("/run/lock/explorer-update.lock", "EXPLORER_UPDATE_LOCK"),
		HealthURL:      envOr("http://127.0.0.1:8080/health", "EXPLORER_HEALTH_URL"),
		HealthAttempts: attempts,
		Service:        envOr("explorer.service", "EXPLORER_SERVICE"),
		Caddyfile:      envOr("/etc/caddy/Caddyfile", "EXPLORER_CADDYFILE"),
	}
}

// Env renders p as environment assignments, for handing the same layout to
// the staged binary.
func (p Paths) Env() []string {
	return []string{
		"EXPLORER_SRC_DIR=" + p.SrcDir,
		"EXPLORER_APP_DIR=" + p.AppDir,
		"APP_USER=" + p.AppUser,
		"EXPLORER_STATE_DIR=" + p.StateDir,
		"EXPLORER_BUILD_CACHE=" + p.BuildCache,
		"EXPLORER_SYSTEMD_DIR=" + p.SystemdDir,
		"EXPLORER_TMPFILES_DIR=" + p.TmpfilesDir,
		"EXPLORER_CLI_TARGET=" + p.CLITarget,
		"EXPLORER_MOTD_TARGET=" + p.MotdTarget,
		"EXPLORER_UPDATE_LOCK=" + p.LockFile,
		"EXPLORER_HEALTH_URL=" + p.HealthURL,
		"EXPLORER_HEALTH_ATTEMPTS=" + strconv.Itoa(p.HealthAttempts),
		"EXPLORER_SERVICE=" + p.Service,
		"EXPLORER_CADDYFILE=" + p.Caddyfile,
	}
}

// BinPath is the installed service binary.
func (p Paths) BinPath() string { return filepath.Join(p.AppDir, "bin", "explorer") }

// RevisionFile records the commit the installed binary was built from.
func (p Paths) RevisionFile() string { return filepath.Join(p.AppDir, ".explorer-revision") }

// EnvFile is the per-host dotenv file.
func (p Paths) EnvFile() string { return filepath.Join(p.AppDir, ".env") }

// SharedEnvFile is the fleet-wide dotenv file.
func (p Paths) SharedEnvFile() string { return filepath.Join(p.AppDir, ".env.shared") }

// UnitPath is the installed service unit.
func (p Paths) UnitPath() string { return filepath.Join(p.SystemdDir, p.Service) }

// TmpfilesPath is the installed tmpfiles rule.
func (p Paths) TmpfilesPath() string { return filepath.Join(p.TmpfilesDir, "explorer.conf") }

// Legacy units of the Python era, removed by update.
func (p Paths) legacyUnits() []string {
	return []string{
		filepath.Join(p.SystemdDir, "explorer-attachment-cleanup.timer"),
		filepath.Join(p.SystemdDir, "explorer-attachment-cleanup.service"),
	}
}
