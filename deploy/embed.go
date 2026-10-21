// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

// Package deploy carries the files the installer puts outside the
// application directory: the systemd unit, the tmpfiles rule, the Caddy site
// template and the login banner. They are compiled into the binary, so an
// install or update writes exactly the copies the verified source tree
// built, and doctor compares the live files against the same bytes.
package deploy

import _ "embed"

var (
	//go:embed systemd/explorer.service
	ServiceUnit []byte
	//go:embed systemd/explorer.tmpfiles.conf
	TmpfilesConf []byte
	//go:embed explorer.caddy
	CaddySite []byte
	//go:embed motd
	Motd []byte
)
