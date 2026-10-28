// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

// Command explorer is the whole of Explorer: `explorer serve` runs the web
// service, and every other verb is the operator CLI installed at
// /usr/local/bin/explorer (doctor, update, access, env, tls, ...).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ElcanoTek/explorer/internal/config"
	"github.com/ElcanoTek/explorer/internal/ops"
	"github.com/ElcanoTek/explorer/internal/version"
	"github.com/ElcanoTek/explorer/internal/web"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(argv []string) int {
	if len(argv) == 0 {
		fmt.Print(ops.Usage)
		return 0
	}
	switch argv[0] {
	case "serve":
		if len(argv) > 1 {
			if argv[1] == "-h" || argv[1] == "--help" {
				fmt.Println("usage: explorer serve   (configuration comes from the environment and .env files)")
				return 0
			}
			fmt.Fprintf(os.Stderr, "explorer serve takes no arguments (got %q)\n", argv[1:])
			return 2
		}
		return serve()
	case "version", "--version", "-v":
		fmt.Println("explorer " + version.Revision())
		return 0
	case "access":
		return accessCommand(argv[1:])
	case "token":
		return tokenCommand(argv[1:])
	default:
		return ops.Run(argv)
	}
}

func serve() int {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	settings, env, err := config.Load(config.AppDir())
	if err != nil {
		slog.Error("configuration", "err", err)
		return 1
	}
	// Export the layered dotenv values, as the Python service's load_dotenv
	// did, so the AWS SDK's own settings (AWS_PROFILE, AWS_ENDPOINT_URL_S3,
	// AWS_CA_BUNDLE, ...) work from .env too.
	for k, v := range env {
		if os.Getenv(k) != v {
			_ = os.Setenv(k, v)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv, err := web.New(ctx, settings, web.Options{})
	if err != nil {
		slog.Error("startup refused", "err", err)
		return 1
	}
	defer func() { _ = srv.Close() }()

	httpServer := &http.Server{
		Addr:              settings.ListenAddr,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	errc := make(chan error, 1)
	go func() {
		slog.Info("explorer listening", "addr", settings.ListenAddr, "auth_mode", settings.AuthMode,
			"revision", version.Short())
		errc <- httpServer.ListenAndServe()
	}()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			slog.Error("listen", "err", err)
			return 1
		}
	case <-ctx.Done():
		slog.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("shutdown", "err", err)
			return 1
		}
	}
	return 0
}
