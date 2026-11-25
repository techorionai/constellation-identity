package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os/signal"
	"syscall"

	"github.com/techorionai/constellation-identity/internal/config"
	"github.com/techorionai/constellation-identity/internal/services"
)

const unlockLoginUsage = "usage: identity unlock-login <email>"

// runUnlockLogin removes the login lock of one email. It connects to Valkey
// only. It prints "unlocked" or "not locked". It does not change the counters
// of the IPs.
func runUnlockLogin(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		_, _ = fmt.Fprintln(stderr, unlockLoginUsage)
		return 2
	}
	cfg, err := config.Load()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "config error: %v\n", err)
		return 1
	}
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	unlocked, err := services.UnlockLogin(ctx, cfg, args[0], log)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "unlock login failed: %v\n", err)
		return 1
	}
	if unlocked {
		_, _ = fmt.Fprintln(stdout, "unlocked")
	} else {
		_, _ = fmt.Fprintln(stdout, "not locked")
	}
	return 0
}
