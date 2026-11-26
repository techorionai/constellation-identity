package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/signal"
	"syscall"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	"github.com/techorionai/constellation-identity/internal/config"
	"github.com/techorionai/constellation-identity/internal/services"
)

const resetMFAUsage = "usage: identity reset-mfa <email>"

// runResetMFA removes the TOTP factor and the recovery codes of one user, and
// revokes the sessions of the user. It is the recovery path of the last admin
// who lost the TOTP device and the recovery codes. It prints "reset". It exits
// with 1 if the user does not exist or on an error, and with 2 for a usage error.
func runResetMFA(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		_, _ = fmt.Fprintln(stderr, resetMFAUsage)
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
	if err := services.ResetMFA(ctx, cfg, args[0], log); err != nil {
		if errors.Is(err, commands.ErrUserNotFound) {
			_, _ = fmt.Fprintln(stderr, "reset MFA failed: no user has this email")
			return 1
		}
		_, _ = fmt.Fprintf(stderr, "reset MFA failed: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "reset")
	return 0
}
