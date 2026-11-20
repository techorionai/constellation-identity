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

// runSetupLink deletes the unused setup tokens, makes a new one, and prints the
// link to standard output. It does not write the link to the log. It exits with
// code 1 if an active admin exists.
func runSetupLink(stdout, stderr io.Writer) int {
	cfg, err := config.Load()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "config error: %v\n", err)
		return 1
	}
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	link, err := services.SetupLink(ctx, cfg, log)
	if errors.Is(err, commands.ErrAdminExists) {
		_, _ = fmt.Fprintln(stderr, "An active admin exists. The setup link is only for a new install.")
		return 1
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "setup link failed: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, link)
	return 0
}
