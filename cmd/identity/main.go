// Command identity runs the identity service.
//
// Usage:
//
//	identity                              Start the server.
//	identity healthcheck                  Exit 0 if /readyz of the admin port is 200.
//	identity rotate-signing-keys --force  Replace all signing keys.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/techorionai/constellation-platform-go/telemetry"

	"github.com/techorionai/constellation-identity/internal/config"
	"github.com/techorionai/constellation-identity/internal/services"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const shutdownTimeout = 30 * time.Second

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return serve(stderr)
	}
	switch args[0] {
	case "healthcheck":
		return runHealthcheck(stdout, stderr)
	case "rotate-signing-keys":
		return runRotate(args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		return 2
	}
}

func serve(stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "config error: %v\n", err)
		return 1
	}
	tel, err := telemetry.Setup(ctx, telemetry.Options{ServiceName: "identity", ServiceVersion: version, LogLevel: cfg.LogLevel})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "telemetry error: %v\n", err)
		return 1
	}
	defer func() { _ = tel.Shutdown(context.WithoutCancel(ctx)) }()

	app, err := services.Start(ctx, cfg)
	if err != nil {
		slog.ErrorContext(ctx, "the service cannot start", "error", err)
		return 1
	}
	slog.InfoContext(ctx, "the service is ready", "public_addr", app.PublicAddr(), "admin_addr", app.AdminAddr())

	<-ctx.Done()
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	if err := app.Shutdown(sctx); err != nil {
		slog.ErrorContext(ctx, "the service did not stop cleanly", "error", err)
		return 1
	}
	return 0
}

func runRotate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rotate-signing-keys", flag.ContinueOnError)
	fs.SetOutput(stderr)
	force := fs.Bool("force", false, "delete all signing keys and make a new one")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !*force {
		_, _ = fmt.Fprintln(stdout, "This command deletes all signing keys and their secrets, and makes one new active key.")
		_, _ = fmt.Fprintln(stdout, "All tokens that the old keys signed become invalid. Users must log in again.")
		_, _ = fmt.Fprintln(stdout, "Nothing changed. Run the command with --force to do it.")
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
	if err := services.ForceRotateSigningKeys(ctx, cfg, log); err != nil {
		_, _ = fmt.Fprintf(stderr, "rotation failed: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, rotatedMessage)
	return 0
}

// rotatedMessage is the output of a successful rotate-signing-keys --force.
const rotatedMessage = "All signing keys were replaced. The new key is active. " +
	"A running service uses it after the next cache reload. " +
	"A verifier with a cached JWKS can reject new tokens for up to about 15 minutes."

var errNoAdminPort = errors.New("the admin address has no port")
