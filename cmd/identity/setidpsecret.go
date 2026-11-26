package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/techorionai/constellation-identity/internal/config"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/services"
)

const setIdpSecretUsage = "usage: identity set-idp-secret <google|microsoft>   (the secret is one line on stdin)"

// maxIdpSecretBytes is the largest client secret that the subcommand reads.
const maxIdpSecretBytes = 4096

// stdin is the input of the subcommands. A test replaces it.
var stdin io.Reader = os.Stdin

// runSetIdpSecret stores the client secret of an upstream provider in the
// secrets store. It reads the secret from stdin (one line, at most 4 KiB). It
// writes "stored" to stdout. It never writes the secret to a log or to stdout.
// It exits with 0 on success, 1 on an error, and 2 for a usage error or an empty
// secret.
func runSetIdpSecret(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || !domain.ValidProvider(args[0]) {
		_, _ = fmt.Fprintln(stderr, setIdpSecretUsage)
		return 2
	}
	secret, err := readSecretLine(stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "set-idp-secret: %v\n", err)
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
	if err := services.SetIdpSecret(ctx, cfg, args[0], secret, log); err != nil {
		_, _ = fmt.Fprintf(stderr, "set-idp-secret failed: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "stored")
	return 0
}

// readSecretLine reads one line of at most maxIdpSecretBytes. It removes the
// line end. An empty line, and a line that is too long, are errors.
func readSecretLine(r io.Reader) (string, error) {
	br := bufio.NewReader(io.LimitReader(r, maxIdpSecretBytes+2))
	line, err := br.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read the secret: %w", err)
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return "", errors.New("the secret on stdin is empty")
	}
	if len(line) > maxIdpSecretBytes {
		return "", fmt.Errorf("the secret is longer than %d bytes", maxIdpSecretBytes)
	}
	return line, nil
}
