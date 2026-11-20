package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

const defaultAdminAddr = ":9090"

// runHealthcheck asks /readyz of the local admin server. The distroless image
// has no shell, so the container health check uses this command.
func runHealthcheck(stdout, stderr io.Writer) int {
	addr := os.Getenv("IDENTITY_ADMIN__ADDR")
	if addr == "" {
		addr = defaultAdminAddr
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		_, _ = fmt.Fprintf(stderr, "healthcheck: %v\n", errNoAdminPort)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	return healthcheck(ctx, "http://"+net.JoinHostPort("127.0.0.1", port)+"/readyz", stdout, stderr)
}

// healthcheck returns 0 if the URL answers 200, and 1 in all other cases.
func healthcheck(ctx context.Context, url string, stdout, stderr io.Writer) int {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) //nolint:gosec // The URL is the local admin port.
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "healthcheck: %v\n", err)
		return 1
	}
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // The URL is the local admin port.
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "healthcheck: %v\n", err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		_, _ = fmt.Fprintf(stderr, "healthcheck: status %d\n", resp.StatusCode)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "ready")
	return 0
}
