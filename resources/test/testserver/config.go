package testserver

import (
	"testing"

	"github.com/techorionai/constellation-identity/internal/config"
)

// Config returns the config that Start would use, with a new database if
// WithDB is not set. It does not start a server.
func (e *Env) Config(t testing.TB, opts ...Option) config.Config {
	t.Helper()
	cfg, _, err := e.buildConfig(t, opts)
	if err != nil {
		t.Fatalf("testserver: config: %v", err)
	}
	return cfg
}
