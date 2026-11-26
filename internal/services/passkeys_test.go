package services

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/techorionai/constellation-identity/internal/config"
)

// U3 of issue 15: an issuer with an IP address as host turns passkeys off and
// writes one warn record. The setting that turns passkeys off writes none.
func TestIssue15_U3_IPIssuerTurnsPasskeysOff(t *testing.T) {
	var buf bytes.Buffer
	a := &App{cfg: config.Config{Issuer: "http://127.0.0.1:8080", WebAuthn: config.WebAuthn{Enabled: true, RPName: "Constellation"}},
		log: slog.New(slog.NewTextHandler(&buf, nil))}
	w, on, err := a.buildWebAuthn()
	if err != nil || on || w != nil {
		t.Fatalf("service = %v, on = %v, err = %v", w, on, err)
	}
	if n := strings.Count(buf.String(), "level=WARN"); n != 1 {
		t.Fatalf("warn records = %d, want 1: %s", n, buf.String())
	}

	buf.Reset()
	a.cfg = config.Config{Issuer: "http://localhost:8080", WebAuthn: config.WebAuthn{Enabled: true, RPName: "Constellation"}}
	if w, on, err = a.buildWebAuthn(); err != nil || !on || w == nil || buf.Len() != 0 {
		t.Fatalf("localhost: service = %v, on = %v, err = %v, log = %s", w, on, err, buf.String())
	}

	a.cfg.WebAuthn.Enabled = false
	if w, on, err = a.buildWebAuthn(); err != nil || on || w != nil || buf.Len() != 0 {
		t.Fatalf("off: service = %v, on = %v, err = %v, log = %s", w, on, err, buf.String())
	}
}
