package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/config"
)

// U9 of issue 15: the defaults of the WebAuthn settings and of the bucket
// passkey, and the errors. Each error names its variable.
func TestIssue15_U9_WebAuthnSettings(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		baseEnv(t)
		cfg, err := config.Load()
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.WebAuthn.Enabled || cfg.WebAuthn.RPName != "Constellation" {
			t.Fatalf("webauthn = %+v", cfg.WebAuthn)
		}
		if r := cfg.RateLimit.Rules()["passkey"]; r.Limit != 30 || r.Window != time.Minute || r.Name != "passkey" {
			t.Fatalf("passkey rule = %+v", r)
		}
	})
	t.Run("set", func(t *testing.T) {
		baseEnv(t)
		t.Setenv("IDENTITY_WEBAUTHN__ENABLED", "false")
		t.Setenv("IDENTITY_WEBAUTHN__RP_NAME", "Acme")
		t.Setenv("IDENTITY_RATE_LIMIT__PASSKEY__LIMIT", "5")
		cfg, err := config.Load()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.WebAuthn.Enabled || cfg.WebAuthn.RPName != "Acme" || cfg.RateLimit.Rules()["passkey"].Limit != 5 {
			t.Fatalf("config = %+v", cfg)
		}
	})
	bad := map[string]string{
		"IDENTITY_WEBAUTHN__RP_NAME":           strings.Repeat("a", 65),
		"IDENTITY_RATE_LIMIT__PASSKEY__LIMIT":  "0",
		"IDENTITY_RATE_LIMIT__PASSKEY__WINDOW": "25h",
		"IDENTITY_WEBAUTHN__ENABLED":           "maybe",
	}
	for name, value := range bad {
		t.Run(name, func(t *testing.T) {
			baseEnv(t)
			t.Setenv(name, value)
			_, err := config.Load()
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("err = %v, want an error that names %s", err, name)
			}
		})
	}
}
