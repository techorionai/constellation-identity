package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/config"
)

// U12: the defaults of the user settings, and the limits.
func TestU12_UserSettings(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		baseEnv(t)
		cfg, err := config.Load()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Setup.TTL != 24*time.Hour || cfg.Invite.TTL != 72*time.Hour ||
			cfg.Session.IdleTimeout != 12*time.Hour || cfg.Session.AbsoluteTimeout != 168*time.Hour ||
			cfg.Password.MaxConcurrent != 4 || cfg.Password.QueueTimeout != 2*time.Second ||
			cfg.Login.MaxFailuresPerEmail != 5 || cfg.Login.MaxFailuresPerIP != 50 || cfg.Login.FailureWindow != 15*time.Minute ||
			len(cfg.HTTP.TrustedProxies) != 0 {
			t.Fatalf("config = %+v", cfg)
		}
	})
	t.Run("trusted proxies", func(t *testing.T) {
		baseEnv(t)
		t.Setenv("IDENTITY_HTTP__TRUSTED_PROXIES", "10.0.0.0/8,2001:db8::/32")
		cfg, err := config.Load()
		if err != nil {
			t.Fatal(err)
		}
		p, err := cfg.HTTP.TrustedProxyPrefixes()
		if err != nil || len(p) != 2 {
			t.Fatalf("prefixes = %v, %v", p, err)
		}
	})
	bad := map[string]string{
		"IDENTITY_SETUP__TTL":                    "9m",
		"IDENTITY_INVITE__TTL":                   "721h",
		"IDENTITY_SESSION__IDLE_TIMEOUT":         "4m",
		"IDENTITY_SESSION__ABSOLUTE_TIMEOUT":     "59m",
		"IDENTITY_PASSWORD__MAX_CONCURRENT":      "0",
		"IDENTITY_PASSWORD__QUEUE_TIMEOUT":       "50ms",
		"IDENTITY_LOGIN__MAX_FAILURES_PER_EMAIL": "101",
		"IDENTITY_LOGIN__MAX_FAILURES_PER_IP":    "0",
		"IDENTITY_LOGIN__FAILURE_WINDOW":         "30s",
		"IDENTITY_HTTP__TRUSTED_PROXIES":         "10.0.0.0/8,not-a-cidr",
	}
	for name, value := range bad {
		t.Run(name, func(t *testing.T) {
			baseEnv(t)
			t.Setenv(name, value)
			_, err := config.Load()
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("error = %v, want it to name %s", err, name)
			}
		})
	}
	t.Run("idle more than absolute", func(t *testing.T) {
		baseEnv(t)
		t.Setenv("IDENTITY_SESSION__ABSOLUTE_TIMEOUT", "2h")
		t.Setenv("IDENTITY_SESSION__IDLE_TIMEOUT", "3h")
		_, err := config.Load()
		if err == nil || !strings.Contains(err.Error(), "IDENTITY_SESSION__IDLE_TIMEOUT") {
			t.Fatalf("error = %v", err)
		}
	})
}
