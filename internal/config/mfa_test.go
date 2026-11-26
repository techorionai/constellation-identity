package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/config"
)

// U16: the defaults of the MFA settings, and the range errors. Each error
// names its variable.
func TestU16_MFASettings(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		baseEnv(t)
		cfg, err := config.Load()
		if err != nil {
			t.Fatal(err)
		}
		m := cfg.MFA
		if !m.RequireForAdmins || m.TOTPIssuer != "Constellation" || m.MaxFailuresPerUser != 10 || m.FailureWindow != 15*time.Minute {
			t.Fatalf("mfa = %+v", m)
		}
	})
	t.Run("rule off", func(t *testing.T) {
		baseEnv(t)
		t.Setenv("IDENTITY_MFA__REQUIRE_FOR_ADMINS", "false")
		cfg, err := config.Load()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.MFA.RequireForAdmins {
			t.Fatal("the rule must be off")
		}
	})
	bad := map[string]string{
		"IDENTITY_MFA__TOTP_ISSUER":              strings.Repeat("a", 65),
		"IDENTITY_MFA__MAX_FAILURES_PER_USER":    "101",
		"IDENTITY_MFA__FAILURE_WINDOW":           "30s",
		"IDENTITY_RATE_LIMIT__MFA_VERIFY__LIMIT": "0",
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
