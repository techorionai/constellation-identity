package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/config"
)

// U1 of issue 16: the Microsoft tenant. The values common and consumers give an
// error. A GUID and organizations are valid.
func TestIssue16_U1_MicrosoftTenant(t *testing.T) {
	for _, c := range []struct {
		tenant string
		ok     bool
	}{
		{"common", false}, {"consumers", false}, {"11111111-aaaa-4aaa-8aaa-111111111111", true}, {"organizations", true},
	} {
		t.Run(c.tenant, func(t *testing.T) {
			baseEnv(t)
			t.Setenv("IDENTITY_IDP__MICROSOFT__CLIENT_ID", "client")
			t.Setenv("IDENTITY_IDP__MICROSOFT__TENANT", c.tenant)
			_, err := config.Load()
			if c.ok && err != nil {
				t.Fatalf("err = %v", err)
			}
			if !c.ok && (err == nil || !strings.Contains(err.Error(), "IDENTITY_IDP__MICROSOFT__TENANT")) {
				t.Fatalf("err = %v, want an error that names the variable", err)
			}
		})
	}
}

// The defaults: both providers are off, the tenant is organizations, and the
// deadline is 10 s. A provider is on when its client ID is set.
func TestIssue16_IdpDefaultsAndProviders(t *testing.T) {
	baseEnv(t)
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.IDP.Providers()) != 0 || cfg.IDP.Microsoft.Tenant != "organizations" || cfg.IDP.HTTPTimeout != 10*time.Second {
		t.Fatalf("idp = %+v", cfg.IDP)
	}
	if r := cfg.RateLimit.Rules()["idp"]; r.Limit != 30 || r.Window != time.Minute {
		t.Fatalf("idp rule = %+v", r)
	}
	t.Setenv("IDENTITY_IDP__GOOGLE__CLIENT_ID", "g")
	t.Setenv("IDENTITY_IDP__GOOGLE__ALLOWED_DOMAINS", "example.com,other.org")
	t.Setenv("IDENTITY_IDP__MICROSOFT__CLIENT_ID", "m")
	t.Setenv("IDENTITY_RATE_LIMIT__IDP__LIMIT", "2")
	cfg, err = config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.IDP.Providers(); len(got) != 2 || got[0] != "google" || got[1] != "microsoft" {
		t.Fatalf("providers = %v", got)
	}
	if len(cfg.IDP.Google.AllowedDomains) != 2 || cfg.RateLimit.Rules()["idp"].Limit != 2 {
		t.Fatalf("idp = %+v", cfg.IDP)
	}
}

// The bad values give an error that names the variable.
func TestIssue16_IdpBadValues(t *testing.T) {
	bad := map[string]string{
		"IDENTITY_IDP__HTTP_TIMEOUT":            "26s",
		"IDENTITY_IDP__GOOGLE__CLIENT_ID":       strings.Repeat("a", 257),
		"IDENTITY_IDP__MICROSOFT__CLIENT_ID":    strings.Repeat("a", 257),
		"IDENTITY_IDP__GOOGLE__ALLOWED_DOMAINS": "a@b.com",
		"IDENTITY_RATE_LIMIT__IDP__LIMIT":       "0",
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
	baseEnv(t)
	t.Setenv("IDENTITY_IDP__HTTP_TIMEOUT", "0s")
	if _, err := config.Load(); err == nil {
		t.Fatal("a timeout of 0 must fail")
	}
}
