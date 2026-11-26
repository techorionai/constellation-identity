package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/config"
	"github.com/techorionai/constellation-identity/internal/ports/ratelimit"
)

// U3: with no rate limit variables, the rules are the defaults.
func TestU3_RateLimitDefaults(t *testing.T) {
	baseEnv(t)
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RateLimit.Enabled {
		t.Fatal("rate limits must be enabled by default")
	}
	rules := cfg.RateLimit.Rules()
	want := map[string]struct {
		limit  int64
		window time.Duration
	}{
		"public_meta":       {300, time.Minute},
		"oauth_public":      {60, time.Minute},
		"oauth_backend_ip":  {600, time.Minute},
		"token_ip":          {600, time.Minute},
		"introspect_ip":     {6000, time.Minute},
		"token_client":      {300, time.Minute},
		"introspect_client": {6000, time.Minute},
		"setup_invite":      {10, 15 * time.Minute},
		"api_token_create":  {20, time.Hour},
		"manifest_publish":  {60, time.Hour},
		"mfa_verify":        {30, time.Minute},
		"passkey":           {30, time.Minute},
	}
	if len(rules) != len(want) || len(ratelimit.Buckets()) != len(want) {
		t.Fatalf("rules = %v", rules)
	}
	for name, w := range want {
		got := rules[name]
		if got.Name != name || got.Limit != w.limit || got.Window != w.window {
			t.Errorf("%s: got %+v, want %+v", name, got, w)
		}
	}
}

// U3: a set value replaces the default of its bucket only.
func TestU3_RateLimitOverride(t *testing.T) {
	baseEnv(t)
	t.Setenv("IDENTITY_RATE_LIMIT__TOKEN_IP__LIMIT", "5")
	t.Setenv("IDENTITY_RATE_LIMIT__TOKEN_IP__WINDOW", "30s")
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.RateLimit.Rules()
	if r["token_ip"].Limit != 5 || r["token_ip"].Window != 30*time.Second || r["token_client"].Limit != 300 {
		t.Fatalf("rules = %+v", r)
	}
}

// U4: a bad limit or window gives an error that names the variable.
func TestU4_RateLimitErrors(t *testing.T) {
	tests := []struct{ name, value string }{
		{"IDENTITY_RATE_LIMIT__TOKEN_IP__LIMIT", "0"},
		{"IDENTITY_RATE_LIMIT__TOKEN_IP__LIMIT", "1000001"},
		{"IDENTITY_RATE_LIMIT__SETUP_INVITE__WINDOW", "0s"},
		{"IDENTITY_RATE_LIMIT__SETUP_INVITE__WINDOW", "25h"},
	}
	for _, tt := range tests {
		t.Run(tt.name+"="+tt.value, func(t *testing.T) {
			baseEnv(t)
			t.Setenv(tt.name, tt.value)
			_, err := config.Load()
			if err == nil || !strings.Contains(err.Error(), tt.name) {
				t.Fatalf("error = %v, want it to name %s", err, tt.name)
			}
		})
	}
}
