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

// Issue4_U14: the OIDC settings and the new retention jobs.
func TestIssue4_U14_OIDCSettings(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		baseEnv(t)
		cfg, err := config.Load()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.OIDC.AuthRequestTTL != 10*time.Minute || cfg.OIDC.CodeTTL != time.Minute || cfg.OIDC.UserTokenTTL != 15*time.Minute {
			t.Fatalf("oidc = %+v", cfg.OIDC)
		}
	})
	tests := []struct {
		name, value string
		ok          bool
	}{
		{"IDENTITY_OIDC__AUTH_REQUEST_TTL", "1m", true}, {"IDENTITY_OIDC__AUTH_REQUEST_TTL", "1h", true},
		{"IDENTITY_OIDC__AUTH_REQUEST_TTL", "59s", false}, {"IDENTITY_OIDC__AUTH_REQUEST_TTL", "61m", false},
		{"IDENTITY_OIDC__CODE_TTL", "10s", true}, {"IDENTITY_OIDC__CODE_TTL", "10m", true},
		{"IDENTITY_OIDC__CODE_TTL", "9s", false}, {"IDENTITY_OIDC__CODE_TTL", "11m", false},
		{"IDENTITY_OIDC__USER_TOKEN_TTL", "1m", true}, {"IDENTITY_OIDC__USER_TOKEN_TTL", "1h", true},
		{"IDENTITY_OIDC__USER_TOKEN_TTL", "59s", false}, {"IDENTITY_OIDC__USER_TOKEN_TTL", "61m", false},
		{"IDENTITY_RETENTION__REFRESH_TOKENS__BATCH_SIZE", "1", true}, {"IDENTITY_RETENTION__REFRESH_TOKENS__BATCH_SIZE", "0", false},
		{"IDENTITY_RETENTION__REFRESH_TOKEN_FAMILIES__BATCH_SIZE", "100000", true}, {"IDENTITY_RETENTION__REFRESH_TOKEN_FAMILIES__BATCH_SIZE", "100001", false},
	}
	for _, tt := range tests {
		t.Run(tt.name+"="+tt.value, func(t *testing.T) {
			baseEnv(t)
			t.Setenv(tt.name, tt.value)
			_, err := config.Load()
			switch {
			case tt.ok && err != nil:
				t.Fatalf("err = %v", err)
			case !tt.ok && err == nil:
				t.Fatal("want an error")
			case !tt.ok && !strings.Contains(err.Error(), strings.TrimPrefix(strings.Split(tt.name, "__BATCH")[0], "IDENTITY_")):
				t.Fatalf("the error must name the variable: %v", err)
			}
		})
	}
}

// Issue4: a public client in the clients file.
func TestIssue4_PublicClientInFile(t *testing.T) {
	file := "clients:\n  - id: admin-ui\n    app: identity\n    type: public\n    name: Admin\n    redirect_uris:\n      - https://admin.example.com/cb\n    post_logout_redirect_uris:\n      - https://admin.example.com/bye\n"
	got, err := config.ParseClientsFile([]byte(file))
	if err != nil || len(got) != 1 || got[0].Client.Type != "public" || got[0].Client.RedirectURIs[0] != "https://admin.example.com/cb" || len(got[0].Keys) != 0 {
		t.Fatalf("public client: %+v %v", got, err)
	}
	for name, bad := range map[string]string{
		"http redirect": "    redirect_uris: [http://example.com/cb]\n", "no redirect": "    name: x\n",
		"fragment": "    redirect_uris: [\"https://a.example.com/cb#x\"]\n",
	} {
		_, err := config.ParseClientsFile([]byte("clients:\n  - id: badui\n    app: demo\n    type: public\n" + bad))
		if err == nil || !strings.Contains(err.Error(), "badui") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := config.ParseClientsFile([]byte("clients:\n  - id: svc\n    app: demo\n    redirect_uris: [https://a.example.com/cb]\n")); err == nil {
		t.Error("a service client with a redirect URI must fail")
	}
}
