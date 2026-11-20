package config_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	"github.com/techorionai/constellation-identity/internal/config"
	"github.com/techorionai/constellation-identity/internal/domain"
)

func testJWK(t *testing.T) domain.PublicJWK {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return domain.PublicJWKOf(&priv.PublicKey)
}

func jwkYAML(j domain.PublicJWK, extra string) string {
	return fmt.Sprintf("{ kty: %s, crv: %s, x: %q, y: %q%s }", j.Kty, j.Crv, j.X, j.Y, extra)
}

func clientYAML(id, app, typ string, keys ...string) string {
	s := fmt.Sprintf("  - id: %s\n    app: %s\n    name: Test client\n", id, app)
	if typ != "" {
		s += "    type: " + typ + "\n"
	}
	s += "    keys:\n"
	for _, k := range keys {
		s += k
	}
	return s
}

func keyYAML(kid, jwk string) string {
	return fmt.Sprintf("      - kid: %s\n        jwk: %s\n", kid, jwk)
}

// U7: a valid file, an empty list, and a client with no type.
func TestU7_ClientsFileParse(t *testing.T) {
	j1, j2 := testJWK(t), testJWK(t)
	file := "clients:\n" +
		clientYAML("helpdesk", "helpdesk", "", keyYAML("k1", jwkYAML(j1, ""))) +
		clientYAML("billing", "billing", "service", keyYAML("k1", jwkYAML(j2, "")), keyYAML("k2", jwkYAML(j1, "")))
	got, err := config.ParseClientsFile([]byte(file))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || len(got[0].Keys) != 1 || len(got[1].Keys) != 2 {
		t.Fatalf("clients = %+v", got)
	}
	if got[0].Client.Type != domain.ClientTypeService || got[0].Client.Source != domain.SourceConfig {
		t.Fatalf("client = %+v", got[0].Client)
	}
	if got[0].Keys[0].PublicJWK.Kid != "k1" || got[0].Keys[0].PublicJWK.X != j1.X {
		t.Fatalf("key = %+v", got[0].Keys[0])
	}

	empty, err := config.ParseClientsFile([]byte("clients: []\n"))
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty list: %v %v", empty, err)
	}
	none, err := config.ParseClientsFile(nil)
	if err != nil || len(none) != 0 {
		t.Fatalf("empty file: %v %v", none, err)
	}
	noPath, err := config.LoadClientsFile("")
	if err != nil || noPath != nil {
		t.Fatalf("no path: %v %v", noPath, err)
	}
}

// U8: each bad case gives one error that names the client and the field.
func TestU8_ClientsFileErrors(t *testing.T) {
	good := testJWK(t)
	rsa := "{ kty: RSA, n: abc, e: AQAB }"
	tests := []struct {
		name  string
		file  string
		field string
	}{
		{"bad app", clientYAML("svc", "Bad-App", "", keyYAML("k", jwkYAML(good, ""))), "field app"},
		{"app identity", clientYAML("svc", "identity", "", keyYAML("k", jwkYAML(good, ""))), "field app"},
		{"private d", clientYAML("svc", "svc", "", keyYAML("k", jwkYAML(good, `, d: "AAAA"`))), "keys[0].jwk"},
		{"rsa key", clientYAML("svc", "svc", "", keyYAML("k", rsa)), "keys[0].jwk"},
		{"duplicate kid", clientYAML("svc", "svc", "", keyYAML("k", jwkYAML(good, "")), keyYAML("k", jwkYAML(good, ""))), "keys[1].kid"},
		{"n and e in an EC key", clientYAML("svc", "svc", "", keyYAML("k", jwkYAML(good, ", n: AQAB, e: AQAB"))), "keys[0].jwk"},
		{"alg HS256", clientYAML("svc", "svc", "", keyYAML("k", jwkYAML(good, ", alg: HS256"))), "keys[0].jwk"},
		{"use enc", clientYAML("svc", "svc", "", keyYAML("k", jwkYAML(good, ", use: enc"))), "keys[0].jwk"},
		{"bad id", clientYAML("Bad Id", "svc", "", keyYAML("k", jwkYAML(good, ""))), "field id"},
		{"public type", clientYAML("svc", "svc", "public", keyYAML("k", jwkYAML(good, ""))), "field type"},
		{"point not on curve", clientYAML("svc", "svc", "", keyYAML("k", "{ kty: EC, crv: P-256, x: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, y: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA }")), "keys[0].jwk"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := config.ParseClientsFile([]byte("clients:\n" + tt.file))
			if err == nil {
				t.Fatal("want an error")
			}
			msg := err.Error()
			if !strings.Contains(msg, `client "`) || !strings.Contains(msg, tt.field) {
				t.Fatalf("error %q does not name the client and %q", msg, tt.field)
			}
			if strings.Count(msg, "\n") != 0 {
				t.Fatalf("want one error, got %q", msg)
			}
			if strings.Contains(msg, "AAAA") {
				t.Fatalf("error has key material: %q", msg)
			}
		})
	}
}

func baseEnv(t *testing.T) {
	t.Helper()
	t.Setenv("IDENTITY_ISSUER", "https://id.example.com")
	t.Setenv("IDENTITY_DATABASE__URL", "postgres://u:p@localhost/identity")
	t.Setenv("IDENTITY_DATABASE__NAME", "identity")
	t.Setenv("IDENTITY_VALKEY__ADDRESS", "localhost:6379")
	t.Setenv("IDENTITY_VALKEY__KEY_PREFIX", "identity")
	t.Setenv("IDENTITY_SECRETS__MASTER_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	t.Setenv("IDENTITY_SECRETS__MASTER_KEY_ID", "k1")
}

// U9: each bad value gives an error that names the variable.
func TestU9_ConfigErrors(t *testing.T) {
	t.Run("defaults pass", func(t *testing.T) {
		baseEnv(t)
		cfg, err := config.Load()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.HTTP.Addr != ":8080" || cfg.Admin.Addr != ":9090" {
			t.Fatalf("addr = %q %q", cfg.HTTP.Addr, cfg.Admin.Addr)
		}
		if cfg.Keys.RotationPeriod.Hours() != 2160 || cfg.Keys.PublishDelay.Hours() != 1 || cfg.Keys.RetireAfter.Hours() != 24 {
			t.Fatalf("keys = %+v", cfg.Keys)
		}
	})
	tests := []struct {
		name  string
		set   map[string]string
		unset string
		want  string
	}{
		{"no issuer", nil, "IDENTITY_ISSUER", "IDENTITY_ISSUER"},
		{"publish delay", map[string]string{"IDENTITY_KEYS__PUBLISH_DELAY": "19m"}, "", "IDENTITY_KEYS__PUBLISH_DELAY"},
		{"retire after", map[string]string{"IDENTITY_KEYS__RETIRE_AFTER": "29m"}, "", "IDENTITY_KEYS__RETIRE_AFTER"},
		{"rotation period", map[string]string{"IDENTITY_KEYS__ROTATION_PERIOD": "1h"}, "", "IDENTITY_KEYS__ROTATION_PERIOD"},
		{"bad issuer", map[string]string{"IDENTITY_ISSUER": "http://id.example.com"}, "", "IDENTITY_ISSUER"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseEnv(t)
			for k, v := range tt.set {
				t.Setenv(k, v)
			}
			if tt.unset != "" {
				t.Setenv(tt.unset, "")
			}
			_, err := config.Load()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want it to name %s", err, tt.want)
			}
		})
	}
}

// R26: the minimum publish delay is 20 minutes.
func TestPublishDelayMinimum(t *testing.T) {
	baseEnv(t)
	t.Setenv("IDENTITY_KEYS__PUBLISH_DELAY", "20m")
	if _, err := config.Load(); err != nil {
		t.Fatalf("20m must pass: %v", err)
	}
}

// U9a: the issuer rule.
func TestU9a_IssuerRule(t *testing.T) {
	pass := []string{
		"https://id.example.com", "http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080",
		"https://id.example.com/base",
	}
	fail := []string{
		"http://id.example.com", "http://identity:8080", "https://id.example.com?a=b", "ftp://x", "",
		"https://id.example.com#frag", "id.example.com", "https://", "https://u:p@id.example.com",
		// R24: port range, white space, control characters, trailing slash.
		"https://x.com:99999", "https://x.com:0", "https://x.com/a b", "https://x.com/", "https://x.com/base/",
		"https://x.com/a\tb", " https://x.com", "https://x.com/a\x00b", "https://x.com:80a",
	}
	for _, s := range pass {
		if err := config.ValidateIssuer(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range fail {
		if err := config.ValidateIssuer(s); err == nil {
			t.Errorf("%q must fail", s)
		}
	}
}
