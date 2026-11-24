package services_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/techorionai/constellation-platform-go/manifest"

	"github.com/techorionai/constellation-identity/api/openapi"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/services"
)

type noKeys struct{}

func (noKeys) JWKS() []domain.PublicJWK { return nil }

// Issue2_U12d: AllowInsecureHTTP is true only for an http issuer with a
// loopback host. A non-loopback http issuer stops the start with an error that
// names the issuer.
func TestIssue2_U12d_VerifierConfig(t *testing.T) {
	for issuer, want := range map[string]bool{
		"https://id.example.com": false,
		"http://localhost:8080":  true,
		"http://127.0.0.1:8080":  true,
		"http://[::1]:8080":      true,
		"http://id.example.com":  false,
	} {
		cfg := services.VerifierConfig(issuer)
		if cfg.AllowInsecureHTTP != want {
			t.Errorf("%s: AllowInsecureHTTP = %v, want %v", issuer, cfg.AllowInsecureHTTP, want)
		}
		if cfg.Audience != "identity" || cfg.Issuer != issuer || !strings.HasSuffix(cfg.JWKSURL, "/.well-known/jwks.json") {
			t.Errorf("%s: config = %+v", issuer, cfg)
		}
	}
	for _, issuer := range []string{"https://id.example.com", "http://localhost:8080"} {
		v, err := services.NewVerifier(issuer, noKeys{})
		if err != nil {
			t.Errorf("%s: %v", issuer, err)
			continue
		}
		v.Close()
	}
	_, err := services.NewVerifier("http://id.example.com", noKeys{})
	if err == nil || !strings.Contains(err.Error(), "http://id.example.com") {
		t.Fatalf("error = %v, want one that names the issuer", err)
	}
}

// Issue2_U12c: the embedded identity manifest has the permission
// identity:admin, and only the role admin holds it.
func TestIssue2_U12c_OwnManifest(t *testing.T) {
	m, err := manifest.Load(openapi.Files, openapi.IdentityManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	own := services.OwnManifest(m)
	if own.App != "identity" || len(domain.CheckManifest(own)) != 0 {
		t.Fatalf("manifest = %+v, errors = %v", own.App, domain.CheckManifest(own))
	}
	if !slices.ContainsFunc(own.Permissions, func(p domain.PermissionDef) bool { return p.Key == domain.AdminPermission }) {
		t.Fatal("the manifest has no identity:admin")
	}
	holders := map[string]bool{}
	for _, r := range own.Roles {
		holders[r.Key] = slices.Contains(r.Permissions, domain.AdminPermission)
	}
	if !holders["admin"] || holders["service"] || holders["user"] || len(holders) != 3 {
		t.Fatalf("holders = %v", holders)
	}
	var service domain.RoleDef
	for _, r := range own.Roles {
		if r.Key == "service" {
			service = r
		}
	}
	if !slices.Equal(service.Permissions, []string{"identity:manifest:publish"}) {
		t.Fatalf("service role = %+v", service)
	}
}
