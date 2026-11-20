package httpapi_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/techorionai/constellation-identity/internal/app/queries"
	"github.com/techorionai/constellation-identity/internal/domain"
	httpapi "github.com/techorionai/constellation-identity/internal/handlers/http"
)

type fakeKeys struct{ keys []domain.PublicJWK }

func (f fakeKeys) JWKS() []domain.PublicJWK { return f.keys }

func newServer(issuer string, keys ...domain.PublicJWK) http.Handler {
	return httpapi.New(httpapi.Deps{
		JWKS:      queries.NewGetJWKS(fakeKeys{keys}),
		Discovery: queries.NewGetDiscovery(issuer),
	}).Handler()
}

func get(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(t0(), method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// U10: the discovery document.
func TestU10_Discovery(t *testing.T) {
	rec := get(newServer("https://id.example.com"), http.MethodGet, "/.well-known/openid-configuration", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=3600" {
		t.Fatalf("Cache-Control = %q", cc)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	str := func(k string) string { s, _ := doc[k].(string); return s }
	list := func(k string) []any { l, _ := doc[k].([]any); return l }
	if str("issuer") != "https://id.example.com" {
		t.Fatalf("issuer = %q", str("issuer"))
	}
	endpoints := map[string]string{ //nolint:gosec // Not credentials.
		"authorization_endpoint": "/oauth/authorize",
		"token_endpoint":         "/oauth/token",
		"userinfo_endpoint":      "/oauth/userinfo",
		"end_session_endpoint":   "/oauth/end_session",
		"revocation_endpoint":    "/oauth/revoke",
		"jwks_uri":               "/.well-known/jwks.json",
	}
	for k, path := range endpoints {
		if str(k) != "https://id.example.com"+path {
			t.Errorf("%s = %q", k, str(k))
		}
	}
	for k, want := range map[string]string{ //nolint:gosec // Not credentials.
		"token_endpoint_auth_methods_supported":            "private_key_jwt",
		"token_endpoint_auth_signing_alg_values_supported": "ES256",
		"id_token_signing_alg_values_supported":            "ES256",
		"code_challenge_methods_supported":                 "S256",
		"response_types_supported":                         "code",
		"subject_types_supported":                          "public",
	} {
		l := list(k)
		if len(l) != 1 || l[0] != want {
			t.Errorf("%s = %v, want [%s]", k, l, want)
		}
	}
	if l, ok := doc["grant_types_supported"].([]any); !ok || len(l) != 0 {
		t.Errorf("grant_types_supported = %v", doc["grant_types_supported"])
	}
}

func TestJWKSBodyAndCache(t *testing.T) {
	key := domain.PublicJWK{Kty: "EC", Crv: "P-256", X: "x", Y: "y", Kid: "abc", Use: "sig", Alg: "ES256"}
	rec := get(newServer("https://id.example.com", key), http.MethodGet, "/.well-known/jwks.json", "")
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "public, max-age=300" {
		t.Fatalf("status %d, Cache-Control %q", rec.Code, rec.Header().Get("Cache-Control"))
	}
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 1 || set.Keys[0]["kid"] != "abc" || set.Keys[0]["use"] != "sig" {
		t.Fatalf("keys = %v", set.Keys)
	}
}

// The operations of later issues answer 501 with a Problem body.
func TestNotImplementedOperations(t *testing.T) {
	h := newServer("https://id.example.com")
	for _, path := range []string{"/v1/roles", "/v1/me", "/oauth/userinfo", "/v1/users"} {
		rec := get(h, http.MethodGet, path, "")
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("%s: status = %d", path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
			t.Fatalf("%s: Content-Type = %q", path, ct)
		}
		var p map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		if p["code"] != "not_implemented" || p["status"] != float64(501) {
			t.Fatalf("%s: problem = %v", path, p)
		}
	}
}

func TestTokenEndpointUnsupportedGrant(t *testing.T) {
	h := newServer("https://id.example.com")
	rec := get(h, http.MethodPost, "/oauth/token", "grant_type=client_credentials")
	if rec.Code != http.StatusBadRequest {
		body, _ := io.ReadAll(rec.Body)
		t.Fatalf("status = %d, body %s", rec.Code, body)
	}
	var e map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatal(err)
	}
	if e["error"] != "unsupported_grant_type" {
		t.Fatalf("error body = %v", e)
	}
}
