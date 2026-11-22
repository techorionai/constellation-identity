package domain_test

import (
	"crypto/sha256"
	"encoding/base64"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// Issue4_U1: the redirect URI rules.
func TestIssue4_U1_RedirectURIRules(t *testing.T) {
	for _, ok := range []string{"https://a.example.com/cb", "http://localhost:3000/cb", "http://127.0.0.1/cb", "http://[::1]:8080/cb", "https://a-b.example.com:8443/x?y=1"} {
		if err := domain.ValidateRedirectURI(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"http://a/cb", "https://*.a/cb", "https://a/cb#x", "https://u@a/cb", "ftp://a/cb", "https://a;b/cb", "https://a b/cb",
		"https://a,b/cb", "", "/cb", "https://", "https://a/\\cb", "https://a:99999/cb", "https://a.example.com/c*",
	} {
		if err := domain.ValidateRedirectURI(bad); err == nil {
			t.Errorf("%q must not be valid", bad)
		}
	}
}

// Issue4_U1b: the run time match.
func TestIssue4_U1b_Match(t *testing.T) {
	reg := []string{"https://a.example.com/cb"}
	for uri, want := range map[string]bool{
		"https://a.example.com/cb": true, "https://A.EXAMPLE.com/cb": true, "https://a.example.com/cb/": false,
		"https://a.example.com/cb?x=1": false, "http://localhost.evil.example/cb": false, "https://a.example.com:444/cb": false,
		"https://a.example.com/CB": false, "https://a.example.com/cb#f": false, "https://u@a.example.com/cb": false,
	} {
		if got := domain.MatchRedirectURI(reg, uri); got != want {
			t.Errorf("%s = %v, want %v", uri, got, want)
		}
	}
}

// Issue4_U1c: the loopback exception.
func TestIssue4_U1c_Loopback(t *testing.T) {
	reg := []string{"http://127.0.0.1/cb", "http://localhost:3000/cb", "http://[::1]/cb"}
	for uri, want := range map[string]bool{
		"http://127.0.0.1:5555/cb": true, "http://127.0.0.1/cb": true, "http://localhost:4000/cb": false, "http://localhost:3000/cb": true,
		"http://localhost/cb": false, "http://[::1]:7000/cb": true, "http://127.0.0.1:5555/other": false,
	} {
		if got := domain.MatchRedirectURI(reg, uri); got != want {
			t.Errorf("%s = %v, want %v", uri, got, want)
		}
	}
}

// Issue4_U9: the CORS origin rule.
func TestIssue4_U9_Origins(t *testing.T) {
	reg := []string{"https://a.example.com/cb", "http://127.0.0.1/cb", "http://localhost:3000/cb"}
	for origin, want := range map[string]bool{
		"https://a.example.com": true, "https://a.example.com:443": true, "https://a.example.com:444": false, "http://a.example.com": false,
		"http://127.0.0.1:5555": true, "http://localhost:3000": true, "http://localhost:5555": false, "https://evil.example.com": false,
		"https://a.example.com/path": false, "null": false, "": false,
	} {
		if got := domain.OriginAllowed(reg, origin); got != want {
			t.Errorf("%q = %v, want %v", origin, got, want)
		}
	}
}

// Issue4_U2 and U2a: PKCE.
func TestIssue4_U2_PKCE(t *testing.T) {
	verifier := strings.Repeat("a", 43)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if !domain.VerifyPKCE(challenge, verifier) {
		t.Fatal("the matching verifier must pass")
	}
	if domain.VerifyPKCE(challenge, strings.Repeat("b", 43)) {
		t.Fatal("a wrong verifier must fail")
	}
	// The method plain compares the verifier with the challenge.
	if domain.VerifyPKCE(verifier, verifier) {
		t.Fatal("plain must fail")
	}
	for n, want := range map[int]bool{42: false, 43: true, 128: true, 129: false} {
		if got := domain.ValidCodeVerifier(strings.Repeat("a", n)); got != want {
			t.Errorf("verifier of %d characters = %v", n, got)
		}
	}
	if domain.ValidCodeVerifier(strings.Repeat("a", 42) + "+") {
		t.Fatal("a plus is not in the set")
	}
	if domain.ValidCodeChallenge(strings.Repeat("a", 42)+"+") || !domain.ValidCodeChallenge(challenge) {
		t.Fatal("challenge form")
	}
}

// Issue4_U3 to U3c: scope selection.
func TestIssue4_U3_Scopes(t *testing.T) {
	r, err := domain.ParseAuthorizeScope("demo", "openid foo demo:ticket:read other:thing:read offline_access demo:ticket:read")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.Permissions, []string{"demo:ticket:read"}) || !slices.Equal(r.OIDC, []string{"openid", "offline_access"}) {
		t.Fatalf("scopes = %+v", r)
	}
	if _, err := domain.ParseAuthorizeScope("demo", "openid email"); err == nil {
		t.Fatal("no permission scope must fail")
	}
	if _, err := domain.ParseAuthorizeScope("demo", "other:thing:read"); err == nil {
		t.Fatal("a scope of another app must fail")
	}
	got := domain.IntersectScopes([]string{"demo:a:read", "demo:b:read"}, []string{"demo:a:read"})
	if !slices.Equal(got, []string{"demo:a:read"}) {
		t.Fatalf("intersect = %v", got)
	}
	if domain.IntersectScopes([]string{"demo:a:read"}, nil) != nil {
		t.Fatal("no permission must give none")
	}
}

// Issue4_U4: refresh scope.
func TestIssue4_U4_RefreshScope(t *testing.T) {
	stored := []string{"demo:a:read", "demo:b:read"}
	if got, err := domain.NarrowScope(stored, nil, ""); err != nil || !slices.Equal(got, stored) {
		t.Fatalf("no scope: %v %v", got, err)
	}
	if got, err := domain.NarrowScope(stored, nil, "demo:a:read"); err != nil || !slices.Equal(got, []string{"demo:a:read"}) {
		t.Fatalf("narrow: %v %v", got, err)
	}
	if _, err := domain.NarrowScope(stored, nil, "demo:a:read demo:c:read"); err == nil {
		t.Fatal("a wider scope must fail")
	}
	// An OIDC scope of the original grant is accepted. It does not widen the result.
	oidc := []string{"openid", "offline_access"}
	if got, err := domain.NarrowScope(stored, oidc, "openid offline_access demo:a:read"); err != nil || !slices.Equal(got, []string{"demo:a:read"}) {
		t.Fatalf("oidc scopes with a permission: %v %v", got, err)
	}
	if got, err := domain.NarrowScope(stored, oidc, "openid"); err != nil || !slices.Equal(got, stored) {
		t.Fatalf("oidc scope only: %v %v", got, err)
	}
	if _, err := domain.NarrowScope(stored, oidc, "email"); err == nil {
		t.Fatal("an OIDC scope that the grant did not have must fail")
	}
	if got := domain.IntersectScopes(stored, []string{"demo:a:read"}); !slices.Equal(got, []string{"demo:a:read"}) {
		t.Fatalf("after a role change: %v", got)
	}
}

// Issue4_U12a: a new session has the same time for created_at and auth_time.
func TestIssue4_U12a_NewSession(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	s := domain.SessionPolicy{IdleTimeout: time.Hour, AbsoluteTimeout: 24 * time.Hour}.NewSession("u", now)
	if !s.AuthTime.Equal(now) || !s.CreatedAt.Equal(now) {
		t.Fatalf("session = %+v", s)
	}
}

// Issue4_U12: the rule for the previous session.
func TestIssue4_U12_KeepOnRelogin(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	valid := domain.Session{UserID: "u", IdleExpiresAt: now.Add(time.Hour), ExpiresAt: now.Add(2 * time.Hour)}
	revoked := valid
	revoked.RevokedAt = &now
	idle := valid
	idle.IdleExpiresAt = now.Add(-time.Second)
	absolute := valid
	absolute.ExpiresAt = now.Add(-time.Second)
	for name, tt := range map[string]struct {
		s    domain.Session
		user string
		want bool
	}{
		"same user, valid": {valid, "u", true}, "same user, revoked": {revoked, "u", false}, "same user, idle expired": {idle, "u", false},
		"same user, absolute expired": {absolute, "u", false}, "other user": {valid, "v", false},
	} {
		if got := tt.s.KeepOnRelogin(tt.user, now); got != tt.want {
			t.Errorf("%s = %v", name, got)
		}
	}
}

// Issue4_U17: the used-code marker rule.
func TestIssue4_U17_UsedCode(t *testing.T) {
	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	m := domain.UsedCode{SessionID: "s", ClientID: "c", CodeChallenge: base64.RawURLEncoding.EncodeToString(sum[:])}
	if !m.ReuseRevokes("c", verifier) {
		t.Fatal("same client and matching verifier must revoke")
	}
	if m.ReuseRevokes("c", strings.Repeat("w", 43)) || m.ReuseRevokes("other", verifier) {
		t.Fatal("a wrong verifier or another client must not revoke")
	}
	if (domain.UsedCode{}).ReuseRevokes("c", verifier) {
		t.Fatal("no marker must not revoke")
	}
}

// Issue4_U13b: the claims of the tokens.
func TestIssue4_U13b_Claims(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	c := domain.UserAccessToken{Issuer: "i", Audience: "demo", UserID: "u", ClientID: "c", Scopes: []string{"demo:a:read"}, Now: now, TTL: 15 * time.Minute, JTI: "j"}.Claims()
	if c["principal_type"] != "user" || c["aud"] != "demo" || c["exp"].(int64) != now.Add(15*time.Minute).Unix() || c["scope"] != "demo:a:read" {
		t.Fatalf("access claims = %v", c)
	}
	if domain.AccessTokenType != "at+jwt" || domain.IDTokenType != "JWT" {
		t.Fatal("typ values")
	}
	email, name := "e@example.com", "N"
	id := domain.IDToken{Issuer: "i", UserID: "u", ClientID: "c", AuthTime: now, Nonce: "n", SessionID: "s", Now: now, TTL: time.Minute, Email: &email, Name: &name}.Claims()
	if id["aud"] != "c" || id["sid"] != "s" || id["nonce"] != "n" || id["email"] != "e@example.com" || id["email_verified"] != true || id["name"] != "N" {
		t.Fatalf("id claims = %v", id)
	}
	if _, ok := (domain.IDToken{Now: now, TTL: time.Minute}).Claims()["email"]; ok {
		t.Fatal("no email without the scope")
	}
}
