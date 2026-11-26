package domain_test

import (
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// U15: the user token has amr and auth_time. A token with no method or no
// time has neither claim. The service token has neither claim.
func TestU15_TokenClaims(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	authTime := now.Add(-time.Minute)
	full := domain.UserAccessToken{
		Issuer: "https://id", Audience: "demo", UserID: "u", ClientID: "c", Now: now, TTL: time.Minute, JTI: "j",
		AuthMethods: domain.WithSecondFactor(domain.MethodsPassword(), domain.AMROTP), AuthTime: authTime,
	}.Claims()
	amr, ok := full["amr"].([]string)
	if !ok || len(amr) != 3 || amr[2] != "mfa" || full["auth_time"] != authTime.Unix() {
		t.Fatalf("claims = %v", full)
	}
	old := domain.UserAccessToken{Issuer: "https://id", Audience: "demo", UserID: "u", ClientID: "c", Now: now, TTL: time.Minute, JTI: "j"}.Claims()
	if _, ok := old["amr"]; ok {
		t.Fatal("a token with no methods must have no amr")
	}
	if _, ok := old["auth_time"]; ok {
		t.Fatal("a token with no auth time must have no auth_time")
	}
	svc := domain.ServiceToken{Issuer: "https://id", Audience: "demo", ClientID: "c", Now: now, JTI: "j"}.Claims()
	if _, ok := svc["amr"]; ok {
		t.Fatal("a service token must have no amr")
	}
	if _, ok := svc["auth_time"]; ok {
		t.Fatal("a service token must have no auth_time")
	}
	id := domain.IDToken{Issuer: "https://id", UserID: "u", ClientID: "c", AuthTime: authTime, Now: now, TTL: time.Minute, AuthMethods: domain.MethodsPassword()}.Claims()
	if got, ok := id["amr"].([]string); !ok || len(got) != 1 || got[0] != "pwd" || id["auth_time"] != authTime.Unix() {
		t.Fatalf("id token claims = %v", id)
	}
	noAMR := domain.IDToken{AuthTime: authTime}.Claims()
	if _, ok := noAMR["amr"]; ok {
		t.Fatal("an ID token with no methods must have no amr")
	}
}

// The rule MFA for admins.
func TestNeedsMFA(t *testing.T) {
	admin := []string{"identity:user:read", domain.AdminPermission}
	if !domain.NeedsMFA(true, admin) || domain.NeedsMFA(false, admin) || domain.NeedsMFA(true, []string{"identity:user:read"}) {
		t.Fatal("NeedsMFA is wrong")
	}
}

func TestFreshLogin(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	if !domain.FreshLogin(now.Add(-5*time.Minute), now) || domain.FreshLogin(now.Add(-5*time.Minute-time.Second), now) || domain.FreshLogin(time.Time{}, now) {
		t.Fatal("FreshLogin is wrong")
	}
}
