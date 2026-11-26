package domain_test

import (
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// Issue20_U1: a service token with an app has the claim app. The other claims
// do not change.
func TestIssue20_U1_ServiceTokenApp(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	c := domain.ServiceToken{Issuer: "https://id", Audience: "demo", ClientID: "svc", App: "helpdesk", Scopes: []string{"demo:a:b"}, Now: now, JTI: "j"}.Claims()
	if c["app"] != "helpdesk" || c["sub"] != "svc" || c["client_id"] != "svc" || c["aud"] != "demo" ||
		c["principal_type"] != "service" || c["scope"] != "demo:a:b" || len(c) != 11 {
		t.Fatalf("claims = %v", c)
	}
}

// Issue20_U2: a service token with no app has no key app.
func TestIssue20_U2_ServiceTokenNoApp(t *testing.T) {
	c := domain.ServiceToken{Issuer: "https://id", Audience: "demo", ClientID: "svc", Now: time.Unix(1_800_000_000, 0), JTI: "j"}.Claims()
	if _, ok := c["app"]; ok {
		t.Fatalf("claims = %v", c)
	}
}

// Issue20_U5: the exchange token and the user token have no claim app.
func TestIssue20_U5_OtherTokensNoApp(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	ex := domain.ExchangedToken{Issuer: "https://id", Audience: "mail", UserID: "u", ClientID: "c", Now: now, SubjectExpiresAt: now.Add(time.Hour), JTI: "j"}
	withActor := ex
	withActor.Actor = &domain.ActorClaim{Subject: "agent", PrincipalType: domain.PrincipalAgent}
	user := domain.UserAccessToken{Issuer: "https://id", Audience: "demo", UserID: "u", ClientID: "c", Now: now, TTL: time.Minute, JTI: "j"}
	for name, c := range map[string]map[string]any{"exchange": ex.Claims(), "exchange with actor": withActor.Claims(), "user": user.Claims()} {
		if _, ok := c["app"]; ok {
			t.Fatalf("%s claims = %v", name, c)
		}
	}
}
