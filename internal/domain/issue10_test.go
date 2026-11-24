package domain_test

import (
	"strings"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// Issue10_U1: the claims have act only with an actor.
func TestIssue10_U1_ExchangedTokenClaims(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tok := domain.ExchangedToken{
		Issuer: "https://id.example.com", Audience: "mail", UserID: "u", ClientID: "c", Scopes: []string{"mail:a:b", "mail:c:d"},
		Now: now, SubjectExpiresAt: now.Add(time.Hour), JTI: "j",
	}
	c := tok.Claims()
	if _, has := c["act"]; has || c["principal_type"] != "user" || c["sub"] != "u" || c["scope"] != "mail:a:b mail:c:d" {
		t.Fatalf("claims = %v", c)
	}
	tok.Actor = &domain.ActorClaim{Subject: "agent", PrincipalType: domain.PrincipalAgent}
	act, _ := tok.Claims()["act"].(map[string]any)
	if act["sub"] != "agent" || act["principal_type"] != "agent" || len(act) != 2 {
		t.Fatalf("act = %v", act)
	}
}

// Issue10_U2: exp is the lower value of iat plus 5 minutes and the subject exp.
func TestIssue10_U2_ExchangedTokenExpiry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for left, want := range map[time.Duration]time.Duration{
		4 * time.Minute: 4 * time.Minute, 2 * time.Minute: 2 * time.Minute, 10 * time.Second: 10 * time.Second, time.Hour: 5 * time.Minute,
	} {
		tok := domain.ExchangedToken{Now: now, SubjectExpiresAt: now.Add(left)}
		if got := tok.ExpiresAt().Sub(now); got != want {
			t.Errorf("left %v: life = %v, want %v", left, got, want)
		}
	}
}

// Issue10_U13a: the agent name rules.
func TestIssue10_U13a_CheckAgentName(t *testing.T) {
	for in, want := range map[string]string{" a ": "a", strings.Repeat("a", 100): strings.Repeat("a", 100), strings.Repeat("é", 100): strings.Repeat("é", 100)} {
		if got, err := domain.CheckAgentName(in); err != nil || got != want {
			t.Errorf("%q: %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "  ", strings.Repeat("a", 101), "a\x00b", "a\tb", "a\xffb"} {
		if _, err := domain.CheckAgentName(in); err == nil {
			t.Errorf("%q: want an error", in)
		}
	}
}
