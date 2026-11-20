package domain_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
)

const testIssuer = "https://id.example.com"

var testNow = time.Unix(1_800_000_000, 0)

func goodClaims() domain.AssertionClaims {
	exp := testNow.Add(time.Minute)
	iat := testNow
	return domain.AssertionClaims{
		Issuer: "helpdesk", Subject: "helpdesk", Audience: []string{testIssuer},
		ExpiresAt: &exp, IssuedAt: &iat, JTI: "jti-1",
	}
}

func at(d time.Duration) *time.Time {
	t := testNow.Add(d)
	return &t
}

// Issue2_U10 and U10a to U10i: the claim rules.
func TestIssue2_AssertionClaimRules(t *testing.T) {
	cases := []struct {
		name   string
		change func(*domain.AssertionClaims)
		ok     bool
	}{
		{"good", func(*domain.AssertionClaims) {}, true},
		{"U10 lifetime of 10 minutes", func(c *domain.AssertionClaims) { c.ExpiresAt = at(10 * time.Minute) }, false},
		{"lifetime of 5 minutes", func(c *domain.AssertionClaims) { c.ExpiresAt = at(5 * time.Minute) }, true},
		{"U10a exp 60 seconds in the past", func(c *domain.AssertionClaims) { c.ExpiresAt = at(-60 * time.Second) }, false},
		{"exp inside the leeway", func(c *domain.AssertionClaims) { c.ExpiresAt = at(-10 * time.Second) }, true},
		{"exp missing", func(c *domain.AssertionClaims) { c.ExpiresAt = nil }, false},
		{"U10b iat 2 minutes in the future", func(c *domain.AssertionClaims) { c.IssuedAt = at(2 * time.Minute) }, false},
		{"iat missing", func(c *domain.AssertionClaims) { c.IssuedAt = nil }, false},
		{"U10c nbf 2 minutes in the future", func(c *domain.AssertionClaims) { c.NotBefore = at(2 * time.Minute) }, false},
		{"nbf in the past", func(c *domain.AssertionClaims) { c.NotBefore = at(-time.Minute) }, true},
		{"U10f iss is not sub", func(c *domain.AssertionClaims) { c.Issuer = "other" }, false},
		{"empty sub", func(c *domain.AssertionClaims) { c.Issuer, c.Subject = "", "" }, false},
		{"U10h jti of 257 characters", func(c *domain.AssertionClaims) { c.JTI = strings.Repeat("a", 257) }, false},
		{"jti of 256 characters", func(c *domain.AssertionClaims) { c.JTI = strings.Repeat("a", 256) }, true},
		{"jti missing", func(c *domain.AssertionClaims) { c.JTI = "" }, false},
		{"U10i aud is the token endpoint", func(c *domain.AssertionClaims) { c.Audience = []string{testIssuer + "/oauth/token"} }, false},
		{"U10i aud is another URL", func(c *domain.AssertionClaims) { c.Audience = []string{"https://other.example.com"} }, false},
		{"U10i aud array with the issuer", func(c *domain.AssertionClaims) { c.Audience = []string{"https://other.example.com", testIssuer} }, true},
		{"aud missing", func(c *domain.AssertionClaims) { c.Audience = nil }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			claims := goodClaims()
			c.change(&claims)
			err := claims.Check(testIssuer, testNow)
			if c.ok && err != nil {
				t.Fatalf("error = %v", err)
			}
			if !c.ok && !errors.Is(err, domain.ErrInvalidAssertion) {
				t.Fatalf("error = %v, want ErrInvalidAssertion", err)
			}
		})
	}
}

// Issue2_U10j: the replay TTL.
func TestIssue2_U10j_ReplayTTL(t *testing.T) {
	if got := domain.ReplayTTL(testNow.Add(5*time.Second), testNow); got != 35*time.Second {
		t.Fatalf("ttl = %s, want 35s", got)
	}
	if got := domain.ReplayTTL(testNow.Add(-10*time.Second), testNow); got != 30*time.Second {
		t.Fatalf("ttl = %s, want 30s", got)
	}
}
