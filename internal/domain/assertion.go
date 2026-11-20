package domain

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

// The rules of a client assertion.
const (
	// AssertionLeeway is the clock skew that the time claims allow.
	AssertionLeeway = 30 * time.Second
	// MaxAssertionLifetime is the largest difference between exp and iat.
	MaxAssertionLifetime = 5 * time.Minute
	// MaxJTILength is the largest length of the jti claim.
	MaxJTILength = 256
	// AssertionType is the value of client_assertion_type.
	AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

// ErrInvalidAssertion means the claims of an assertion fail a rule. The text
// is for the log. It never goes to the client.
var ErrInvalidAssertion = errors.New("invalid client assertion")

// AssertionClaims are the claims of a client assertion that was verified with
// a key of the client.
type AssertionClaims struct {
	Issuer    string
	Subject   string
	Audience  []string
	ExpiresAt *time.Time
	IssuedAt  *time.Time
	NotBefore *time.Time
	JTI       string
}

// Check applies the claim rules at the time now. issuer is the issuer URL of
// the service. It is the only audience that the service accepts.
func (c AssertionClaims) Check(issuer string, now time.Time) error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidAssertion, fmt.Sprintf(format, args...))
	}
	switch {
	case c.Subject == "" || c.Issuer != c.Subject:
		return bad("iss is not equal to sub")
	case !slices.Contains(c.Audience, issuer):
		return bad("aud is not the issuer")
	case c.ExpiresAt == nil:
		return bad("exp is missing")
	case !c.ExpiresAt.After(now.Add(-AssertionLeeway)):
		return bad("the assertion expired")
	case c.IssuedAt == nil:
		return bad("iat is missing")
	case c.IssuedAt.After(now.Add(AssertionLeeway)):
		return bad("iat is in the future")
	case c.ExpiresAt.Sub(*c.IssuedAt) > MaxAssertionLifetime:
		return bad("the lifetime is more than %s", MaxAssertionLifetime)
	case c.NotBefore != nil && c.NotBefore.After(now.Add(AssertionLeeway)):
		return bad("nbf is in the future")
	case c.JTI == "":
		return bad("jti is missing")
	case len(c.JTI) > MaxJTILength:
		return bad("jti is too long")
	}
	return nil
}

// ReplayTTL returns the time that the service must remember the jti of an
// assertion: the time to the expiry plus the leeway, and at least the leeway.
func ReplayTTL(exp, now time.Time) time.Duration {
	return max(exp.Sub(now)+AssertionLeeway, AssertionLeeway)
}
