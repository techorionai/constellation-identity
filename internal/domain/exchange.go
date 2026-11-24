package domain

import (
	"strings"
	"time"
)

// The URIs of the grant type and the token types of the token exchange. They
// are public names, not credentials.
//
//nolint:gosec // G101 matches the word token in the names.
const (
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	TokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeAgentID       = "urn:constellation:params:oauth:token-type:agent-id"
)

const (
	// ExchangedTokenLifetime is the longest life of an exchanged token.
	ExchangedTokenLifetime = 5 * time.Minute
	// MinSubjectTokenLife is the shortest remaining life of a subject token.
	MinSubjectTokenLife = 10 * time.Second
)

// ActorClaim is the act claim of an exchanged token.
type ActorClaim struct {
	Subject       string
	PrincipalType string
}

// ExchangedToken is the data of an access token that the token exchange made.
// The subject is the user. Actor is the agent, or nil.
type ExchangedToken struct {
	Issuer   string
	Audience string
	UserID   string
	ClientID string
	Scopes   []string
	Actor    *ActorClaim
	Now      time.Time
	// SubjectExpiresAt is the exp of the subject token.
	SubjectExpiresAt time.Time
	JTI              string
}

// ExpiresAt is the lower value of Now plus ExchangedTokenLifetime and the exp
// of the subject token.
func (t ExchangedToken) ExpiresAt() time.Time {
	exp := t.Now.Add(ExchangedTokenLifetime)
	if t.SubjectExpiresAt.Before(exp) {
		exp = t.SubjectExpiresAt
	}
	return exp
}

// Claims returns the claims of AccessTokenClaims in the contract.
func (t ExchangedToken) Claims() map[string]any {
	c := map[string]any{
		"iss":            t.Issuer,
		"sub":            t.UserID,
		"aud":            t.Audience,
		"exp":            t.ExpiresAt().Unix(),
		"iat":            t.Now.Unix(),
		"nbf":            t.Now.Unix(),
		"jti":            t.JTI,
		"client_id":      t.ClientID,
		"scope":          strings.Join(t.Scopes, " "),
		"principal_type": PrincipalUser,
	}
	if t.Actor != nil {
		c["act"] = map[string]any{"sub": t.Actor.Subject, "principal_type": t.Actor.PrincipalType}
	}
	return c
}
