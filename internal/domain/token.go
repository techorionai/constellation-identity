package domain

import (
	"errors"
	"slices"
	"strings"
	"time"
)

// AccessTokenLifetime is the life of an access token.
const AccessTokenLifetime = 5 * time.Minute

// AccessTokenType is the value of the header member typ (RFC 9068).
const AccessTokenType = "at+jwt"

// PrincipalService is the principal_type of a service client.
const PrincipalService = "service"

// ErrInvalidScope means the requested scopes are not allowed.
var ErrInvalidScope = errors.New("invalid scope")

// GrantScopes checks the requested scopes of a client credentials request. The
// scope is a space-separated list. Each scope must be a permission key of the
// audience app and must be in granted. The result has no duplicates. A request
// with no scope is not valid, because a token must name its scopes.
func GrantScopes(audience, requested string, granted []string) ([]string, error) {
	fields := strings.Fields(requested)
	if len(fields) == 0 {
		return nil, ErrInvalidScope
	}
	var out []string
	for _, s := range fields {
		if !ValidPermissionKey(s) || !strings.HasPrefix(s, audience+":") || !slices.Contains(granted, s) {
			return nil, ErrInvalidScope
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out, nil
}

// ServiceToken is the data of the access token of a service client.
type ServiceToken struct {
	Issuer   string
	Audience string
	ClientID string
	Scopes   []string
	Now      time.Time
	JTI      string
}

// Claims returns the claims of AccessTokenClaims in the contract.
func (t ServiceToken) Claims() map[string]any {
	return map[string]any{
		"iss":            t.Issuer,
		"sub":            t.ClientID,
		"aud":            t.Audience,
		"exp":            t.Now.Add(AccessTokenLifetime).Unix(),
		"iat":            t.Now.Unix(),
		"nbf":            t.Now.Unix(),
		"jti":            t.JTI,
		"client_id":      t.ClientID,
		"scope":          strings.Join(t.Scopes, " "),
		"principal_type": PrincipalService,
	}
}
