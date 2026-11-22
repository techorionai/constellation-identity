package domain

import (
	"slices"
	"strings"
	"time"
)

// The OIDC scopes. They are valid in a request only. The access token scope
// has permission keys only.
const (
	ScopeOpenID        = "openid"
	ScopeProfile       = "profile"
	ScopeEmail         = "email"
	ScopeOfflineAccess = "offline_access"
)

// OIDCScopes lists the OIDC scopes that the service supports.
var OIDCScopes = []string{ScopeOpenID, ScopeProfile, ScopeEmail, ScopeOfflineAccess}

// IDTokenType is the header member typ of an ID token. The access token has
// AccessTokenType.
const IDTokenType = "JWT"

// PrincipalUser is the principal_type of a user.
const PrincipalUser = "user"

// DefaultUserTokenLifetime is the default life of the access token and the ID
// token of a user.
const DefaultUserTokenLifetime = 15 * time.Minute

// ScopeRequest is a scope parameter after the service dropped the tokens that
// it does not know.
type ScopeRequest struct {
	// Permissions are the requested permission keys of the client app.
	Permissions []string
	// OIDC are the requested OIDC scopes.
	OIDC []string
}

// ParseAuthorizeScope splits the scope of an authorization request. An OIDC
// scope stays. A permission key of app stays. The function drops each other
// token. If no permission key remains, it returns ErrInvalidScope.
func ParseAuthorizeScope(app, requested string) (ScopeRequest, error) {
	var out ScopeRequest
	for _, s := range strings.Fields(requested) {
		switch {
		case slices.Contains(OIDCScopes, s):
			if !slices.Contains(out.OIDC, s) {
				out.OIDC = append(out.OIDC, s)
			}
		case ValidPermissionKey(s) && strings.HasPrefix(s, app+":"):
			if !slices.Contains(out.Permissions, s) {
				out.Permissions = append(out.Permissions, s)
			}
		}
	}
	if len(out.Permissions) == 0 {
		return ScopeRequest{}, ErrInvalidScope
	}
	return out, nil
}

// IntersectScopes returns the keys of wanted that are in granted, in the order
// of wanted. It returns nil if none remain.
func IntersectScopes(wanted, granted []string) []string {
	var out []string
	for _, s := range wanted {
		if slices.Contains(granted, s) && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// NarrowScope applies the scope parameter of a refresh request (RFC 6749
// section 6). An empty value gives the stored scope. A token that is in neither
// the stored scope nor the stored OIDC scopes gives ErrInvalidScope. An OIDC
// scope (openid, offline_access, email, profile) of the original grant is
// accepted and does not change the result, because a refresh makes no ID token.
// If the request has OIDC scopes only, the result is the stored scope. The
// result is never wider than stored.
func NarrowScope(stored, storedOIDC []string, requested string) ([]string, error) {
	fields := strings.Fields(requested)
	if len(fields) == 0 {
		return stored, nil
	}
	var out []string
	for _, s := range fields {
		if slices.Contains(storedOIDC, s) {
			continue
		}
		if !slices.Contains(stored, s) {
			return nil, ErrInvalidScope
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return stored, nil
	}
	return out, nil
}

// UserAccessToken is the data of the access token of a user.
type UserAccessToken struct {
	Issuer   string
	Audience string
	UserID   string
	ClientID string
	Scopes   []string
	Now      time.Time
	TTL      time.Duration
	JTI      string
}

// Claims returns the claims of AccessTokenClaims in the contract.
func (t UserAccessToken) Claims() map[string]any {
	return map[string]any{
		"iss":            t.Issuer,
		"sub":            t.UserID,
		"aud":            t.Audience,
		"exp":            t.Now.Add(t.TTL).Unix(),
		"iat":            t.Now.Unix(),
		"nbf":            t.Now.Unix(),
		"jti":            t.JTI,
		"client_id":      t.ClientID,
		"scope":          strings.Join(t.Scopes, " "),
		"principal_type": PrincipalUser,
	}
}

// IDToken is the data of an ID token.
type IDToken struct {
	Issuer    string
	UserID    string
	ClientID  string
	AuthTime  time.Time
	Nonce     string
	SessionID string
	Now       time.Time
	TTL       time.Duration
	// Email and Name are set only for the scopes email and profile.
	Email *string
	Name  *string
}

// Claims returns the claims of the ID token.
func (t IDToken) Claims() map[string]any {
	c := map[string]any{
		"iss":       t.Issuer,
		"sub":       t.UserID,
		"aud":       t.ClientID,
		"exp":       t.Now.Add(t.TTL).Unix(),
		"iat":       t.Now.Unix(),
		"auth_time": t.AuthTime.Unix(),
		"nonce":     t.Nonce,
		"sid":       t.SessionID,
	}
	if t.Email != nil {
		c["email"] = *t.Email
		c["email_verified"] = true
	}
	if t.Name != nil {
		c["name"] = *t.Name
	}
	return c
}
