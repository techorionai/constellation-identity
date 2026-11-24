package domain

import (
	"encoding/base64"
	"slices"
	"strings"
	"time"
)

// The rules of a personal API token.
const (
	// APITokenPrefix starts each API token.
	APITokenPrefix = "cpat_"
	// APITokenSecretLength is the number of base64url characters after the prefix
	// (32 random bytes).
	APITokenSecretLength = 43
	// MaxAPITokenNameLength is the longest name of a token.
	MaxAPITokenNameLength = 100
	// MaxIntrospectTokenBytes is the longest token value that the introspection
	// reads. A longer value is not active.
	MaxIntrospectTokenBytes = 512
	// APITokenTotalFactor times the limit of active tokens is the limit of all
	// rows of a user (active, expired, and revoked).
	APITokenTotalFactor = 10
	// APITokenTouchInterval is the minimum time between two updates of the last
	// used time of a token.
	APITokenTouchInterval = time.Hour
	// IntrospectedAPIToken is the token_type of an introspected API token.
	IntrospectedAPIToken = "api_token"
)

// UserRole is the implicit role of each user with the status active.
var UserRole = RoleRef{App: IdentityApp, Role: "user"}

// ImplicitUserRoles gives the implicit roles of a user. Only a user with the
// status active has them.
func ImplicitUserRoles(status UserStatus) []RoleRef {
	if status != UserActive {
		return nil
	}
	return []RoleRef{UserRole}
}

// APIToken is the stored record of a personal API token. The token value is
// never stored. The record has the SHA-256 hash.
type APIToken struct {
	ID         string
	UserID     string
	Name       string
	Scope      []string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// APITokenWithOwner is a token with the status of its user.
type APITokenWithOwner struct {
	APIToken
	OwnerStatus UserStatus
}

// NewAPIToken makes a random token value and the hash that the service stores.
func NewAPIToken() (value, hash string, err error) {
	secret, _, err := NewSecret()
	if err != nil {
		return "", "", err
	}
	value = APITokenPrefix + secret
	return value, HashSecret(value), nil
}

// ParseAPIToken checks the strict format of an API token: the prefix cpat_ and
// 43 base64url characters that decode to 32 bytes. It returns the hash. A value
// of another format gives false.
func ParseAPIToken(s string) (hash string, ok bool) {
	secret, found := strings.CutPrefix(s, APITokenPrefix)
	if !found || len(secret) != APITokenSecretLength {
		return "", false
	}
	if b, err := base64.RawURLEncoding.Strict().DecodeString(secret); err != nil || len(b) != 32 {
		return "", false
	}
	return HashSecret(s), true
}

// IsOIDCScope reports whether s is an OIDC scope value.
func IsOIDCScope(s string) bool { return slices.Contains(OIDCScopes, s) }

// EffectiveAPIScopes returns the keys of stored that are in granted and that
// have the prefix of the caller app. A key of the app identity is never in the
// result, also if the caller app is identity (defense in depth). The order of
// stored stays. A nil result means that the token has no scope for the caller.
func EffectiveAPIScopes(stored, granted []string, callerApp string) []string {
	if callerApp == IdentityApp {
		return nil
	}
	var out []string
	for _, s := range stored {
		if strings.HasPrefix(s, callerApp+":") && !strings.HasPrefix(s, IdentityApp+":") &&
			slices.Contains(granted, s) && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}
