package domain

import "time"

// RefreshFamily is the chain of the refresh tokens of one code flow.
type RefreshFamily struct {
	ID         string
	SessionID  string
	ClientID   string
	UserID     string
	Scope      []string
	OIDCScopes []string
	CreatedAt  time.Time
	RevokedAt  *time.Time
	// AuthTime and AuthMethods are the values of the code flow that made the
	// family. A refresh keeps them. A family from before the upgrade has a zero
	// AuthTime and no methods.
	AuthTime    time.Time
	AuthMethods []string
	// UpstreamAuthValid is the flag of the session at the time of the code flow.
	// It stays inside the service (P24).
	UpstreamAuthValid bool
}

// RefreshToken is one refresh token. The service stores the hash only.
type RefreshToken struct {
	Hash      string
	FamilyID  string
	CreatedAt time.Time
	UsedAt    *time.Time
	ExpiresAt time.Time
}

// AuthRequest is the state of an authorization request between the first
// request and the code. The store holds it for a short time.
type AuthRequest struct {
	ClientID           string    `json:"client_id"`
	RedirectURI        string    `json:"redirect_uri"`
	Scope              []string  `json:"scope"`
	OIDCScopes         []string  `json:"oidc_scopes"`
	State              string    `json:"state"`
	Nonce              string    `json:"nonce"`
	CodeChallenge      string    `json:"code_challenge"`
	CreatedAt          time.Time `json:"created_at"`
	FreshLoginRequired bool      `json:"fresh_login_required"`
}

// AuthCode is the record of an authorization code.
type AuthCode struct {
	ClientID      string    `json:"client_id"`
	RedirectURI   string    `json:"redirect_uri"`
	CodeChallenge string    `json:"code_challenge"`
	Nonce         string    `json:"nonce"`
	SessionID     string    `json:"session_id"`
	UserID        string    `json:"user_id"`
	Scope         []string  `json:"scope"`
	OIDCScopes    []string  `json:"oidc_scopes"`
	AuthTime      time.Time `json:"auth_time"`
	AuthMethods   []string  `json:"auth_methods,omitempty"`
	// UpstreamAuthValid is the flag of the session. It stays inside the service.
	UpstreamAuthValid bool `json:"upstream_auth_valid,omitempty"`
}

// UsedCode is the marker of a code that a client used. It has the data that
// the reuse check needs.
type UsedCode struct {
	SessionID     string `json:"session_id"`
	CodeChallenge string `json:"code_challenge"`
	ClientID      string `json:"client_id"`
}

// ReuseRevokes reports whether a request for a used code must revoke the
// session. The request must have the client ID of the marker, and a
// code_verifier that matches the code challenge of the marker.
func (u UsedCode) ReuseRevokes(clientID, verifier string) bool {
	return clientID == u.ClientID && VerifyPKCE(u.CodeChallenge, verifier)
}
