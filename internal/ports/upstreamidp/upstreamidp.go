// Package upstreamidp is the port of the upstream OIDC providers.
package upstreamidp

import (
	"context"
	"errors"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// Errors of the client.
var (
	// ErrProvider means the provider did not answer, or answered with an error.
	ErrProvider = errors.New("the provider failed")
	// ErrToken means the ID token of the provider breaks a rule.
	ErrToken = errors.New("the ID token is not valid")
)

// AuthParams are the values of an authorization request.
type AuthParams struct {
	State    string
	Nonce    string
	Verifier string
	// Fresh asks the provider for a fresh login.
	Fresh bool
}

// ExchangeParams are the values of the callback.
type ExchangeParams struct {
	Code     string
	Verifier string
	Nonce    string
	// Iss is the iss parameter of the response, or empty.
	Iss string
}

// Client talks to the upstream providers. All calls use the deadline of ctx.
type Client interface {
	// Enabled reports whether the provider is on.
	Enabled(provider string) bool
	// AuthCodeURL returns the URL of the authorization request. It reads the
	// discovery document. An error wraps ErrProvider.
	AuthCodeURL(ctx context.Context, provider string, p AuthParams) (string, error)
	// Exchange trades the code for the ID token and checks the token. An error
	// wraps ErrProvider (the provider failed) or ErrToken (a rule broke). It
	// never returns an access token or a refresh token.
	Exchange(ctx context.Context, provider string, p ExchangeParams) (domain.UpstreamIdentity, error)
}
