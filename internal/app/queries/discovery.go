package queries

import (
	"context"
	"strings"

	"github.com/techorionai/constellation-platform-go/executor"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// GetDiscovery is the input of the discovery query.
type GetDiscovery struct{}

// DiscoveryResult is the OIDC discovery document.
type DiscoveryResult struct {
	Issuer                                     string
	AuthorizationEndpoint                      string
	TokenEndpoint                              string
	UserinfoEndpoint                           string
	EndSessionEndpoint                         string
	RevocationEndpoint                         string
	JWKSURI                                    string
	ScopesSupported                            []string
	ResponseTypesSupported                     []string
	SubjectTypesSupported                      []string
	GrantTypesSupported                        []string
	CodeChallengeMethodsSupported              []string
	IDTokenSigningAlgValuesSupported           []string
	TokenEndpointAuthMethodsSupported          []string
	TokenEndpointAuthSigningAlgValuesSupported []string
}

// GetDiscoveryQuery builds the discovery document from the issuer.
type GetDiscoveryQuery struct {
	issuer string
}

var _ executor.ExecutorWithReturn[GetDiscovery, DiscoveryResult] = (*GetDiscoveryQuery)(nil)

// NewGetDiscovery makes the query. issuer is the value of IDENTITY_ISSUER.
func NewGetDiscovery(issuer string) *GetDiscoveryQuery {
	return &GetDiscoveryQuery{issuer: issuer}
}

// Execute returns the discovery document. Later issues add the grant types, the
// method none, and the scopes.
func (q *GetDiscoveryQuery) Execute(context.Context, GetDiscovery) (DiscoveryResult, error) {
	base := strings.TrimSuffix(q.issuer, "/")
	return DiscoveryResult{
		Issuer:                                     q.issuer,
		AuthorizationEndpoint:                      base + "/oauth/authorize",
		TokenEndpoint:                              base + "/oauth/token",
		UserinfoEndpoint:                           base + "/oauth/userinfo",
		EndSessionEndpoint:                         base + "/oauth/end_session",
		RevocationEndpoint:                         base + "/oauth/revoke",
		JWKSURI:                                    base + "/.well-known/jwks.json",
		ScopesSupported:                            []string{},
		ResponseTypesSupported:                     []string{"code"},
		SubjectTypesSupported:                      []string{"public"},
		GrantTypesSupported:                        []string{},
		CodeChallengeMethodsSupported:              []string{"S256"},
		IDTokenSigningAlgValuesSupported:           []string{domain.AlgES256},
		TokenEndpointAuthMethodsSupported:          []string{"private_key_jwt"},
		TokenEndpointAuthSigningAlgValuesSupported: []string{domain.AlgES256},
	}, nil
}
