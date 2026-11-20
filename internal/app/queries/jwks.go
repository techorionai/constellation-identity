// Package queries holds the read use cases.
package queries

import (
	"context"

	"github.com/techorionai/constellation-platform-go/executor"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// KeySource gives the public signing keys.
type KeySource interface {
	JWKS() []domain.PublicJWK
}

// GetJWKS is the input of the JWKS query.
type GetJWKS struct{}

// GetJWKSResult is the key set.
type GetJWKSResult struct {
	Keys []domain.PublicJWK
}

// GetJWKSQuery returns the public keys: pending, active, and retired.
type GetJWKSQuery struct {
	source KeySource
}

var _ executor.ExecutorWithReturn[GetJWKS, GetJWKSResult] = (*GetJWKSQuery)(nil)

// NewGetJWKS makes the query.
func NewGetJWKS(source KeySource) *GetJWKSQuery { return &GetJWKSQuery{source: source} }

// Execute returns the key set.
func (q *GetJWKSQuery) Execute(context.Context, GetJWKS) (GetJWKSResult, error) {
	return GetJWKSResult{Keys: q.source.JWKS()}, nil
}
