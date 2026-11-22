// Package authflow is the port of the short-lived state of the authorization
// code flow: auth requests, codes, and used-code markers.
package authflow

import (
	"context"
	"errors"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// ErrNotFound means the store has no record with the key.
var ErrNotFound = errors.New("record not found")

// AuthRequests stores the auth requests.
type AuthRequests interface {
	// Put stores the request under the ID for the time ttl.
	Put(ctx context.Context, id string, r domain.AuthRequest, ttl time.Duration) error
	// Get reads the request. It wraps ErrNotFound if it does not exist.
	Get(ctx context.Context, id string) (domain.AuthRequest, error)
	// Take reads and deletes the request in one step (GETDEL). It wraps
	// ErrNotFound if it does not exist.
	Take(ctx context.Context, id string) (domain.AuthRequest, error)
}

// Codes stores the authorization codes. The key is the hash of the code.
type Codes interface {
	// Put stores the code record for the time ttl.
	Put(ctx context.Context, hash string, c domain.AuthCode, ttl time.Duration) error
	// Peek reads the record and does not delete it. It wraps ErrNotFound.
	Peek(ctx context.Context, hash string) (domain.AuthCode, error)
	// Claim reads and deletes the record in one step. It wraps ErrNotFound.
	Claim(ctx context.Context, hash string) (domain.AuthCode, error)
	// MarkUsed stores the used-code marker for the time ttl.
	MarkUsed(ctx context.Context, hash string, m domain.UsedCode, ttl time.Duration) error
	// GetUsed reads the used-code marker. It wraps ErrNotFound.
	GetUsed(ctx context.Context, hash string) (domain.UsedCode, error)
}
