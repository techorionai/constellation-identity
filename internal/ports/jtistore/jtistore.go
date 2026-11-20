// Package jtistore is the port of the replay protection of client assertions.
package jtistore

import (
	"context"
	"time"
)

// Store remembers the jti of each assertion that a client used.
type Store interface {
	// Claim records the jti of a client for ttl. It returns true if the jti
	// was not recorded before. It returns false if the jti was used already.
	// An error means the store is not available, and the caller must not
	// accept the assertion.
	Claim(ctx context.Context, clientID, jti string, ttl time.Duration) (first bool, err error)
}
