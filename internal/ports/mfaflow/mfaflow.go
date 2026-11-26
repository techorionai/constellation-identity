// Package mfaflow is the port of the short-lived state of the second factor:
// the pending login, the TOTP setup secret, and the failure counter.
package mfaflow

import (
	"context"
	"errors"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// ErrNotFound means the store has no record with the key.
var ErrNotFound = errors.New("record not found")

// PendingLogins stores the pending logins. The key is the hash of the cookie value.
type PendingLogins interface {
	// Put stores the pending login for the time ttl.
	Put(ctx context.Context, hash string, p domain.PendingLogin, ttl time.Duration) error
	// Get reads the pending login. It wraps ErrNotFound.
	Get(ctx context.Context, hash string) (domain.PendingLogin, error)
	// Take reads and deletes the pending login in one step. It wraps ErrNotFound.
	Take(ctx context.Context, hash string) (domain.PendingLogin, error)
	// Delete removes the pending login.
	Delete(ctx context.Context, hash string) error
	// Attempt counts one attempt on the pending login and returns the new count.
	// The counter has the life ttl, set at the first attempt.
	Attempt(ctx context.Context, hash string, ttl time.Duration) (int64, error)
}

// SetupSecrets stores the secret of a TOTP setup that is not done. The key is
// the hash of the session ID.
type SetupSecrets interface {
	// PutIfAbsent stores the secret if the key has no value. It returns false
	// if the key has a value. One step does the check and the write.
	PutIfAbsent(ctx context.Context, sessionHash string, secret []byte, ttl time.Duration) (bool, error)
	// Get reads the secret. It wraps ErrNotFound.
	Get(ctx context.Context, sessionHash string) ([]byte, error)
	Delete(ctx context.Context, sessionHash string) error
}

// Failures counts the failed second factor attempts of a user.
type Failures interface {
	// Reserve adds one attempt and returns the new count. The counter has the
	// life window, set at the first attempt of the window.
	Reserve(ctx context.Context, userID string, window time.Duration) (int64, error)
	// Release takes one attempt back. The count never goes below 0.
	Release(ctx context.Context, userID string) error
}

// The kinds of a WebAuthn ceremony. The kind is part of the key.
const (
	// CeremonyRegister is a registration. The key is the hash of the session ID.
	CeremonyRegister = "reg"
	// CeremonyLogin is a login with no password. The key is the hash of the cookie value.
	CeremonyLogin = "login"
	// CeremonySecondFactor is a second factor. The key is the hash of the cookie value of the pending login.
	CeremonySecondFactor = "mfa"
)

// Ceremonies stores the state of the WebAuthn ceremonies.
type Ceremonies interface {
	// Put stores the state for the time ttl. It replaces an older value.
	Put(ctx context.Context, kind, hash string, c domain.Ceremony, ttl time.Duration) error
	// Take reads and deletes the state in one step. It wraps ErrNotFound.
	Take(ctx context.Context, kind, hash string) (domain.Ceremony, error)
}
