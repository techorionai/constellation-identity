package valkey

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/authflow"
	"github.com/techorionai/constellation-identity/internal/ports/mfaflow"
)

// MFAFlow keeps the short-lived records of the second factor in Valkey: the
// pending login, the TOTP setup secret, and the failure counter. It uses SET,
// GET, GETDEL, DEL, and MULTI/EXEC only, because the ACL of the service denies
// scripts.
type MFAFlow struct{ s *Store }

// NewMFAFlow makes the adapter on the store of the code flow.
func NewMFAFlow(s *Store) *MFAFlow { return &MFAFlow{s: s} }

func (m *MFAFlow) pendingKey(h string) string { return m.s.keys.Key("mfa", "pending", h) }
func (m *MFAFlow) attemptKey(h string) string { return m.s.keys.Key("mfa", "pending-attempts", h) }
func (m *MFAFlow) setupKey(h string) string   { return m.s.keys.Key("mfa", "setup", h) }
func (m *MFAFlow) failKey(userID string) string {
	return m.s.keys.Key("mfa", "fail", "user", digest(userID))
}

func notFound(err error) error {
	if errors.Is(err, authflow.ErrNotFound) {
		return fmt.Errorf("not found: %w", mfaflow.ErrNotFound)
	}
	return err
}

// Pending returns the adapter of the port mfaflow.PendingLogins.
func (m *MFAFlow) Pending() PendingStore { return PendingStore{m: m} }

// Setups returns the adapter of the port mfaflow.SetupSecrets.
func (m *MFAFlow) Setups() SetupStore { return SetupStore{m: m} }

// FailureCounter returns the adapter of the port mfaflow.Failures.
func (m *MFAFlow) FailureCounter() FailureStore { return FailureStore{m: m} }

// PendingStore is the adapter of the pending logins.
type PendingStore struct{ m *MFAFlow }

var _ mfaflow.PendingLogins = PendingStore{}

// Put stores a pending login.
func (p PendingStore) Put(ctx context.Context, hash string, v domain.PendingLogin, ttl time.Duration) error {
	return p.m.s.put(ctx, p.m.pendingKey(hash), v, ttl)
}

// Get reads a pending login.
func (p PendingStore) Get(ctx context.Context, hash string) (domain.PendingLogin, error) {
	var v domain.PendingLogin
	err := p.m.s.read(ctx, p.m.pendingKey(hash), false, &v)
	return v, notFound(err)
}

// Take reads and deletes a pending login in one step.
func (p PendingStore) Take(ctx context.Context, hash string) (domain.PendingLogin, error) {
	var v domain.PendingLogin
	err := p.m.s.read(ctx, p.m.pendingKey(hash), true, &v)
	return v, notFound(err)
}

// Delete removes a pending login and its attempt counter.
func (p PendingStore) Delete(ctx context.Context, hash string) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	c := p.m.s.client
	if err := c.Do(ctx, c.B().Del().Key(p.m.pendingKey(hash), p.m.attemptKey(hash)).Build()).Error(); err != nil {
		return fmt.Errorf("delete pending login: %w", err)
	}
	return nil
}

// Attempt adds one attempt in one MULTI/EXEC transaction. EXPIRE with NX sets
// the life at the first attempt only.
func (p PendingStore) Attempt(ctx context.Context, hash string, ttl time.Duration) (int64, error) {
	return incrWithExpiry(ctx, p.m.s, p.m.attemptKey(hash), ttl)
}

func incrWithExpiry(ctx context.Context, s *Store, key string, ttl time.Duration) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	c := s.client
	secs := max(int64(ttl/time.Second), 1)
	res := c.DoMulti(ctx,
		c.B().Multi().Build(),
		c.B().Incr().Key(key).Build(),
		c.B().Expire().Key(key).Seconds(secs).Nx().Build(),
		c.B().Exec().Build())
	for _, r := range res {
		if err := r.Error(); err != nil {
			return 0, fmt.Errorf("count attempt: %w", err)
		}
	}
	replies, err := res[len(res)-1].ToArray()
	if err != nil {
		return 0, fmt.Errorf("count attempt: %w", err)
	}
	if len(replies) != 2 {
		return 0, fmt.Errorf("count attempt: %d replies, want 2", len(replies))
	}
	n, err := replies[0].AsInt64()
	if err != nil {
		return 0, fmt.Errorf("count attempt: %w", err)
	}
	return n, nil
}

// SetupStore is the adapter of the setup secrets. The value is the secret in
// base64 form.
type SetupStore struct{ m *MFAFlow }

var _ mfaflow.SetupSecrets = SetupStore{}

// Put stores the secret.
func (st SetupStore) Put(ctx context.Context, sessionHash string, secret []byte, ttl time.Duration) error {
	return st.m.s.put(ctx, st.m.setupKey(sessionHash), base64.StdEncoding.EncodeToString(secret), ttl)
}

// Get reads the secret.
func (st SetupStore) Get(ctx context.Context, sessionHash string) ([]byte, error) {
	var enc string
	if err := st.m.s.read(ctx, st.m.setupKey(sessionHash), false, &enc); err != nil {
		return nil, notFound(err)
	}
	b, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, fmt.Errorf("decode setup secret: %w", err)
	}
	return b, nil
}

// Delete removes the secret.
func (st SetupStore) Delete(ctx context.Context, sessionHash string) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	c := st.m.s.client
	if err := c.Do(ctx, c.B().Del().Key(st.m.setupKey(sessionHash)).Build()).Error(); err != nil {
		return fmt.Errorf("delete setup secret: %w", err)
	}
	return nil
}

// FailureStore is the adapter of the failure counter.
type FailureStore struct{ m *MFAFlow }

var _ mfaflow.Failures = FailureStore{}

// Reserve adds one attempt.
func (f FailureStore) Reserve(ctx context.Context, userID string, window time.Duration) (int64, error) {
	return incrWithExpiry(ctx, f.m.s, f.m.failKey(userID), window)
}

// Release takes one attempt back. The counter never goes below 0.
func (f FailureStore) Release(ctx context.Context, userID string) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	c := f.m.s.client
	key := f.m.failKey(userID)
	n, err := c.Do(ctx, c.B().Decr().Key(key).Build()).AsInt64()
	if err != nil {
		return fmt.Errorf("release attempt: %w", err)
	}
	if n < 0 {
		// The counter did not exist or expired. DECR made it -1. Delete it.
		if err := c.Do(ctx, c.B().Del().Key(key).Build()).Error(); err != nil {
			return fmt.Errorf("release attempt: %w", err)
		}
	}
	return nil
}
