// Package mock holds in-memory fakes of the ports of the identity service. A
// unit test uses them. A server-side integration test uses live dependencies.
package mock

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/privatekeys"
)

// SigningKeys is an in-memory signing key repository. A function field, when
// set, runs before the real work and can return an error.
type SigningKeys struct {
	mu   sync.Mutex
	rows []domain.SigningKey

	InsertHook      func(domain.SigningKey) error
	UpdateStateHook func(kid string, state domain.KeyState) error
	DeleteHook      func(kid string) error
}

// List returns the keys, the oldest first.
func (r *SigningKeys) List(context.Context) ([]domain.SigningKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := slices.Clone(r.rows)
	slices.SortStableFunc(out, func(a, b domain.SigningKey) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return out, nil
}

// Insert adds a key.
func (r *SigningKeys) Insert(_ context.Context, k domain.SigningKey) error {
	if r.InsertHook != nil {
		if err := r.InsertHook(k); err != nil {
			return err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows = append(r.rows, k)
	return nil
}

// UpdateState sets the state of a key.
func (r *SigningKeys) UpdateState(_ context.Context, kid string, state domain.KeyState, retiredAt *time.Time) error {
	if r.UpdateStateHook != nil {
		if err := r.UpdateStateHook(kid, state); err != nil {
			return err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.rows {
		if r.rows[i].KID == kid {
			r.rows[i].State = state
			r.rows[i].RetiredAt = retiredAt
			return nil
		}
	}
	return fmt.Errorf("signing key %s not found", kid)
}

// Delete removes a key row.
func (r *SigningKeys) Delete(_ context.Context, kid string) error {
	if r.DeleteHook != nil {
		if err := r.DeleteHook(kid); err != nil {
			return err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows = slices.DeleteFunc(r.rows, func(k domain.SigningKey) bool { return k.KID == kid })
	return nil
}

// WithLock runs fn. A test runs one pass at a time, so there is no lock.
func (r *SigningKeys) WithLock(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

// PrivateKeys is an in-memory private key store. A function field, when set,
// runs before the real work and can return an error.
type PrivateKeys struct {
	mu    sync.Mutex
	items map[string][]byte

	PutHook    func(name string) error
	DeleteHook func(name string) error
}

// Put stores a key.
func (s *PrivateKeys) Put(_ context.Context, name string, pem []byte) error {
	if s.PutHook != nil {
		if err := s.PutHook(name); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.items == nil {
		s.items = map[string][]byte{}
	}
	s.items[name] = slices.Clone(pem)
	return nil
}

// Get returns a key.
func (s *PrivateKeys) Get(_ context.Context, name string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.items[name]
	if !ok {
		return nil, fmt.Errorf("%s: %w", name, privatekeys.ErrNotFound)
	}
	return slices.Clone(v), nil
}

// Delete removes a key.
func (s *PrivateKeys) Delete(_ context.Context, name string) error {
	if s.DeleteHook != nil {
		if err := s.DeleteHook(name); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, name)
	return nil
}

// ListNames returns the names with the prefix, in ascending order.
func (s *PrivateKeys) ListNames(_ context.Context, prefix string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for n := range s.items {
		if strings.HasPrefix(n, prefix) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out, nil
}

// Names returns all names, in ascending order.
func (s *PrivateKeys) Names() []string {
	names, _ := s.ListNames(context.Background(), "")
	return names
}
