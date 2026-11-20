// Package secrets is the adapter of the port privatekeys on the secrets
// service of platform-go.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"strings"

	platformsecrets "github.com/techorionai/constellation-platform-go/secrets"

	"github.com/techorionai/constellation-identity/internal/ports/privatekeys"
)

// Store keeps private keys in the secrets service.
type Store struct {
	svc *platformsecrets.Service
}

var _ privatekeys.Store = (*Store)(nil)

// New makes the store.
func New(svc *platformsecrets.Service) *Store { return &Store{svc: svc} }

// Put stores the PEM text under name.
func (s *Store) Put(ctx context.Context, name string, pem []byte) error {
	return s.svc.Put(ctx, name, pem)
}

// Get returns the PEM text. It returns an error that wraps
// privatekeys.ErrNotFound for an unknown name.
func (s *Store) Get(ctx context.Context, name string) ([]byte, error) {
	v, err := s.svc.Get(ctx, name)
	if errors.Is(err, platformsecrets.ErrNotFound) {
		return nil, fmt.Errorf("%s: %w", name, privatekeys.ErrNotFound)
	}
	if errors.Is(err, platformsecrets.ErrDecrypt) || errors.Is(err, platformsecrets.ErrUnknownKey) {
		return nil, fmt.Errorf("%s: %w", name, privatekeys.ErrUndecryptable)
	}
	return v, err
}

// Delete removes a key. An unknown name is not an error.
func (s *Store) Delete(ctx context.Context, name string) error {
	err := s.svc.Delete(ctx, name)
	if errors.Is(err, platformsecrets.ErrNotFound) {
		return nil
	}
	return err
}

// ListNames returns all names that start with prefix.
func (s *Store) ListNames(ctx context.Context, prefix string) ([]string, error) {
	var out []string
	after := prefix
	for {
		page, err := s.svc.List(ctx, platformsecrets.ListParams{After: after, Limit: 100})
		if err != nil {
			return nil, err
		}
		for _, n := range page.Names {
			if !strings.HasPrefix(n, prefix) {
				// The names are in ascending order. No later name has the prefix.
				return out, nil
			}
			out = append(out, n)
		}
		if page.Next == "" {
			return out, nil
		}
		after = page.Next
	}
}
