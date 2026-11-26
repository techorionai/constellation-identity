package valkey

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/authflow"
	"github.com/techorionai/constellation-identity/internal/ports/idpflow"
)

// IdpFlow keeps the records of the upstream flows in Valkey. The key is
// idp:flow:<hash of the state>. It uses SET and GETDEL only.
type IdpFlow struct{ s *Store }

var _ idpflow.Store = (*IdpFlow)(nil)

// NewIdpFlow makes the adapter on the store of the code flow.
func NewIdpFlow(s *Store) *IdpFlow { return &IdpFlow{s: s} }

func (f *IdpFlow) key(hash string) string { return f.s.keys.Key("idp", "flow", hash) }

// Put stores a flow record.
func (f *IdpFlow) Put(ctx context.Context, hash string, rec domain.IdpFlow, ttl time.Duration) error {
	return f.s.put(ctx, f.key(hash), rec, ttl)
}

// Take reads and deletes a flow record in one step.
func (f *IdpFlow) Take(ctx context.Context, hash string) (domain.IdpFlow, error) {
	var rec domain.IdpFlow
	err := f.s.read(ctx, f.key(hash), true, &rec)
	if errors.Is(err, authflow.ErrNotFound) {
		return domain.IdpFlow{}, fmt.Errorf("not found: %w", idpflow.ErrNotFound)
	}
	return rec, err
}
