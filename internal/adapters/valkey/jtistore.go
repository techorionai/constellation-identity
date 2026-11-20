// Package valkey holds the Valkey adapters.
package valkey

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"time"

	valkeygo "github.com/valkey-io/valkey-go"

	"github.com/techorionai/constellation-identity/internal/ports/jtistore"
)

// Keyspace makes the keys of the service. clients/valkey of platform-go
// implements it.
type Keyspace interface {
	Key(parts ...string) string
}

// JTIStore is the adapter of the port jtistore on Valkey.
type JTIStore struct {
	client valkeygo.Client
	keys   Keyspace
}

var _ jtistore.Store = (*JTIStore)(nil)

// NewJTIStore makes the store.
func NewJTIStore(client valkeygo.Client, keys Keyspace) *JTIStore {
	return &JTIStore{client: client, keys: keys}
}

// Claim runs SET identity:jti:<sha256(client_id, jti)> 1 NX EX <ttl>. The hash
// keeps the key short and free of input bytes. The separator is a zero byte,
// so two pairs of values never give the same input.
func (s *JTIStore) Claim(ctx context.Context, clientID, jti string, ttl time.Duration) (bool, error) {
	sum := sha256.Sum256([]byte(clientID + "\x00" + jti))
	key := s.keys.Key("jti", hex.EncodeToString(sum[:]))
	seconds := max(int64(math.Ceil(ttl.Seconds())), 1)
	err := s.client.Do(ctx, s.client.B().Set().Key(key).Value("1").Nx().ExSeconds(seconds).Build()).Error()
	if valkeygo.IsValkeyNil(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("record jti: %w", err)
	}
	return true, nil
}
