package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/techorionai/constellation-identity/internal/ports/jtistore"
)

// cleanupBatch is the largest number of expired rows that one Claim deletes.
const cleanupBatch = 100

// JTIStore is the adapter of the port jtistore on PostgreSQL.
type JTIStore struct {
	pool *pgxpool.Pool
}

var _ jtistore.Store = (*JTIStore)(nil)

// NewJTIStore makes the store.
func NewJTIStore(pool *pgxpool.Pool) *JTIStore { return &JTIStore{pool: pool} }

// Claim deletes up to 100 expired rows, then inserts the key of the jti with
// ON CONFLICT DO NOTHING. 0 inserted rows mean that the jti was used before.
// The key is the hex SHA-256 of the client ID, a zero byte, and the jti. The
// zero byte means that two pairs of values never give the same input. The
// time comes from the database clock.
func (s *JTIStore) Claim(ctx context.Context, clientID, jti string, ttl time.Duration) (bool, error) {
	sum := sha256.Sum256([]byte(clientID + "\x00" + jti))
	key := hex.EncodeToString(sum[:])
	seconds := max(int64(math.Ceil(ttl.Seconds())), 1)

	// A failure of the cleanup or of the insert is a store failure.
	if _, err := s.pool.Exec(ctx, `
		DELETE FROM client_assertion_jtis WHERE key IN (
			SELECT key FROM client_assertion_jtis
			WHERE expires_at < now() LIMIT $1 FOR UPDATE SKIP LOCKED)`, cleanupBatch); err != nil {
		return false, fmt.Errorf("delete expired jti: %w", err)
	}
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO client_assertion_jtis (key, expires_at)
		VALUES ($1, now() + $2::bigint * interval '1 second')
		ON CONFLICT (key) DO NOTHING`, key, seconds)
	if err != nil {
		return false, fmt.Errorf("record jti: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
