package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	clientpg "github.com/techorionai/constellation-platform-go/clients/postgres"
	"github.com/techorionai/constellation-platform-go/transaction"
	txpg "github.com/techorionai/constellation-platform-go/transaction/postgres"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/signingkeys"
)

// SigningKeys is the PostgreSQL repository of the signing keys.
type SigningKeys struct {
	pool *pgxpool.Pool
}

var _ signingkeys.Repository = (*SigningKeys)(nil)

// NewSigningKeys makes the repository.
func NewSigningKeys(pool *pgxpool.Pool) *SigningKeys { return &SigningKeys{pool: pool} }

// List returns all keys, the oldest first.
func (r *SigningKeys) List(ctx context.Context) ([]domain.SigningKey, error) {
	rows, err := clientpg.Conn(ctx, r.pool).Query(ctx, `
		SELECT kid, alg, public_jwk, private_key_name, state, created_at, activates_at, retired_at
		FROM signing_keys ORDER BY created_at, kid`)
	if err != nil {
		return nil, fmt.Errorf("list signing keys: %w", err)
	}
	defer rows.Close()
	var keys []domain.SigningKey
	for rows.Next() {
		var (
			k     domain.SigningKey
			jwk   []byte
			state string
		)
		if err := rows.Scan(&k.KID, &k.Alg, &jwk, &k.PrivateKeyName, &state, &k.CreatedAt, &k.ActivatesAt, &k.RetiredAt); err != nil {
			return nil, fmt.Errorf("scan signing key: %w", err)
		}
		if err := json.Unmarshal(jwk, &k.PublicJWK); err != nil {
			return nil, fmt.Errorf("decode public key of %s: %w", k.KID, err)
		}
		k.State = domain.KeyState(state)
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list signing keys: %w", err)
	}
	return keys, nil
}

// Insert adds a key.
func (r *SigningKeys) Insert(ctx context.Context, k domain.SigningKey) error {
	jwk, err := json.Marshal(k.PublicJWK)
	if err != nil {
		return fmt.Errorf("encode public key: %w", err)
	}
	_, err = clientpg.Conn(ctx, r.pool).Exec(ctx, `
		INSERT INTO signing_keys (kid, alg, public_jwk, private_key_name, state, created_at, activates_at, retired_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		k.KID, k.Alg, jwk, k.PrivateKeyName, string(k.State), k.CreatedAt, k.ActivatesAt, k.RetiredAt)
	if err != nil {
		return fmt.Errorf("insert signing key: %w", err)
	}
	return nil
}

// UpdateState sets the state of a key.
func (r *SigningKeys) UpdateState(ctx context.Context, kid string, state domain.KeyState, retiredAt *time.Time) error {
	_, err := clientpg.Conn(ctx, r.pool).Exec(ctx,
		`UPDATE signing_keys SET state = $2, retired_at = $3 WHERE kid = $1`,
		kid, string(state), retiredAt)
	if err != nil {
		return fmt.Errorf("update signing key: %w", err)
	}
	return nil
}

// Activate retires the keys in retire, then makes the key kid active. It is
// one transaction. The order matters: the unique index allows one active key.
func (r *SigningKeys) Activate(ctx context.Context, kid string, retire []string, retiredAt time.Time) error {
	tx := txpg.NewTransactor(r.pool)
	return tx.WithinTx(ctx, func(ctx context.Context) error {
		for _, old := range retire {
			if err := r.UpdateState(ctx, old, domain.KeyRetired, &retiredAt); err != nil {
				return err
			}
		}
		return r.UpdateState(ctx, kid, domain.KeyActive, nil)
	}, transaction.Name("activate_signing_key"))
}

// Delete removes a key row.
func (r *SigningKeys) Delete(ctx context.Context, kid string) error {
	_, err := clientpg.Conn(ctx, r.pool).Exec(ctx, `DELETE FROM signing_keys WHERE kid = $1`, kid)
	if err != nil {
		return fmt.Errorf("delete signing key: %w", err)
	}
	return nil
}

// WithLock runs fn while this instance holds the advisory lock of the key
// manager.
func (r *SigningKeys) WithLock(ctx context.Context, fn func(ctx context.Context) error) error {
	return withAdvisoryLock(ctx, r.pool, keyManagerLock, fn)
}
