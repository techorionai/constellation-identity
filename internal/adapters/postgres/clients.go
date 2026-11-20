package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/clients"
)

// Clients is the PostgreSQL repository of the OAuth clients.
type Clients struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

var _ clients.Repository = (*Clients)(nil)

// NewClients makes the repository.
func NewClients(pool *pgxpool.Pool) *Clients { return &Clients{pool: pool, now: time.Now} }

// UpsertConfig adds or updates a client of the clients file and replaces its
// keys, in one transaction.
func (r *Clients) UpsertConfig(ctx context.Context, c domain.ClientConfig) (bool, error) {
	now := r.now().UTC()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `
		INSERT INTO clients (id, type, app, name, disabled, source, created_at, updated_at)
		VALUES ($1, $2, $3, $4, false, 'config', $5, $5)
		ON CONFLICT (id) DO UPDATE
		SET type = EXCLUDED.type, app = EXCLUDED.app, name = EXCLUDED.name,
		    disabled = false, updated_at = EXCLUDED.updated_at
		WHERE clients.source = 'config'`,
		c.Client.ID, string(c.Client.Type), c.Client.App, c.Client.Name, now)
	if err != nil {
		return false, fmt.Errorf("upsert client %s: %w", c.Client.ID, err)
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}

	kids := make([]string, 0, len(c.Keys))
	for _, k := range c.Keys {
		jwk, err := json.Marshal(k.PublicJWK)
		if err != nil {
			return false, fmt.Errorf("encode key %s: %w", k.KID, err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO client_keys (client_id, kid, public_jwk, created_at)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (client_id, kid) DO UPDATE SET public_jwk = EXCLUDED.public_jwk`,
			c.Client.ID, k.KID, jwk, now); err != nil {
			return false, fmt.Errorf("upsert key %s: %w", k.KID, err)
		}
		kids = append(kids, k.KID)
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM client_keys WHERE client_id = $1 AND NOT (kid = ANY($2))`,
		c.Client.ID, kids); err != nil {
		return false, fmt.Errorf("delete old keys of %s: %w", c.Client.ID, err)
	}
	// Replace the assignments of the file. An assignment with source api stays.
	if _, err := tx.Exec(ctx,
		`DELETE FROM client_roles WHERE client_id = $1 AND source = 'config'`, c.Client.ID); err != nil {
		return false, fmt.Errorf("delete old roles of %s: %w", c.Client.ID, err)
	}
	for _, ref := range c.Roles {
		if _, err := tx.Exec(ctx, `
			INSERT INTO client_roles (client_id, app, role, source) VALUES ($1, $2, $3, 'config')
			ON CONFLICT (client_id, app, role) DO NOTHING`, c.Client.ID, ref.App, ref.Role); err != nil {
			return false, fmt.Errorf("insert role %s of %s: %w", ref, c.Client.ID, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit: %w", err)
	}
	return true, nil
}

// DisableConfigNotIn disables each config client that is not in ids.
func (r *Clients) DisableConfigNotIn(ctx context.Context, ids []string) ([]string, error) {
	if ids == nil {
		ids = []string{}
	}
	rows, err := r.pool.Query(ctx, `
		UPDATE clients SET disabled = true, updated_at = $2
		WHERE source = 'config' AND NOT disabled AND NOT (id = ANY($1))
		RETURNING id`, ids, r.now().UTC())
	if err != nil {
		return nil, fmt.Errorf("disable clients: %w", err)
	}
	defer rows.Close()
	var changed []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan client id: %w", err)
		}
		changed = append(changed, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("disable clients: %w", err)
	}
	return changed, nil
}

// Get returns a client.
func (r *Clients) Get(ctx context.Context, id string) (domain.Client, error) {
	var (
		c        domain.Client
		typ, src string
	)
	err := r.pool.QueryRow(ctx, `
		SELECT id, type, app, name, disabled, source, created_at, updated_at
		FROM clients WHERE id = $1`, id).
		Scan(&c.ID, &typ, &c.App, &c.Name, &c.Disabled, &src, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Client{}, fmt.Errorf("client %s: %w", id, clients.ErrNotFound)
	}
	if err != nil {
		return domain.Client{}, fmt.Errorf("get client: %w", err)
	}
	c.Type = domain.ClientType(typ)
	c.Source = domain.ClientSource(src)
	return c, nil
}

// Keys returns the public keys of a client.
func (r *Clients) Keys(ctx context.Context, id string) ([]domain.ClientKey, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT client_id, kid, public_jwk, created_at
		FROM client_keys WHERE client_id = $1 ORDER BY kid`, id)
	if err != nil {
		return nil, fmt.Errorf("list client keys: %w", err)
	}
	defer rows.Close()
	var keys []domain.ClientKey
	for rows.Next() {
		var (
			k   domain.ClientKey
			jwk []byte
		)
		if err := rows.Scan(&k.ClientID, &k.KID, &jwk, &k.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan client key: %w", err)
		}
		if err := json.Unmarshal(jwk, &k.PublicJWK); err != nil {
			return nil, fmt.Errorf("decode client key %s: %w", k.KID, err)
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list client keys: %w", err)
	}
	return keys, nil
}

// WithLock runs fn while this instance holds the advisory lock of the clients
// sync.
func (r *Clients) WithLock(ctx context.Context, fn func(ctx context.Context) error) error {
	return withAdvisoryLock(ctx, r.pool, clientsSyncLock, fn)
}
