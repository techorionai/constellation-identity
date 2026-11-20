package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/manifests"
)

// Manifests is the PostgreSQL repository of the manifests, the permissions,
// and the roles.
type Manifests struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

var _ manifests.Repository = (*Manifests)(nil)

// NewManifests makes the repository.
func NewManifests(pool *pgxpool.Pool) *Manifests { return &Manifests{pool: pool, now: time.Now} }

// querier is the read part of a pool and of a transaction.
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Publish stores a manifest in one transaction. The transaction inserts the
// apps row if it does not exist, then locks it. A second publish of the same
// app waits for the lock and sees the result of the first one.
func (r *Manifests) Publish(ctx context.Context, m domain.Manifest, publishedBy string) (domain.PublishedManifest, error) {
	hash := m.Hash()
	now := r.now().UTC()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return domain.PublishedManifest{}, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// A row with version 0 is a placeholder. It is visible only in this
	// transaction, because the transaction either replaces it or rolls back.
	if _, err := tx.Exec(ctx, `
		INSERT INTO apps (key, manifest_version, manifest_hash, published_at, published_by)
		VALUES ($1, 0, '', $2, $3) ON CONFLICT (key) DO NOTHING`, m.App, now, publishedBy); err != nil {
		return domain.PublishedManifest{}, fmt.Errorf("insert app: %w", err)
	}
	var (
		version int
		stored  string
	)
	if err := tx.QueryRow(ctx,
		`SELECT manifest_version, manifest_hash FROM apps WHERE key = $1 FOR UPDATE`, m.App).
		Scan(&version, &stored); err != nil {
		return domain.PublishedManifest{}, fmt.Errorf("lock app: %w", err)
	}
	if version > 0 && stored == hash {
		return loadManifest(ctx, tx, m.App)
	}

	// Replace the permissions and the roles. The foreign keys delete the role
	// permissions. No statement touches client_roles.
	for _, q := range []string{`DELETE FROM roles WHERE app = $1`, `DELETE FROM permissions WHERE app = $1`} {
		if _, err := tx.Exec(ctx, q, m.App); err != nil {
			return domain.PublishedManifest{}, fmt.Errorf("delete old manifest: %w", err)
		}
	}
	for _, p := range m.Permissions {
		if _, err := tx.Exec(ctx,
			`INSERT INTO permissions (key, app, description) VALUES ($1, $2, $3)`,
			p.Key, m.App, p.Description); err != nil {
			return domain.PublishedManifest{}, fmt.Errorf("insert permission %s: %w", p.Key, err)
		}
	}
	for _, role := range m.Roles {
		if _, err := tx.Exec(ctx,
			`INSERT INTO roles (app, key, name, description) VALUES ($1, $2, $3, $4)`,
			m.App, role.Key, role.Name, role.Description); err != nil {
			return domain.PublishedManifest{}, fmt.Errorf("insert role %s: %w", role.Key, err)
		}
		for _, perm := range role.Permissions {
			if _, err := tx.Exec(ctx,
				`INSERT INTO role_permissions (app, role, permission) VALUES ($1, $2, $3)`,
				m.App, role.Key, perm); err != nil {
				return domain.PublishedManifest{}, fmt.Errorf("insert role permission %s: %w", perm, err)
			}
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE apps SET manifest_version = manifest_version + 1, manifest_hash = $2,
		                published_at = $3, published_by = $4
		WHERE key = $1`, m.App, hash, now, publishedBy); err != nil {
		return domain.PublishedManifest{}, fmt.Errorf("update app: %w", err)
	}
	out, err := loadManifest(ctx, tx, m.App)
	if err != nil {
		return domain.PublishedManifest{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.PublishedManifest{}, fmt.Errorf("commit: %w", err)
	}
	return out, nil
}

// loadManifest reads the manifest of an app.
func loadManifest(ctx context.Context, q querier, app string) (domain.PublishedManifest, error) {
	out := domain.PublishedManifest{Manifest: domain.Manifest{App: app}}
	err := q.QueryRow(ctx, `
		SELECT manifest_version, manifest_hash, published_at, published_by
		FROM apps WHERE key = $1 AND manifest_version > 0`, app).
		Scan(&out.Version, &out.Hash, &out.PublishedAt, &out.PublishedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.PublishedManifest{}, fmt.Errorf("manifest of app %s: %w", app, manifests.ErrNotFound)
	}
	if err != nil {
		return domain.PublishedManifest{}, fmt.Errorf("get app: %w", err)
	}

	rows, err := q.Query(ctx, `SELECT key, description FROM permissions WHERE app = $1 ORDER BY key`, app)
	if err != nil {
		return domain.PublishedManifest{}, fmt.Errorf("list permissions: %w", err)
	}
	for rows.Next() {
		var p domain.PermissionDef
		if err := rows.Scan(&p.Key, &p.Description); err != nil {
			rows.Close()
			return domain.PublishedManifest{}, fmt.Errorf("scan permission: %w", err)
		}
		out.Manifest.Permissions = append(out.Manifest.Permissions, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return domain.PublishedManifest{}, fmt.Errorf("list permissions: %w", err)
	}

	roles, err := queryRoles(ctx, q, `WHERE r.app = $1`, 0, app)
	if err != nil {
		return domain.PublishedManifest{}, err
	}
	for _, role := range roles {
		out.Manifest.Roles = append(out.Manifest.Roles, domain.RoleDef{
			Key: role.Ref.Role, Name: role.Name, Description: role.Description, Permissions: role.Permissions,
		})
	}
	return out, nil
}

// queryRoles reads roles with their permissions. where is a condition with
// the alias r, limit is the largest number of roles (0 means no limit), and
// args are the arguments of the condition. The result is in order of app and
// role.
func queryRoles(ctx context.Context, q querier, where string, limit int, args ...any) ([]domain.Role, error) {
	suffix := ""
	if limit > 0 {
		suffix = fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := q.Query(ctx, `
		SELECT r.app, r.key, r.name, r.description,
		       COALESCE(array_agg(rp.permission ORDER BY rp.permission)
		                FILTER (WHERE rp.permission IS NOT NULL), '{}')
		FROM roles r
		LEFT JOIN role_permissions rp ON rp.app = r.app AND rp.role = r.key `+where+`
		GROUP BY r.app, r.key, r.name, r.description
		ORDER BY r.app, r.key`+suffix, args...)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	defer rows.Close()
	var out []domain.Role
	for rows.Next() {
		var role domain.Role
		if err := rows.Scan(&role.Ref.App, &role.Ref.Role, &role.Name, &role.Description, &role.Permissions); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		out = append(out, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	return out, nil
}

// Get returns the manifest of an app.
func (r *Manifests) Get(ctx context.Context, app string) (domain.PublishedManifest, error) {
	return loadManifest(ctx, r.pool, app)
}

// List returns manifests in app order.
func (r *Manifests) List(ctx context.Context, afterApp string, limit int) ([]domain.PublishedManifest, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT key FROM apps WHERE manifest_version > 0 AND key > $1 ORDER BY key LIMIT $2`, afterApp, limit)
	if err != nil {
		return nil, fmt.Errorf("list apps: %w", err)
	}
	var apps []string
	for rows.Next() {
		var app string
		if err := rows.Scan(&app); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan app: %w", err)
		}
		apps = append(apps, app)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list apps: %w", err)
	}
	out := make([]domain.PublishedManifest, 0, len(apps))
	for _, app := range apps {
		m, err := loadManifest(ctx, r.pool, app)
		if errors.Is(err, manifests.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// HasManifest reports whether the app has a published manifest.
func (r *Manifests) HasManifest(ctx context.Context, app string) (bool, error) {
	var ok bool
	if err := r.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM apps WHERE key = $1 AND manifest_version > 0)`, app).Scan(&ok); err != nil {
		return false, fmt.Errorf("check manifest: %w", err)
	}
	return ok, nil
}

// Role returns a role.
func (r *Manifests) Role(ctx context.Context, ref domain.RoleRef) (domain.Role, error) {
	roles, err := queryRoles(ctx, r.pool, `WHERE r.app = $1 AND r.key = $2`, 1, ref.App, ref.Role)
	if err != nil {
		return domain.Role{}, err
	}
	if len(roles) == 0 {
		return domain.Role{}, fmt.Errorf("role %s: %w", ref, manifests.ErrNotFound)
	}
	return roles[0], nil
}

// Roles returns roles after a reference.
func (r *Manifests) Roles(ctx context.Context, app string, after domain.RoleRef, limit int) ([]domain.Role, error) {
	return queryRoles(ctx, r.pool, `
		WHERE ($1 = '' OR r.app = $1) AND (r.app, r.key) > ($2, $3)`, limit, app, after.App, after.Role)
}
