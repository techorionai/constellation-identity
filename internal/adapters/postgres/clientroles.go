package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	clientspg "github.com/techorionai/constellation-platform-go/clients/postgres"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/clientroles"
)

// ClientRoles is the PostgreSQL repository of the role assignments of
// clients.
type ClientRoles struct {
	pool *pgxpool.Pool
}

var _ clientroles.Repository = (*ClientRoles)(nil)

// NewClientRoles makes the repository.
func NewClientRoles(pool *pgxpool.Pool) *ClientRoles { return &ClientRoles{pool: pool} }

// Assignments returns the assignments of a client. The service calculates
// pending in this query. No column stores it.
func (r *ClientRoles) Assignments(ctx context.Context, clientID string) ([]domain.RoleAssignment, error) {
	rows, err := clientspg.Conn(ctx, r.pool).Query(ctx, `
		SELECT cr.app, cr.role, cr.source, (ro.key IS NULL)
		FROM client_roles cr
		LEFT JOIN roles ro ON ro.app = cr.app AND ro.key = cr.role
		WHERE cr.client_id = $1
		ORDER BY cr.app, cr.role`, clientID)
	if err != nil {
		return nil, fmt.Errorf("list client roles: %w", err)
	}
	defer rows.Close()
	var out []domain.RoleAssignment
	for rows.Next() {
		var (
			a   domain.RoleAssignment
			src string
		)
		if err := rows.Scan(&a.Role.App, &a.Role.Role, &src, &a.Pending); err != nil {
			return nil, fmt.Errorf("scan client role: %w", err)
		}
		a.Source = domain.AssignmentSource(src)
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list client roles: %w", err)
	}
	return out, nil
}

// GrantedPermissions returns the permissions of the roles that exist and that
// the client has, and of the implicit roles. The join to role_permissions
// drops a pending assignment, because a pending role has no row there.
func (r *ClientRoles) GrantedPermissions(ctx context.Context, clientID string, implicit ...domain.RoleRef) ([]string, error) {
	apps := make([]string, 0, len(implicit))
	roles := make([]string, 0, len(implicit))
	for _, ref := range implicit {
		apps = append(apps, ref.App)
		roles = append(roles, ref.Role)
	}
	rows, err := clientspg.Conn(ctx, r.pool).Query(ctx, `
		SELECT DISTINCT rp.permission
		FROM role_permissions rp
		WHERE EXISTS (SELECT 1 FROM client_roles cr
		              WHERE cr.client_id = $1 AND cr.app = rp.app AND cr.role = rp.role)
		   OR EXISTS (SELECT 1 FROM unnest($2::text[], $3::text[]) AS i (app, role)
		              WHERE i.app = rp.app AND i.role = rp.role)
		ORDER BY rp.permission`, clientID, apps, roles)
	if err != nil {
		return nil, fmt.Errorf("list granted permissions: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, fmt.Errorf("scan permission: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list granted permissions: %w", err)
	}
	return out, nil
}

// Page returns a page of the assignments of a client.
func (r *ClientRoles) Page(ctx context.Context, clientID string, after *domain.RoleRef, limit int) ([]domain.RoleAssignment, error) {
	return rolePage(ctx, clientspg.Conn(ctx, r.pool), `client_roles`, `client_id`, clientID, after, limit)
}

// Assign gives a role to a client.
func (r *ClientRoles) Assign(ctx context.Context, clientID string, role domain.RoleRef, source domain.AssignmentSource) error {
	if _, err := clientspg.Conn(ctx, r.pool).Exec(ctx, `
		INSERT INTO client_roles (client_id, app, role, source) VALUES ($1, $2, $3, $4)
		ON CONFLICT (client_id, app, role) DO NOTHING`, clientID, role.App, role.Role, string(source)); err != nil {
		return fmt.Errorf("assign client role %s: %w", role, err)
	}
	return nil
}

// Delete removes an assignment.
func (r *ClientRoles) Delete(ctx context.Context, clientID string, role domain.RoleRef) (bool, error) {
	tag, err := clientspg.Conn(ctx, r.pool).Exec(ctx,
		`DELETE FROM client_roles WHERE client_id = $1 AND app = $2 AND role = $3`, clientID, role.App, role.Role)
	if err != nil {
		return false, fmt.Errorf("delete client role: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
