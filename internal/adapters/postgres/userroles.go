package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	clientspg "github.com/techorionai/constellation-platform-go/clients/postgres"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/userroles"
)

// UserRoles is the PostgreSQL repository of the role assignments of users.
type UserRoles struct {
	pool *pgxpool.Pool
}

var _ userroles.Repository = (*UserRoles)(nil)

// NewUserRoles makes the repository.
func NewUserRoles(pool *pgxpool.Pool) *UserRoles { return &UserRoles{pool: pool} }

// Assign gives a role to a user.
func (r *UserRoles) Assign(ctx context.Context, userID string, role domain.RoleRef, source domain.AssignmentSource) error {
	if _, err := clientspg.Conn(ctx, r.pool).Exec(ctx, `
		INSERT INTO user_roles (user_id, app, role, source) VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id, app, role) DO NOTHING`,
		userID, role.App, role.Role, string(source)); err != nil {
		return fmt.Errorf("assign role %s: %w", role, err)
	}
	return nil
}

// Assignments returns the assignments of a user. Pending is calculated in this
// query. No column stores it.
func (r *UserRoles) Assignments(ctx context.Context, userID string) ([]domain.RoleAssignment, error) {
	rows, err := clientspg.Conn(ctx, r.pool).Query(ctx, `
		SELECT ur.app, ur.role, ur.source, (ro.key IS NULL)
		FROM user_roles ur
		LEFT JOIN roles ro ON ro.app = ur.app AND ro.key = ur.role
		WHERE ur.user_id = $1
		ORDER BY ur.app, ur.role`, userID)
	if err != nil {
		return nil, fmt.Errorf("list user roles: %w", err)
	}
	defer rows.Close()
	var out []domain.RoleAssignment
	for rows.Next() {
		var (
			a   domain.RoleAssignment
			src string
		)
		if err := rows.Scan(&a.Role.App, &a.Role.Role, &src, &a.Pending); err != nil {
			return nil, fmt.Errorf("scan user role: %w", err)
		}
		a.Source = domain.AssignmentSource(src)
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list user roles: %w", err)
	}
	return out, nil
}

// ActiveUserHasRole reports whether an active user has the role.
func (r *UserRoles) ActiveUserHasRole(ctx context.Context, role domain.RoleRef) (bool, error) {
	var ok bool
	err := clientspg.Conn(ctx, r.pool).QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM user_roles ur JOIN users u ON u.id = ur.user_id
			WHERE ur.app = $1 AND ur.role = $2 AND u.status = 'active')`,
		role.App, role.Role).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("check role holders: %w", err)
	}
	return ok, nil
}
