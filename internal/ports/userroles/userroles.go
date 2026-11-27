// Package userroles is the port of the role assignments of users.
package userroles

import (
	"context"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// Repository stores the role assignments of users. A call joins the
// transaction in the context.
type Repository interface {
	// Assign gives a role to a user. It returns true if it added a row, and false
	// if the user had the role.
	Assign(ctx context.Context, userID string, role domain.RoleRef, source domain.AssignmentSource) (bool, error)
	// Delete removes an assignment. It returns false if the user does not have
	// the role.
	Delete(ctx context.Context, userID string, role domain.RoleRef) (bool, error)
	// Assignments returns the assignments of a user in order of app and role.
	// Pending is true when the role has no row in the current manifests.
	Assignments(ctx context.Context, userID string) ([]domain.RoleAssignment, error)
	// Page returns up to limit assignments of a user in order of app and role,
	// after the role. A nil role means the start.
	Page(ctx context.Context, userID string, after *domain.RoleRef, limit int) ([]domain.RoleAssignment, error)
	// GrantedPermissions returns the permission keys that the user has through
	// assignments that are not pending, and through the implicit roles. The
	// result has no duplicates.
	GrantedPermissions(ctx context.Context, userID string, implicit ...domain.RoleRef) ([]string, error)
	// ActiveUserHasRole reports whether at least one user with the status
	// active has the role.
	ActiveUserHasRole(ctx context.Context, role domain.RoleRef) (bool, error)
	// CountActiveHolders returns the number of users with the status active
	// that have a role that is not pending and that grants the permission.
	CountActiveHolders(ctx context.Context, permission string) (int, error)
}
