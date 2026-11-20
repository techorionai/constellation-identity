// Package userroles is the port of the role assignments of users.
package userroles

import (
	"context"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// Repository stores the role assignments of users. A call joins the
// transaction in the context.
type Repository interface {
	// Assign gives a role to a user. A second call with the same role does
	// nothing.
	Assign(ctx context.Context, userID string, role domain.RoleRef, source domain.AssignmentSource) error
	// Assignments returns the assignments of a user in order of app and role.
	// Pending is true when the role has no row in the current manifests.
	Assignments(ctx context.Context, userID string) ([]domain.RoleAssignment, error)
	// ActiveUserHasRole reports whether at least one user with the status
	// active has the role.
	ActiveUserHasRole(ctx context.Context, role domain.RoleRef) (bool, error)
}
