// Package manifests is the port of the manifest and role repository.
package manifests

import (
	"context"
	"errors"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// ErrNotFound means the repository has no such manifest or role.
var ErrNotFound = errors.New("not found")

// Repository stores the published manifests, and the permissions and roles
// that come from them.
type Repository interface {
	// Publish stores the manifest of m.App under a lock on the app. If the
	// hash of m is the stored hash, it changes nothing and returns the stored
	// manifest. Otherwise it replaces the permissions, the roles, and the role
	// permissions of the app and increments the version. It never changes a
	// role assignment.
	Publish(ctx context.Context, m domain.Manifest, publishedBy string) (domain.PublishedManifest, error)
	// Get returns the manifest of an app. The error wraps ErrNotFound.
	Get(ctx context.Context, app string) (domain.PublishedManifest, error)
	// List returns up to limit manifests whose app is after afterApp, in app
	// order.
	List(ctx context.Context, afterApp string, limit int) ([]domain.PublishedManifest, error)
	// HasManifest reports whether the app has a published manifest.
	HasManifest(ctx context.Context, app string) (bool, error)
	// Role returns a role. The error wraps ErrNotFound.
	Role(ctx context.Context, ref domain.RoleRef) (domain.Role, error)
	// Roles returns up to limit roles after the reference after, in order of
	// app and role. An empty app means all apps.
	Roles(ctx context.Context, app string, after domain.RoleRef, limit int) ([]domain.Role, error)
}
