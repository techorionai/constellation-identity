package services

import (
	"fmt"
	"log/slog"

	"github.com/techorionai/constellation-platform-go/decorators"
	"github.com/techorionai/constellation-platform-go/executor"
	"github.com/techorionai/constellation-platform-go/manifest"

	"github.com/techorionai/constellation-identity/api/openapi"
	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/domain"
)

// loadOwnManifest reads the embedded copy of services/identity/manifest.json
// of constellation-contracts and checks it. The permission identity:admin is
// in the manifest, and only the role admin holds it.
func loadOwnManifest() (domain.Manifest, error) {
	m, err := manifest.Load(openapi.Files, openapi.IdentityManifestPath)
	if err != nil {
		return domain.Manifest{}, fmt.Errorf("own manifest: %w", err)
	}
	return OwnManifest(m), nil
}

// OwnManifest converts a manifest of platform-go to the domain type.
func OwnManifest(m manifest.PermissionManifest) domain.Manifest {
	out := domain.Manifest{App: m.App}
	for _, p := range m.Permissions {
		out.Permissions = append(out.Permissions, domain.PermissionDef{Key: p.Key, Description: p.Description})
	}
	for _, r := range m.DefaultRoles {
		out.Roles = append(out.Roles, domain.RoleDef{
			Key: r.Key, Name: r.Name, Description: r.Description, Permissions: r.Permissions,
		})
	}
	return out
}

// errorLevel logs an error that the caller caused at the info level.
func errorLevel(err error) slog.Level {
	if _, ok := apperrors.AsValidationError(err); ok {
		return slog.LevelInfo
	}
	switch apperrors.CodeOf(err) {
	case apperrors.NotFound, apperrors.InvalidInput:
		return slog.LevelInfo
	}
	return slog.LevelError
}

// withObservability adds logging and tracing to a use case.
func withObservability[P, R any](e executor.ExecutorWithReturn[P, R], name string, log *slog.Logger) executor.ExecutorWithReturn[P, R] {
	return decorators.ApplyTracing(decorators.ApplyLogging(e, name,
		decorators.WithLogger(log), decorators.WithErrorLevel(errorLevel)), name)
}
