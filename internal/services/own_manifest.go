package services

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/techorionai/constellation-platform-go/decorators"
	"github.com/techorionai/constellation-platform-go/executor"
	"github.com/techorionai/constellation-platform-go/manifest"

	"github.com/techorionai/constellation-identity/api/openapi"
	"github.com/techorionai/constellation-identity/internal/app/commands"
	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/clients"
	"github.com/techorionai/constellation-identity/internal/ports/manifests"
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
	if errors.Is(err, apperrors.ErrRateLimited) {
		return slog.LevelInfo
	}
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

// newPublishAPI makes the publish of the HTTP API. It has the rate limit, the
// logging, and the tracing. A request that the rate limit stops is not an
// error log record and not a span error. The own publish of the service does
// not use it.
func newPublishAPI(repo manifests.Repository, cl clients.Repository, limits *commands.RateLimits, log *slog.Logger) executor.ExecutorWithReturn[commands.PublishManifest, domain.PublishedManifest] {
	return decorators.ApplyTracing(decorators.ApplyLogging(
		commands.NewPublishManifest(repo, cl, log).WithRateLimits(limits), "PublishManifest",
		decorators.WithLogger(log), decorators.WithErrorLevel(errorLevel)), "PublishManifest",
		decorators.WithErrorClassifier(rateLimitClassifier))
}

// traceIssue adds tracing to the client credentials grant. The command writes
// its own failure log.
func traceIssue[P, R any](e executor.ExecutorWithReturn[P, R]) executor.ExecutorWithReturn[P, R] {
	return decorators.ApplyTracing(e, "IssueServiceToken", decorators.WithErrorClassifier(issueSpanError))
}

// traceOAuth adds tracing to the introspection and to the token exchange. The
// command writes its own failure log.
func traceOAuth[P, R any](e executor.ExecutorWithReturn[P, R], name string) executor.ExecutorWithReturn[P, R] {
	return decorators.ApplyTracing(e, name, decorators.WithErrorClassifier(oauthSpanError))
}

// rateLimitClassifier tells the tracing decorator that a request that a rate
// limit stops is not a failure of the service.
func rateLimitClassifier(err error) bool { return !errors.Is(err, apperrors.ErrRateLimited) }

// oauthSpanError tells the tracing decorator which errors of the introspection
// and of the token exchange are failures. A request that a rate limit stops is
// not a failure. An unavailable store or limiter is a failure.
func oauthSpanError(err error) bool {
	oe, ok := apperrors.AsOAuthError(err)
	if !ok {
		return true
	}
	if oe.RateLimited {
		return false
	}
	return oe.Code == apperrors.OAuthServerError || oe.Code == apperrors.OAuthTemporarilyUnavailable
}

// issueSpanError is the classifier of the client credentials grant. An
// unavailable limiter is a failure. A request that a rate limit stops is not.
func issueSpanError(err error) bool {
	oe, ok := apperrors.AsOAuthError(err)
	if !ok {
		return true
	}
	if oe.RateLimited {
		return false
	}
	return oe.Code == apperrors.OAuthServerError || errors.Is(err, apperrors.ErrRateLimiterUnavailable)
}
