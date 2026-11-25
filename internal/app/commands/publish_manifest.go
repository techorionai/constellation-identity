package commands

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/techorionai/constellation-platform-go/executor"

	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/clients"
	"github.com/techorionai/constellation-identity/internal/ports/manifests"
	"github.com/techorionai/constellation-identity/internal/ports/ratelimit"
)

// PublishManifest is the input of a manifest publish.
type PublishManifest struct {
	// PathApp is the app of the request path.
	PathApp string
	// CallerClientID is the client ID of the token. CallerIsService is true if
	// the principal of the token is a service.
	CallerClientID  string
	CallerIsService bool
	// Manifest is the manifest of the request body.
	Manifest domain.Manifest
	// PublishedBy is the ID of the principal, stored with the manifest.
	PublishedBy string
	// Internal is true for the own manifest of the identity service at start.
	// It skips the check of the caller.
	Internal bool
}

// PublishManifestCommand checks and stores a manifest.
type PublishManifestCommand struct {
	repo    manifests.Repository
	clients clients.Repository
	log     *slog.Logger
	limits  *RateLimits
}

var _ executor.ExecutorWithReturn[PublishManifest, domain.PublishedManifest] = (*PublishManifestCommand)(nil)

// NewPublishManifest makes the command.
func NewPublishManifest(repo manifests.Repository, cl clients.Repository, log *slog.Logger) *PublishManifestCommand {
	if log == nil {
		log = slog.Default()
	}
	return &PublishManifestCommand{repo: repo, clients: cl, log: log}
}

// WithRateLimits sets the rate limits of the publish. The own publish of the
// service (Internal) is not counted.
func (c *PublishManifestCommand) WithRateLimits(l *RateLimits) *PublishManifestCommand {
	c.limits = l
	return c
}

// Execute checks the caller and the keys, then stores the manifest. A check
// error is an *apperrors.ValidationError that holds all problems of the keys.
func (c *PublishManifestCommand) Execute(ctx context.Context, p PublishManifest) (domain.PublishedManifest, error) {
	if !p.Internal {
		// A service client has one bucket for its client ID. A user has one
		// bucket for each user, also if the user has an OAuth client.
		key := p.PublishedBy
		if p.CallerIsService && p.CallerClientID != "" {
			key = p.CallerClientID
		}
		if err := c.limits.Check(ctx, ratelimit.BucketManifestPublish, key); err != nil {
			return domain.PublishedManifest{}, err
		}
		callerApp, err := c.callerApp(ctx, p)
		if err != nil {
			return domain.PublishedManifest{}, err
		}
		if fe := domain.CheckManifestApp(p.PathApp, callerApp, p.Manifest); fe != nil {
			return domain.PublishedManifest{}, apperrors.NewValidationError([]domain.FieldError{*fe})
		}
	}
	if fes := domain.CheckManifest(p.Manifest); len(fes) > 0 {
		return domain.PublishedManifest{}, apperrors.NewValidationError(fes)
	}
	out, err := c.repo.Publish(ctx, p.Manifest, p.PublishedBy)
	if err != nil {
		return domain.PublishedManifest{}, fmt.Errorf("publish manifest of %s: %w", p.Manifest.App, err)
	}
	c.log.InfoContext(ctx, "manifest published",
		"app", out.Manifest.App, "version", out.Version, "published_by", out.PublishedBy)
	return out, nil
}

// callerApp returns the app of the calling service client. It returns an
// empty string if the caller is not an enabled service client.
func (c *PublishManifestCommand) callerApp(ctx context.Context, p PublishManifest) (string, error) {
	if !p.CallerIsService {
		return "", nil
	}
	client, err := c.clients.Get(ctx, p.CallerClientID)
	if errors.Is(err, clients.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get the caller client: %w", err)
	}
	if client.Type != domain.ClientTypeService || client.Disabled {
		return "", nil
	}
	return client.App, nil
}
