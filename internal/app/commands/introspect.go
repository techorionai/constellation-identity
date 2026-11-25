package commands

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/apitokens"
	"github.com/techorionai/constellation-identity/internal/ports/ratelimit"
	"github.com/techorionai/constellation-identity/internal/ports/userroles"
)

// Introspect is the input of the introspection of a token (RFC 7662). The
// token and the assertion are secrets: no log, span, or error text may hold
// them.
type Introspect struct {
	Token         string
	ClientID      string
	AssertionType string
	Assertion     string
	// SecondAuthentication is true if the request has a client secret or an
	// Authorization header with the scheme Basic.
	SecondAuthentication bool
	// RepeatedParameter is true if a single-value parameter occurs more than
	// one time.
	RepeatedParameter bool
}

// IntrospectResult is the answer. If Active is false, no other field is set.
type IntrospectResult struct {
	Active bool
	// Scope has the permission keys of the token for the caller app.
	Scope []string
	// Sub is the ID of the user.
	Sub string
	// Aud is the caller app.
	Aud string
	// Exp and Iat are Unix seconds.
	Exp int64
	Iat int64
	// JTI is the ID of the token.
	JTI string
}

// IntrospectDeps are the ports of the introspection.
type IntrospectDeps struct {
	// RateLimits limits the requests of one verified client. It can be nil.
	RateLimits *RateLimits
	// Auth checks the client authentication of the caller.
	Auth      ServiceAuthenticator
	Tokens    apitokens.Repository
	UserRoles userroles.Repository
	Log       *slog.Logger
	// Now is the clock. The default is time.Now.
	Now Clock
}

// IntrospectCommand is the use case of the introspection of API tokens.
type IntrospectCommand struct {
	d       IntrospectDeps
	results metric.Int64Counter
}

// NewIntrospect makes the command.
func NewIntrospect(d IntrospectDeps) (*IntrospectCommand, error) {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	results, err := otel.Meter("identity").Int64Counter("identity.introspections",
		metric.WithDescription("Introspection requests by result."))
	if err != nil {
		return nil, fmt.Errorf("make the introspection counter: %w", err)
	}
	return &IntrospectCommand{d: d, results: results}, nil
}

const introspectAuthFailed = "The client authentication failed."

// Execute authenticates the caller, then checks the token. The metric has the
// result only. It has no token, hash, or user ID.
func (c *IntrospectCommand) Execute(ctx context.Context, in Introspect) (IntrospectResult, error) {
	res, err := c.introspect(ctx, in)
	result := "inactive"
	switch {
	case err != nil:
		result = "error"
	case res.Active:
		result = "active"
	}
	c.results.Add(ctx, 1, metric.WithAttributes(attribute.String("result", result)))
	return res, err
}

func (c *IntrospectCommand) introspect(ctx context.Context, in Introspect) (IntrospectResult, error) {
	if in.RepeatedParameter {
		return IntrospectResult{}, fail(apperrors.OAuthInvalidRequest, "A parameter occurs more than one time.", nil)
	}
	if in.SecondAuthentication || in.AssertionType != domain.AssertionType || in.Assertion == "" {
		return IntrospectResult{}, fail(apperrors.OAuthInvalidClient, introspectAuthFailed, nil)
	}
	client, err := c.d.Auth.AuthenticateService(ctx, in.AssertionType, in.Assertion, in.ClientID)
	if err != nil {
		return IntrospectResult{}, mapIntrospectAuthError(err)
	}
	if err := oauthRateError(c.d.RateLimits.Check(ctx, ratelimit.BucketIntrospectClient, client.ID)); err != nil {
		return IntrospectResult{}, err
	}
	callerApp := client.App

	if len(in.Token) > domain.MaxIntrospectTokenBytes {
		return IntrospectResult{}, nil
	}
	hash, ok := domain.ParseAPIToken(in.Token)
	if !ok {
		return IntrospectResult{}, nil
	}
	row, err := c.d.Tokens.GetByHash(ctx, hash)
	if errors.Is(err, apitokens.ErrNotFound) {
		return IntrospectResult{}, nil
	}
	if err != nil {
		return IntrospectResult{}, unavailable(err)
	}
	now := c.d.Now().UTC()
	if row.RevokedAt != nil || !row.ExpiresAt.After(now) || row.OwnerStatus != domain.UserActive {
		return IntrospectResult{}, nil
	}
	granted, err := c.d.UserRoles.GrantedPermissions(ctx, row.UserID, domain.ImplicitUserRoles(row.OwnerStatus)...)
	if err != nil {
		return IntrospectResult{}, unavailable(err)
	}
	scope := domain.EffectiveAPIScopes(row.Scope, granted, callerApp)
	if len(scope) == 0 {
		return IntrospectResult{}, nil
	}
	if err := c.d.Tokens.TouchLastUsed(ctx, row.ID, now, domain.APITokenTouchInterval); err != nil {
		// The response does not change. The log record has no token data.
		c.d.Log.WarnContext(ctx, "identity.api_token.touch_failed", "event", "identity.api_token.touch_failed", "error", err)
	}
	return IntrospectResult{
		Active: true, Scope: scope, Sub: row.UserID, Aud: callerApp,
		Exp: row.ExpiresAt.Unix(), Iat: row.CreatedAt.Unix(), JTI: row.ID,
	}, nil
}

func unavailable(cause error) error {
	return fail(apperrors.OAuthTemporarilyUnavailable, "The service is not available. Try again.", cause)
}

// mapIntrospectAuthError maps the error of the client authentication. The
// mapping is only for the introspection. A failure of the client check is
// invalid_client. A failure of a store is temporarily_unavailable.
func mapIntrospectAuthError(err error) error {
	oe, ok := apperrors.AsOAuthError(err)
	if !ok {
		return unavailable(err)
	}
	switch oe.Code {
	case apperrors.OAuthInvalidClient, apperrors.OAuthInvalidRequest:
		return fail(apperrors.OAuthInvalidClient, introspectAuthFailed, err)
	}
	return unavailable(err)
}
