package commands

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/techorionai/constellation-platform-go/audit"
	"github.com/techorionai/constellation-platform-go/transaction"

	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/apitokens"
	"github.com/techorionai/constellation-identity/internal/ports/ratelimit"
	"github.com/techorionai/constellation-identity/internal/ports/userroles"
	"github.com/techorionai/constellation-identity/internal/ports/users"
)

// The codes of the API token operations. They are the codes of the contract.
const (
	codeUserTokenRequired = "user_token_required" //nolint:gosec // An error code, not a credential.
	codeScopeNotGranted   = "scope_not_granted"
	codeTokenLimit        = "token_limit"
	codeAPITokenNotFound  = "api_token_not_found" //nolint:gosec // An error code, not a credential.
	codeUserNotFound      = "user_not_found"
)

// APITokenSettings are the limits of the personal API tokens.
type APITokenSettings struct {
	// DefaultTTLDays is the life of a token when the request has no expiresInDays.
	DefaultTTLDays int
	// MaxTTLDays is the largest value of expiresInDays.
	MaxTTLDays int
	// MaxPerUser is the largest number of active tokens of a user. The largest
	// number of all rows of a user is APITokenTotalFactor times this value.
	MaxPerUser int
}

// APITokensDeps are the ports of the API token use cases.
type APITokensDeps struct {
	// RateLimits limits the creation of tokens for each user. It can be nil.
	RateLimits *RateLimits
	Tokens     apitokens.Repository
	Users      users.Repository
	UserRoles  userroles.Repository
	Tx         transaction.Transactor
	// Audit writes the audit entries in the transaction of the change.
	Audit    audit.Writer
	Settings APITokenSettings
	Log      *slog.Logger
	// Now is the clock. The default is time.Now.
	Now Clock
}

// APITokens has the use cases of the personal API tokens: create, list, and
// revoke. Each change writes one info log record with the actor, the
// operation, and the ID of the token. The record has no token value and no
// hash.
type APITokens struct{ d APITokensDeps }

// NewAPITokens makes the use cases.
func NewAPITokens(d APITokensDeps) *APITokens {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &APITokens{d: d}
}

func (a *APITokens) now() time.Time { return a.d.Now().UTC() }

// CreateAPIToken is the input of the creation of a personal API token.
type CreateAPIToken struct {
	UserID        string
	Name          string
	Scope         string
	ExpiresInDays *int32
	// AMR is the amr claim of the access token that made the request. The new
	// token records it, so the removal of a login method can revoke it. The API
	// does not show it.
	AMR []string
}

// CreatedAPIToken is a new token. Value is a secret. It is shown one time.
type CreatedAPIToken struct {
	Value string
	Token domain.APIToken
}

func userTokenRequired() error {
	return apperrors.NewProblem(403, codeUserTokenRequired, "The token must be the access token of an active user.")
}

// parseTokenScope checks the syntax of the scope of a new token. An empty scope,
// an OIDC scope, and a value that is not a permission key give invalid_request.
func parseTokenScope(scope string) ([]string, error) {
	fields := strings.Fields(scope)
	if len(fields) == 0 {
		return nil, apperrors.NewInvalidInput("the scope is required")
	}
	var out []string
	for _, s := range fields {
		if domain.IsOIDCScope(s) || !domain.ValidPermissionKey(s) {
			return nil, apperrors.NewInvalidInput("the scope must have permission keys only")
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out, nil
}

// Create makes a personal API token for a user. The checks run in one
// transaction under the lock of the user row: the status of the user, the scope,
// the limit of active tokens, and the limit of all rows.
func (a *APITokens) Create(ctx context.Context, in CreateAPIToken) (CreatedAPIToken, error) {
	if err := a.d.RateLimits.Check(ctx, ratelimit.BucketAPITokenCreate, in.UserID); err != nil {
		return CreatedAPIToken{}, err
	}
	name := strings.TrimSpace(in.Name)
	if n := utf8.RuneCountInString(name); n < 1 || n > domain.MaxAPITokenNameLength {
		return CreatedAPIToken{}, apperrors.NewInvalidInput("the name must have 1 to 100 characters")
	}
	scope, err := parseTokenScope(in.Scope)
	if err != nil {
		return CreatedAPIToken{}, err
	}
	days := a.d.Settings.DefaultTTLDays
	if in.ExpiresInDays != nil {
		days = int(*in.ExpiresInDays)
		if days < 1 || days > a.d.Settings.MaxTTLDays {
			return CreatedAPIToken{}, apperrors.NewInvalidInput(fmt.Sprintf("expiresInDays must be from 1 to %d", a.d.Settings.MaxTTLDays))
		}
	}
	value, hash, err := domain.NewAPIToken()
	if err != nil {
		return CreatedAPIToken{}, err
	}
	id := newUUID()
	now := a.now()
	tok := domain.APIToken{
		ID: id, UserID: in.UserID, Name: name, Scope: scope, CreatedAt: now, ExpiresAt: now.AddDate(0, 0, days),
		AMR: slices.Clone(in.AMR),
	}
	err = a.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		u, err := a.d.Users.LockByID(ctx, in.UserID)
		if errors.Is(err, users.ErrNotFound) {
			return userTokenRequired()
		}
		if err != nil {
			return err
		}
		if u.Status != domain.UserActive {
			return userTokenRequired()
		}
		granted, err := a.d.UserRoles.GrantedPermissions(ctx, u.ID, domain.ImplicitUserRoles(u.Status)...)
		if err != nil {
			return err
		}
		var fields []domain.FieldError
		for _, s := range scope {
			if strings.HasPrefix(s, domain.IdentityApp+":") || !slices.Contains(granted, s) {
				fields = append(fields, domain.FieldError{
					Code: codeScopeNotGranted, Field: "/scope", Message: "the user cannot give the scope " + s,
				})
			}
		}
		if err := validationErr(fields); err != nil {
			return err
		}
		active, err := a.d.Tokens.CountActive(ctx, u.ID, now)
		if err != nil {
			return err
		}
		if active >= a.d.Settings.MaxPerUser {
			return apperrors.NewUnprocessable(codeTokenLimit, "The user has the largest number of active API tokens.")
		}
		all, err := a.d.Tokens.CountAll(ctx, u.ID)
		if err != nil {
			return err
		}
		if all >= domain.APITokenTotalFactor*a.d.Settings.MaxPerUser {
			return apperrors.NewUnprocessable(codeTokenLimit, "The user has the largest number of API token records. Revoked and expired tokens go after the retention period.")
		}
		if err := a.d.Tokens.Insert(ctx, hash, tok); err != nil {
			return err
		}
		return writeAudit(ctx, a.d.Audit, now, ActionAPITokenCreate, targetAPIToken, id, map[string]any{"scopes": slices.Clone(scope)})
	}, txName("create_api_token"))
	if err != nil {
		return CreatedAPIToken{}, err
	}
	a.logChange(ctx, in.UserID, "create", id)
	return CreatedAPIToken{Value: value, Token: tok}, nil
}

func (a *APITokens) logChange(ctx context.Context, actor, op, tokenID string) {
	a.d.Log.InfoContext(ctx, "identity.api_token.change", "event", "identity.api_token.change",
		"actor_id", actor, "operation", op, "token_id", tokenID)
}

// List returns a page of the tokens of a user, newest first.
func (a *APITokens) List(ctx context.Context, userID string, p ListPage) (Page[domain.APIToken], error) {
	n, err := p.size()
	if err != nil {
		return Page[domain.APIToken]{}, err
	}
	cur, err := decodeUUIDCursor(p.Token)
	if err != nil {
		return Page[domain.APIToken]{}, err
	}
	items, err := a.d.Tokens.ListByUser(ctx, userID, cur, n+1)
	if err != nil {
		return Page[domain.APIToken]{}, fmt.Errorf("list api tokens: %w", err)
	}
	out := Page[domain.APIToken]{Items: items}
	if len(items) > n {
		out.Items = items[:n]
		last := out.Items[n-1]
		out.Next = EncodeTimeCursor(last.CreatedAt, last.ID)
	}
	return out, nil
}

// ListForUser returns a page of the tokens of any user, for the admin API. An
// unknown user, or an ID that is not a UUID, gives 404 user_not_found.
func (a *APITokens) ListForUser(ctx context.Context, userID string, p ListPage) (Page[domain.APIToken], error) {
	if !uuidPattern.MatchString(userID) {
		return Page[domain.APIToken]{}, errUserNotFound()
	}
	if _, err := a.d.Users.GetByID(ctx, userID); errors.Is(err, users.ErrNotFound) {
		return Page[domain.APIToken]{}, errUserNotFound()
	} else if err != nil {
		return Page[domain.APIToken]{}, fmt.Errorf("get the user: %w", err)
	}
	return a.List(ctx, userID, p)
}

func errUserNotFound() error {
	return apperrors.NewProblem(404, codeUserNotFound, "The user does not exist.")
}

func errAPITokenNotFound() error {
	return apperrors.NewProblem(404, codeAPITokenNotFound, "The API token does not exist.")
}

// Revoke revokes a token of the user. A token of another user, an unknown ID,
// and an ID that is not a UUID give 404 api_token_not_found. A token that is
// revoked already gives no error.
func (a *APITokens) Revoke(ctx context.Context, userID, tokenID string) error {
	if !uuidPattern.MatchString(tokenID) {
		return errAPITokenNotFound()
	}
	err := a.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		found, err := a.d.Tokens.Revoke(ctx, tokenID, userID, a.now())
		if err != nil {
			return fmt.Errorf("revoke the api token: %w", err)
		}
		if !found {
			return errAPITokenNotFound()
		}
		return writeAudit(ctx, a.d.Audit, a.now(), ActionAPITokenRevoke, targetAPIToken, tokenID, nil)
	}, txName("revoke_api_token"))
	if err != nil {
		return err
	}
	a.logChange(ctx, userID, "revoke", tokenID)
	return nil
}

// AdminRevoke revokes a token of any user. The admin log record has the
// operation api_token.revoke.
func (a *APITokens) AdminRevoke(ctx context.Context, actor, tokenID string) error {
	if !uuidPattern.MatchString(tokenID) {
		return errAPITokenNotFound()
	}
	err := a.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		found, err := a.d.Tokens.Revoke(ctx, tokenID, "", a.now())
		if err != nil {
			return fmt.Errorf("revoke the api token: %w", err)
		}
		if !found {
			return errAPITokenNotFound()
		}
		return writeAudit(ctx, a.d.Audit, a.now(), ActionAPITokenRevoke, targetAPIToken, tokenID, nil)
	}, txName("admin_revoke_api_token"))
	if err != nil {
		return err
	}
	a.d.Log.InfoContext(ctx, "identity.admin.change", "event", "identity.admin.change",
		"actor_id", actor, "operation", "api_token.revoke", "target_id", tokenID)
	return nil
}
