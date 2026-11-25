package commands

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/techorionai/constellation-platform-go/executor"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/agentroles"
	"github.com/techorionai/constellation-identity/internal/ports/agents"
	"github.com/techorionai/constellation-identity/internal/ports/clientroles"
	"github.com/techorionai/constellation-identity/internal/ports/clients"
	"github.com/techorionai/constellation-identity/internal/ports/manifests"
	"github.com/techorionai/constellation-identity/internal/ports/ratelimit"
	"github.com/techorionai/constellation-identity/internal/ports/tokensigner"
	"github.com/techorionai/constellation-identity/internal/ports/tokenverifier"
	"github.com/techorionai/constellation-identity/internal/ports/userroles"
	"github.com/techorionai/constellation-identity/internal/ports/users"
)

// exchangePermission is the permission that a client needs for the token
// exchange grant.
const exchangePermission = "identity:token:exchange"

// TokenExchange is the input of the token exchange grant (RFC 8693). The
// values come from the form of the token request. The assertion, the subject
// token, and the actor token are secret or private: no log, span, or error
// text may hold them.
type TokenExchange struct {
	AssertionType      string
	Assertion          string
	ClientID           string
	SubjectToken       string
	SubjectTokenType   string
	ActorToken         string
	ActorTokenType     string
	RequestedTokenType string
	Audience           string
	Scope              string
	// SecondAuthentication is true if the request has a client secret or an
	// Authorization header with the scheme Basic, besides the assertion.
	SecondAuthentication bool
	// RepeatedParameter is true if a single-value parameter occurs more than
	// one time.
	RepeatedParameter bool
}

// TokenExchangeResult is the token and its data.
type TokenExchangeResult struct {
	AccessToken     string
	ExpiresIn       int
	Scope           string
	IssuedTokenType string
}

// TokenExchangeDeps are the ports of the command.
type TokenExchangeDeps struct {
	// RateLimits limits the requests of one verified client. It can be nil.
	RateLimits *RateLimits
	Issuer     string
	// Auth checks the client authentication of the caller.
	Auth        ServiceAuthenticator
	Clients     clients.Repository
	ClientRoles clientroles.Repository
	Manifests   manifests.Repository
	Users       users.Repository
	UserRoles   userroles.Repository
	Agents      agents.Repository
	AgentRoles  agentroles.Repository
	Keys        OIDCKeys
	Signer      tokensigner.Signer
	Verifier    tokenverifier.Verifier
	Log         *slog.Logger
	// Now is the clock. The default is time.Now.
	Now func() time.Time
	// NewID makes the jti of a token. The default is a random UUID.
	NewID func() string
}

// TokenExchangeCommand is the use case of the token exchange grant.
type TokenExchangeCommand struct {
	d      TokenExchangeDeps
	issued metric.Int64Counter
	errors metric.Int64Counter
}

var _ executor.ExecutorWithReturn[TokenExchange, TokenExchangeResult] = (*TokenExchangeCommand)(nil)

// NewTokenExchange makes the command.
func NewTokenExchange(d TokenExchangeDeps) (*TokenExchangeCommand, error) {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.NewID == nil {
		d.NewID = newUUID
	}
	meter := otel.Meter("identity")
	issued, err := meter.Int64Counter("identity.tokens.issued", metric.WithDescription("Access tokens issued."))
	if err != nil {
		return nil, fmt.Errorf("make the issued counter: %w", err)
	}
	errs, err := meter.Int64Counter("identity.token.errors", metric.WithDescription("Failed token requests."))
	if err != nil {
		return nil, fmt.Errorf("make the error counter: %w", err)
	}
	return &TokenExchangeCommand{d: d, issued: issued, errors: errs}, nil
}

const (
	subjectInvalid = "The subject token is not valid."
	actorInvalid   = "The actor token is not valid."
	serverFailed   = "The server has an internal error."
)

// Execute checks the request in the order of docs/tokens.md and signs the
// token. Each failure is an *apperrors.OAuthError.
func (c *TokenExchangeCommand) Execute(ctx context.Context, in TokenExchange) (TokenExchangeResult, error) {
	var st requestState
	st.clientID = in.ClientID
	withAgent := attribute.Bool("with_agent", in.ActorToken != "")
	res, err := c.exchange(ctx, in, &st)
	if err != nil {
		code := apperrors.OAuthServerError
		if oe, ok := apperrors.AsOAuthError(err); ok {
			code = oe.Code
		}
		c.errors.Add(ctx, 1, metric.WithAttributes(attribute.String("error", code), withAgent))
		field := "client.id_unverified"
		if st.verified {
			field = "client.id"
		}
		if oe, ok := apperrors.AsOAuthError(err); ok && oe.RateLimited {
			c.d.Log.InfoContext(ctx, "token request limited", "error_code", code, "grant_type", "token_exchange", field, truncate(st.clientID, 64))
			return TokenExchangeResult{}, err
		}
		c.d.Log.WarnContext(ctx, "token request failed", "error_code", code, "grant_type", "token_exchange", field, truncate(st.clientID, 64))
		return TokenExchangeResult{}, err
	}
	c.issued.Add(ctx, 1, metric.WithAttributes(
		attribute.String("grant_type", "token_exchange"),
		attribute.String("principal_type", domain.PrincipalUser), withAgent))
	return res, nil
}

func (c *TokenExchangeCommand) exchange(ctx context.Context, in TokenExchange, st *requestState) (TokenExchangeResult, error) {
	// 1. The request.
	switch {
	case in.RepeatedParameter:
		return TokenExchangeResult{}, fail(apperrors.OAuthInvalidRequest, "A parameter occurs more than one time.", nil)
	case in.SecondAuthentication:
		return TokenExchangeResult{}, fail(apperrors.OAuthInvalidRequest, "Use client_assertion as the only client authentication.", nil)
	}

	// 2. The client authentication.
	client, err := c.d.Auth.AuthenticateService(ctx, in.AssertionType, in.Assertion, in.ClientID)
	if err != nil {
		return TokenExchangeResult{}, err
	}
	st.clientID, st.verified = client.ID, true
	if err := oauthRateError(c.d.RateLimits.Check(ctx, ratelimit.BucketTokenClient, client.ID)); err != nil {
		return TokenExchangeResult{}, err
	}
	now := c.d.Now().UTC()

	// 3. The permission of the client.
	clientPerms, err := c.d.ClientRoles.GrantedPermissions(ctx, client.ID, domain.ServiceRole)
	if err != nil {
		return TokenExchangeResult{}, fail(apperrors.OAuthServerError, serverFailed, err)
	}
	if !slices.Contains(clientPerms, exchangePermission) {
		return TokenExchangeResult{}, fail(apperrors.OAuthUnauthorizedClient, "The client cannot use the token exchange grant.", nil)
	}

	// 4. The required parameters.
	if in.SubjectToken == "" || in.SubjectTokenType == "" || in.Audience == "" || strings.TrimSpace(in.Scope) == "" {
		return TokenExchangeResult{}, fail(apperrors.OAuthInvalidRequest, "The subject_token, subject_token_type, audience, and scope are required.", nil)
	}
	if (in.ActorToken == "") != (in.ActorTokenType == "") {
		return TokenExchangeResult{}, fail(apperrors.OAuthInvalidRequest, "The actor_token and the actor_token_type must appear together.", nil)
	}

	// 5. The token types.
	if in.SubjectTokenType != domain.TokenTypeAccessToken ||
		in.RequestedTokenType != "" && in.RequestedTokenType != domain.TokenTypeAccessToken ||
		in.ActorTokenType != "" && in.ActorTokenType != domain.TokenTypeAgentID {
		return TokenExchangeResult{}, fail(apperrors.OAuthUnsupportedTokenType, "A token type is not supported.", nil)
	}

	// 6. The audience.
	if !domain.ValidAppKey(in.Audience) || in.Audience == domain.IdentityApp {
		return TokenExchangeResult{}, fail(apperrors.OAuthInvalidTarget, "The audience is required and must be an app with a manifest.", nil)
	}
	has, err := c.d.Manifests.HasManifest(ctx, in.Audience)
	if err != nil {
		return TokenExchangeResult{}, fail(apperrors.OAuthServerError, serverFailed, err)
	}
	if !has {
		return TokenExchangeResult{}, fail(apperrors.OAuthInvalidTarget, "The audience is required and must be an app with a manifest.", nil)
	}

	// 7. The subject token.
	subject, user, err := c.checkSubject(ctx, in.SubjectToken, client, now)
	if err != nil {
		return TokenExchangeResult{}, err
	}

	// 8. The actor token.
	var agent *domain.Agent
	if in.ActorToken != "" {
		a, err := c.checkActor(ctx, in.ActorToken, client)
		if err != nil {
			return TokenExchangeResult{}, err
		}
		agent = &a
	}

	// 9. The scope.
	granted, err := c.d.UserRoles.GrantedPermissions(ctx, user.ID, domain.ImplicitUserRoles(user.Status)...)
	if err != nil {
		return TokenExchangeResult{}, fail(apperrors.OAuthServerError, serverFailed, err)
	}
	if agent != nil {
		agentPerms, err := c.d.AgentRoles.GrantedPermissions(ctx, agent.ID)
		if err != nil {
			return TokenExchangeResult{}, fail(apperrors.OAuthServerError, serverFailed, err)
		}
		granted = domain.IntersectScopes(granted, agentPerms)
	}
	scopes, err := domain.GrantScopes(in.Audience, in.Scope, granted)
	if err != nil {
		return TokenExchangeResult{}, fail(apperrors.OAuthInvalidScope, "Each scope must be a permission of the audience that the user and the agent have.", err)
	}

	// 10. The token.
	key, err := c.d.Keys.ActiveKey()
	if err != nil {
		return TokenExchangeResult{}, fail(apperrors.OAuthTemporarilyUnavailable, "The service is not available. Try again.", err)
	}
	token := domain.ExchangedToken{
		Issuer: c.d.Issuer, Audience: in.Audience, UserID: user.ID, ClientID: client.ID, Scopes: scopes,
		Now: now, SubjectExpiresAt: subject.ExpiresAt, JTI: c.d.NewID(),
	}
	agentID := ""
	if agent != nil {
		agentID = agent.ID
		token.Actor = &domain.ActorClaim{Subject: agent.ID, PrincipalType: domain.PrincipalAgent}
	}
	signed, err := c.d.Signer.Sign(key, token.Claims(), map[string]any{"typ": domain.AccessTokenType})
	if err != nil {
		return TokenExchangeResult{}, fail(apperrors.OAuthServerError, serverFailed, err)
	}
	// The record has IDs only. It has no token, no assertion, and no actor value.
	c.d.Log.InfoContext(ctx, "identity.token.exchange", "event", "identity.token.exchange", "client.id", client.ID,
		"user_id", user.ID, "agent_id", agentID, "audience", in.Audience, "scope", strings.Join(scopes, " "), "jti", token.JTI)
	return TokenExchangeResult{
		AccessToken:     signed,
		ExpiresIn:       int(token.ExpiresAt().Unix() - now.Unix()),
		Scope:           strings.Join(scopes, " "),
		IssuedTokenType: domain.TokenTypeAccessToken,
	}, nil
}

// checkSubject checks the subject token. Each failure of the token is
// invalid_grant with the same text.
func (c *TokenExchangeCommand) checkSubject(ctx context.Context, token string, client domain.Client, now time.Time) (tokenverifier.Claims, domain.User, error) {
	bad := func(why string) (tokenverifier.Claims, domain.User, error) {
		return tokenverifier.Claims{}, domain.User{}, fail(apperrors.OAuthInvalidGrant, subjectInvalid, errors.New(why))
	}
	claims, err := c.d.Verifier.Verify(token, c.d.Keys.JWKS())
	if err != nil || claims.Issuer != c.d.Issuer || claims.Typ != domain.AccessTokenType {
		return bad("the signature, the issuer, or the type is not valid")
	}
	if claims.ExpiresAt.IsZero() || !now.Before(claims.ExpiresAt) {
		return bad("the token is expired")
	}
	if !claims.NotBefore.IsZero() && claims.NotBefore.After(now) {
		return bad("the token is not valid yet")
	}
	if claims.PrincipalType != domain.PrincipalUser {
		return bad("the principal is not a user")
	}
	if claims.HasAct {
		return bad("the token has the act claim")
	}
	// Only the code flow makes a user token, and only for a public client. An
	// exchanged token has the ID of a service client.
	issuer, err := c.d.Clients.Get(ctx, claims.ClientID)
	if errors.Is(err, clients.ErrNotFound) {
		return bad("the client of the token is unknown")
	}
	if err != nil {
		return tokenverifier.Claims{}, domain.User{}, fail(apperrors.OAuthServerError, serverFailed, err)
	}
	if issuer.Disabled || issuer.Type != domain.ClientTypePublic {
		return bad("the client of the token is not an enabled public client")
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != client.App {
		return bad("the audience is not the app of the client")
	}
	if !uuidPattern.MatchString(claims.Subject) {
		return bad("the subject is not a user ID")
	}
	user, err := c.d.Users.GetByID(ctx, claims.Subject)
	if errors.Is(err, users.ErrNotFound) {
		return bad("the user does not exist")
	}
	if err != nil {
		return tokenverifier.Claims{}, domain.User{}, fail(apperrors.OAuthServerError, serverFailed, err)
	}
	if user.Status != domain.UserActive {
		return bad("the user is not active")
	}
	if claims.ExpiresAt.Sub(now) < domain.MinSubjectTokenLife {
		return bad("the token has too little life left")
	}
	return claims, user, nil
}

// checkActor checks the agent. All failures give the same text.
func (c *TokenExchangeCommand) checkActor(ctx context.Context, value string, client domain.Client) (domain.Agent, error) {
	bad := func(why string) (domain.Agent, error) {
		return domain.Agent{}, fail(apperrors.OAuthInvalidGrant, actorInvalid, errors.New(why))
	}
	if !uuidPattern.MatchString(value) {
		return bad("the actor token is not a UUID")
	}
	a, err := c.d.Agents.Get(ctx, value)
	if errors.Is(err, agents.ErrNotFound) {
		return bad("the agent does not exist")
	}
	if err != nil {
		return domain.Agent{}, fail(apperrors.OAuthServerError, serverFailed, err)
	}
	if !a.Enabled {
		return bad("the agent is disabled")
	}
	if a.ClientID != client.ID {
		return bad("the agent belongs to another client")
	}
	return a, nil
}
