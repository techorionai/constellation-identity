package commands

import (
	"context"
	"crypto/rand"
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
	"github.com/techorionai/constellation-identity/internal/ports/assertion"
	"github.com/techorionai/constellation-identity/internal/ports/clientroles"
	"github.com/techorionai/constellation-identity/internal/ports/clients"
	"github.com/techorionai/constellation-identity/internal/ports/jtistore"
	"github.com/techorionai/constellation-identity/internal/ports/manifests"
	"github.com/techorionai/constellation-identity/internal/ports/tokensigner"
)

// IssueServiceToken is the input of the client credentials grant. The values
// come from the form of the token request. The assertion is a secret: no log,
// span, or error text may hold it.
type IssueServiceToken struct {
	GrantType     string
	AssertionType string
	Assertion     string
	// ClientID is the form field client_id. It is optional.
	ClientID string
	Audience string
	Scope    string
	// SecondAuthentication is true if the request has a client secret or an
	// Authorization header, besides the assertion.
	SecondAuthentication bool
	// RepeatedParameter is true if a single-value parameter occurs more than
	// one time.
	RepeatedParameter bool
}

// IssueServiceTokenResult is the token and its data.
type IssueServiceTokenResult struct {
	AccessToken string
	ExpiresIn   int
	Scope       string
}

// KeySource gives the key that signs.
type KeySource interface {
	ActiveKey() (tokensigner.Key, error)
}

// IssueServiceTokenDeps are the ports of the command.
type IssueServiceTokenDeps struct {
	Issuer      string
	Clients     clients.Repository
	ClientRoles clientroles.Repository
	Manifests   manifests.Repository
	JTI         jtistore.Store
	Keys        KeySource
	Signer      tokensigner.Signer
	Parser      assertion.Parser
	Log         *slog.Logger
	// Now is the clock. The default is time.Now.
	Now func() time.Time
	// NewID makes the jti of a token. The default is a random UUID.
	NewID func() string
}

// IssueServiceTokenCommand is the use case of the client credentials grant
// with private_key_jwt.
type IssueServiceTokenCommand struct {
	d      IssueServiceTokenDeps
	issued metric.Int64Counter
	errors metric.Int64Counter
}

var _ executor.ExecutorWithReturn[IssueServiceToken, IssueServiceTokenResult] = (*IssueServiceTokenCommand)(nil)

// NewIssueServiceToken makes the command.
func NewIssueServiceToken(d IssueServiceTokenDeps) (*IssueServiceTokenCommand, error) {
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
	return &IssueServiceTokenCommand{d: d, issued: issued, errors: errs}, nil
}

// requestState is what the failure log may say about the client.
type requestState struct {
	clientID string
	verified bool
}

// Execute checks the request in the order of docs/tokens.md and signs the
// token. Each failure is an *apperrors.OAuthError.
func (c *IssueServiceTokenCommand) Execute(ctx context.Context, in IssueServiceToken) (IssueServiceTokenResult, error) {
	var st requestState
	res, err := c.issue(ctx, in, &st)
	if err != nil {
		code := apperrors.OAuthServerError
		if oe, ok := apperrors.AsOAuthError(err); ok {
			code = oe.Code
		}
		c.errors.Add(ctx, 1, metric.WithAttributes(attribute.String("error", code)))
		// The log record has the error code and the client ID. It never has
		// the assertion, the form, or the cause text of a check.
		field := "client.id_unverified"
		if st.verified {
			field = "client.id"
		}
		c.d.Log.WarnContext(ctx, "token request failed", "error_code", code, field, truncate(st.clientID, 64))
		return IssueServiceTokenResult{}, err
	}
	c.issued.Add(ctx, 1, metric.WithAttributes(
		attribute.String("grant_type", "client_credentials"),
		attribute.String("principal_type", domain.PrincipalService)))
	return res, nil
}

func fail(code, description string, cause error) error {
	return apperrors.NewOAuthError(code, description, cause)
}

const authFailed = "The client authentication failed."

func (c *IssueServiceTokenCommand) issue(ctx context.Context, in IssueServiceToken, st *requestState) (IssueServiceTokenResult, error) {
	// 1. The request.
	switch {
	case in.GrantType == "":
		return IssueServiceTokenResult{}, fail(apperrors.OAuthInvalidRequest, "The grant_type is required.", nil)
	case in.GrantType != "client_credentials":
		return IssueServiceTokenResult{}, fail(apperrors.OAuthUnsupportedGrantType, "The grant type is not supported.", nil)
	case in.RepeatedParameter:
		return IssueServiceTokenResult{}, fail(apperrors.OAuthInvalidRequest, "A parameter occurs more than one time.", nil)
	case in.SecondAuthentication:
		return IssueServiceTokenResult{}, fail(apperrors.OAuthInvalidRequest, "Use client_assertion as the only client authentication.", nil)
	case in.AssertionType != domain.AssertionType || in.Assertion == "":
		return IssueServiceTokenResult{}, fail(apperrors.OAuthInvalidRequest, "The client_assertion_type and the client_assertion are required.", nil)
	}

	// 2. The assertion header.
	a, err := c.d.Parser.Parse(in.Assertion)
	if err != nil {
		return IssueServiceTokenResult{}, fail(apperrors.OAuthInvalidClient, authFailed, errors.New("the assertion cannot be parsed"))
	}
	if a.Algorithm() != domain.AlgES256 || a.KeyID() == "" {
		return IssueServiceTokenResult{}, fail(apperrors.OAuthInvalidClient, authFailed, errors.New("the alg or the kid is not valid"))
	}

	// 3. The client.
	st.clientID = a.Subject()
	client, err := c.d.Clients.Get(ctx, a.Subject())
	if errors.Is(err, clients.ErrNotFound) {
		return IssueServiceTokenResult{}, fail(apperrors.OAuthInvalidClient, authFailed, errors.New("unknown client"))
	}
	if err != nil {
		return IssueServiceTokenResult{}, fail(apperrors.OAuthServerError, "The server has an internal error.", err)
	}
	if client.Disabled {
		return IssueServiceTokenResult{}, fail(apperrors.OAuthInvalidClient, authFailed, errors.New("the client is disabled"))
	}
	if client.Type != domain.ClientTypeService {
		return IssueServiceTokenResult{}, fail(apperrors.OAuthUnauthorizedClient, "The client must not use this grant.", nil)
	}

	// 4. The key and the signature.
	keys, err := c.d.Clients.Keys(ctx, client.ID)
	if err != nil {
		return IssueServiceTokenResult{}, fail(apperrors.OAuthServerError, "The server has an internal error.", err)
	}
	i := slices.IndexFunc(keys, func(k domain.ClientKey) bool { return k.KID == a.KeyID() })
	if i < 0 {
		return IssueServiceTokenResult{}, fail(apperrors.OAuthInvalidClient, authFailed, errors.New("unknown kid"))
	}
	claims, err := a.Verify(keys[i].PublicJWK)
	if err != nil {
		return IssueServiceTokenResult{}, fail(apperrors.OAuthInvalidClient, authFailed, errors.New("the signature is not valid"))
	}
	st.verified = true

	// 5. The claims.
	now := c.d.Now()
	if err := claims.Check(c.d.Issuer, now); err != nil {
		return IssueServiceTokenResult{}, fail(apperrors.OAuthInvalidClient, authFailed, err)
	}
	if in.ClientID != "" && in.ClientID != claims.Subject {
		return IssueServiceTokenResult{}, fail(apperrors.OAuthInvalidClient, authFailed, errors.New("client_id is not equal to sub"))
	}

	// 6. Replay protection. A store error means no token (fail closed).
	first, err := c.d.JTI.Claim(ctx, client.ID, claims.JTI, domain.ReplayTTL(*claims.ExpiresAt, now))
	if err != nil {
		return IssueServiceTokenResult{}, fail(apperrors.OAuthTemporarilyUnavailable, "The service is not available. Try again.", err)
	}
	if !first {
		return IssueServiceTokenResult{}, fail(apperrors.OAuthInvalidClient, authFailed, errors.New("the jti was used"))
	}

	// 7. The audience.
	if !domain.ValidAppKey(in.Audience) {
		return IssueServiceTokenResult{}, fail(apperrors.OAuthInvalidTarget, "The audience is required and must be an app with a manifest.", nil)
	}
	has, err := c.d.Manifests.HasManifest(ctx, in.Audience)
	if err != nil {
		return IssueServiceTokenResult{}, fail(apperrors.OAuthServerError, "The server has an internal error.", err)
	}
	if !has {
		return IssueServiceTokenResult{}, fail(apperrors.OAuthInvalidTarget, "The audience is required and must be an app with a manifest.", nil)
	}

	// 8. The scopes.
	granted, err := c.d.ClientRoles.GrantedPermissions(ctx, client.ID, domain.ServiceRole)
	if err != nil {
		return IssueServiceTokenResult{}, fail(apperrors.OAuthServerError, "The server has an internal error.", err)
	}
	scopes, err := domain.GrantScopes(in.Audience, in.Scope, granted)
	if err != nil {
		return IssueServiceTokenResult{}, fail(apperrors.OAuthInvalidScope, "The scope is required. Each scope must be a permission of the audience that the client has.", err)
	}

	key, err := c.d.Keys.ActiveKey()
	if err != nil {
		return IssueServiceTokenResult{}, fail(apperrors.OAuthTemporarilyUnavailable, "The service is not available. Try again.", err)
	}
	token := domain.ServiceToken{
		Issuer: c.d.Issuer, Audience: in.Audience, ClientID: client.ID, Scopes: scopes, Now: now, JTI: c.d.NewID(),
	}
	signed, err := c.d.Signer.Sign(key, token.Claims(), map[string]any{"typ": domain.AccessTokenType})
	if err != nil {
		return IssueServiceTokenResult{}, fail(apperrors.OAuthServerError, "The server has an internal error.", err)
	}
	res := IssueServiceTokenResult{
		AccessToken: signed,
		ExpiresIn:   int(domain.AccessTokenLifetime / time.Second),
		Scope:       strings.Join(scopes, " "),
	}
	return res, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// newUUID returns a random UUID (version 4).
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("commands: no random source: " + err.Error())
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
