package commands

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/techorionai/constellation-platform-go/transaction"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/authflow"
	"github.com/techorionai/constellation-identity/internal/ports/clients"
	"github.com/techorionai/constellation-identity/internal/ports/mfa"
	"github.com/techorionai/constellation-identity/internal/ports/refreshtokens"
	"github.com/techorionai/constellation-identity/internal/ports/sessions"
	"github.com/techorionai/constellation-identity/internal/ports/tokensigner"
	"github.com/techorionai/constellation-identity/internal/ports/tokenverifier"
	"github.com/techorionai/constellation-identity/internal/ports/userroles"
	"github.com/techorionai/constellation-identity/internal/ports/users"
)

// OIDCKeys gives the signing key and the public keys of the service.
type OIDCKeys interface {
	ActiveKey() (tokensigner.Key, error)
	JWKS() []domain.PublicJWK
}

// ServiceAuthenticator authenticates a service client with private_key_jwt.
type ServiceAuthenticator interface {
	AuthenticateService(ctx context.Context, assertionType, assertion, clientID string) (domain.Client, error)
}

// OIDCDeps are the ports and the settings of the code flow use cases.
type OIDCDeps struct {
	Issuer       string
	Clients      clients.Repository
	Users        users.Repository
	UserRoles    userroles.Repository
	Sessions     sessions.Repository
	Refresh      refreshtokens.Repository
	AuthRequests authflow.AuthRequests
	Codes        authflow.Codes
	Keys         OIDCKeys
	Signer       tokensigner.Signer
	Verifier     tokenverifier.Verifier
	ServiceAuth  ServiceAuthenticator
	Tx           transaction.Transactor
	Policy       domain.SessionPolicy
	// MFA reads the second factors of a user. It can be nil. A nil value means
	// that no user has a second factor.
	MFA mfa.Repository
	// PasskeysOn is true when the service accepts passkeys.
	PasskeysOn bool
	// RequireMFAForAdmins is the setting IDENTITY_MFA__REQUIRE_FOR_ADMINS.
	RequireMFAForAdmins bool
	AuthRequestTTL      time.Duration
	CodeTTL             time.Duration
	UserTokenTTL        time.Duration
	Log                 *slog.Logger
	// Now is the clock. The default is time.Now.
	Now Clock
}

// usedCodeTTL is the life of the used-code marker. It is longer than the life
// of a code.
const usedCodeTTL = 10 * time.Minute

// OIDC holds the use cases of the authorization code flow, the refresh
// tokens, userinfo, revoke, and end session.
type OIDC struct {
	d            OIDCDeps
	issued       metric.Int64Counter
	tokenErrors  metric.Int64Counter
	codeReuse    metric.Int64Counter
	refreshReuse metric.Int64Counter
}

// NewOIDC makes the use cases.
func NewOIDC(d OIDCDeps) (*OIDC, error) {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.UserTokenTTL == 0 {
		d.UserTokenTTL = domain.DefaultUserTokenLifetime
	}
	meter := otel.Meter("identity")
	o := &OIDC{d: d}
	var err error
	if o.issued, err = meter.Int64Counter("identity.tokens.issued", metric.WithDescription("Access tokens issued.")); err != nil {
		return nil, fmt.Errorf("make the issued counter: %w", err)
	}
	if o.tokenErrors, err = meter.Int64Counter("identity.token.errors", metric.WithDescription("Failed token requests.")); err != nil {
		return nil, fmt.Errorf("make the error counter: %w", err)
	}
	if o.codeReuse, err = meter.Int64Counter("identity.code.reuse", metric.WithDescription("Reuse of an authorization code.")); err != nil {
		return nil, fmt.Errorf("make the code reuse counter: %w", err)
	}
	if o.refreshReuse, err = meter.Int64Counter("identity.refresh_token.reuse", metric.WithDescription("Reuse of a refresh token.")); err != nil {
		return nil, fmt.Errorf("make the refresh reuse counter: %w", err)
	}
	return o, nil
}

// now returns the time with the precision of the database (microseconds), so
// that a time in a record compares correctly with a time that PostgreSQL stored.
func (o *OIDC) now() time.Time { return o.d.Now().UTC().Truncate(time.Microsecond) }

// --- authorize ---

// Authorize is the input of the authorization request. The values come from
// the raw query. The use case decides for each missing value.
type Authorize struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              string
	MaxAge              string
	HasMaxAge           bool
	// SessionToken is the session cookie value.
	SessionToken string
}

// AuthorizeKind is the kind of the result of an authorization step.
type AuthorizeKind int

// The kinds of the result.
const (
	// AuthorizeErrorPage means the handler shows an error page and does not redirect.
	AuthorizeErrorPage AuthorizeKind = iota
	// AuthorizeRedirect means the handler redirects to Location.
	AuthorizeRedirect
	// AuthorizeLogin means the handler redirects to the login page with the
	// auth request.
	AuthorizeLogin
	// AuthorizeSetupMFA means the handler redirects to the TOTP setup page. The
	// user needs MFA and has no second factor.
	AuthorizeSetupMFA
)

// AuthorizeOutcome is the result of an authorization step.
type AuthorizeOutcome struct {
	Kind          AuthorizeKind
	Location      string
	AuthRequestID string
	// Message is the text of the error page.
	Message string
}

const startAgainText = "This login request is not valid or it has expired. Go back to the application and start again."

func errorPage(msg string) AuthorizeOutcome {
	return AuthorizeOutcome{Kind: AuthorizeErrorPage, Message: msg}
}

// redirectWith adds the parameters to the query of a redirect URI.
func redirectWith(redirectURI string, params ...[2]string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}
	q := u.Query()
	for _, p := range params {
		if p[1] != "" {
			q.Set(p[0], p[1])
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func redirectError(redirectURI, state, code, desc string) AuthorizeOutcome {
	return AuthorizeOutcome{Kind: AuthorizeRedirect, Location: redirectWith(redirectURI,
		[2]string{"error", code}, [2]string{"error_description", desc}, [2]string{"state", state})}
}

// publicClient returns the public client that is not disabled. The bool is
// false for an unknown client, a disabled client, and a service client.
func (o *OIDC) publicClient(ctx context.Context, id string) (domain.Client, bool, error) {
	if id == "" {
		return domain.Client{}, false, nil
	}
	c, err := o.d.Clients.Get(ctx, id)
	if errors.Is(err, clients.ErrNotFound) {
		return domain.Client{}, false, nil
	}
	if err != nil {
		return domain.Client{}, false, err
	}
	if c.Disabled || c.Type != domain.ClientTypePublic {
		return domain.Client{}, false, nil
	}
	return c, true, nil
}

// sessionOf returns the valid session of the cookie value and its active user.
func (o *OIDC) sessionOf(ctx context.Context, token string) (domain.Session, domain.User, bool, error) {
	if token == "" || len(token) > domain.MaxTokenValueLength {
		return domain.Session{}, domain.User{}, false, nil
	}
	s, err := o.d.Sessions.GetByTokenHash(ctx, domain.HashSecret(token))
	if errors.Is(err, sessions.ErrNotFound) {
		return domain.Session{}, domain.User{}, false, nil
	}
	if err != nil {
		return domain.Session{}, domain.User{}, false, err
	}
	if !s.Valid(o.now()) {
		return domain.Session{}, domain.User{}, false, nil
	}
	u, err := o.d.Users.GetByID(ctx, s.UserID)
	if errors.Is(err, users.ErrNotFound) {
		return domain.Session{}, domain.User{}, false, nil
	}
	if err != nil {
		return domain.Session{}, domain.User{}, false, err
	}
	if u.Status != domain.UserActive {
		return domain.Session{}, domain.User{}, false, nil
	}
	return s, u, true, nil
}

// StartAuthorization checks the authorization request. It gives an error page
// for a client or a redirect URI that is not valid, a redirect with an error
// for any other problem, a redirect to the login page, or a code.
func (o *OIDC) StartAuthorization(ctx context.Context, in Authorize) (AuthorizeOutcome, error) {
	if in.ClientID == "" || in.RedirectURI == "" {
		return errorPage("The request has no client or no redirect address."), nil
	}
	client, ok, err := o.publicClient(ctx, in.ClientID)
	if err != nil {
		return AuthorizeOutcome{}, fmt.Errorf("get the client: %w", err)
	}
	if !ok {
		return errorPage("The client is not known."), nil
	}
	if !domain.MatchRedirectURI(client.RedirectURIs, in.RedirectURI) {
		return errorPage("The redirect address is not registered for this client."), nil
	}
	bad := func(code, desc string) (AuthorizeOutcome, error) {
		return redirectError(in.RedirectURI, in.State, code, desc), nil
	}
	switch {
	case in.State == "":
		return bad(apperrors.OAuthInvalidRequest, "The state is required.")
	case in.ResponseType != "code":
		return bad(apperrors.OAuthInvalidRequest, "The response_type must be code.")
	case in.CodeChallengeMethod != "S256":
		return bad(apperrors.OAuthInvalidRequest, "The code_challenge_method must be S256.")
	case !domain.ValidCodeChallenge(in.CodeChallenge):
		return bad(apperrors.OAuthInvalidRequest, "The code_challenge is not valid.")
	case strings.TrimSpace(in.Scope) == "":
		return bad(apperrors.OAuthInvalidRequest, "The scope is required.")
	case in.Nonce == "":
		return bad(apperrors.OAuthInvalidRequest, "The nonce is required.")
	}
	prompt := strings.Fields(in.Prompt)
	promptNone, promptLogin := slices.Contains(prompt, "none"), slices.Contains(prompt, "login")
	if promptNone && len(prompt) > 1 {
		return bad(apperrors.OAuthInvalidRequest, "The prompt none cannot have another value.")
	}
	maxAge := -1
	if in.HasMaxAge {
		n, err := strconv.Atoi(in.MaxAge)
		if err != nil || n < 0 {
			return bad(apperrors.OAuthInvalidRequest, "The max_age must be an integer of 0 or more.")
		}
		maxAge = n
	}
	scope, err := domain.ParseAuthorizeScope(client.App, in.Scope)
	if err != nil {
		return bad(apperrors.OAuthInvalidScope, "The scope has no permission of the application.")
	}

	sess, user, hasSession, err := o.sessionOf(ctx, in.SessionToken)
	if err != nil {
		return AuthorizeOutcome{}, fmt.Errorf("get the session: %w", err)
	}
	now := o.now()
	fresh := promptLogin || maxAge == 0
	if maxAge > 0 && hasSession && now.Sub(sess.AuthTime) > time.Duration(maxAge)*time.Second {
		fresh = true
	}
	if promptNone && (!hasSession || fresh) {
		return bad("login_required", "A login is required.")
	}
	req := domain.AuthRequest{
		ClientID: client.ID, RedirectURI: in.RedirectURI, Scope: scope.Permissions, OIDCScopes: scope.OIDC,
		State: in.State, Nonce: in.Nonce, CodeChallenge: in.CodeChallenge, CreatedAt: now, FreshLoginRequired: fresh,
	}
	if hasSession && !fresh {
		return o.complete(ctx, req, sess, user, promptNone)
	}
	id, _, err := domain.NewSecret()
	if err != nil {
		return AuthorizeOutcome{}, err
	}
	if err := o.d.AuthRequests.Put(ctx, id, req, o.d.AuthRequestTTL); err != nil {
		return AuthorizeOutcome{}, fmt.Errorf("store the auth request: %w", err)
	}
	return AuthorizeOutcome{Kind: AuthorizeLogin, AuthRequestID: id}, nil
}

// Continue is the input of the continue step.
type Continue struct {
	AuthRequestID string
	SessionToken  string
}

// CompleteAuthorization is the continue step. It uses the auth request one
// time, checks the session, selects the scopes, makes the code, and gives the
// redirect.
func (o *OIDC) CompleteAuthorization(ctx context.Context, in Continue) (AuthorizeOutcome, error) {
	if in.AuthRequestID == "" || len(in.AuthRequestID) > 128 {
		return errorPage(startAgainText), nil
	}
	req, err := o.d.AuthRequests.Take(ctx, in.AuthRequestID)
	if errors.Is(err, authflow.ErrNotFound) {
		return errorPage(startAgainText), nil
	}
	if err != nil {
		return AuthorizeOutcome{}, fmt.Errorf("read the auth request: %w", err)
	}
	sess, user, ok, err := o.sessionOf(ctx, in.SessionToken)
	if err != nil {
		return AuthorizeOutcome{}, fmt.Errorf("get the session: %w", err)
	}
	if !ok {
		return redirectError(req.RedirectURI, req.State, "login_required", "A login is required."), nil
	}
	if req.FreshLoginRequired && sess.AuthTime.Before(req.CreatedAt) {
		return redirectError(req.RedirectURI, req.State, "login_required", "A new login is required."), nil
	}
	return o.complete(ctx, req, sess, user, false)
}

// complete does steps 4 to 6 of the flow: scope selection, code, and redirect.
// With silent true (prompt=none) the user cannot do a step, so a session that
// needs MFA gets the error login_required.
func (o *OIDC) complete(ctx context.Context, req domain.AuthRequest, sess domain.Session, user domain.User, silent bool) (AuthorizeOutcome, error) {
	client, ok, err := o.publicClient(ctx, req.ClientID)
	if err != nil {
		return AuthorizeOutcome{}, fmt.Errorf("get the client: %w", err)
	}
	if !ok || !domain.MatchRedirectURI(client.RedirectURIs, req.RedirectURI) {
		return errorPage("The client or the redirect address is not valid."), nil
	}
	granted, err := o.d.UserRoles.GrantedPermissions(ctx, user.ID, domain.ImplicitUserRoles(user.Status)...)
	if err != nil {
		return AuthorizeOutcome{}, fmt.Errorf("get the permissions: %w", err)
	}
	selected := domain.IntersectScopes(req.Scope, granted)
	if len(selected) == 0 {
		return redirectError(req.RedirectURI, req.State, apperrors.OAuthInvalidScope, "The user has no permission for the requested scope."), nil
	}
	// The rule "MFA for admins": a user that needs MFA and has a session with no
	// mfa gets no code.
	if domain.NeedsMFA(o.d.RequireMFAForAdmins, granted) && !domain.HasMFA(sess.AuthMethods) {
		if silent {
			return redirectError(req.RedirectURI, req.State, "login_required", "A login with a second factor is required."), nil
		}
		return o.mfaGate(ctx, req, user)
	}
	code, hash, err := domain.NewSecret()
	if err != nil {
		return AuthorizeOutcome{}, err
	}
	rec := domain.AuthCode{
		ClientID: client.ID, RedirectURI: req.RedirectURI, CodeChallenge: req.CodeChallenge, Nonce: req.Nonce,
		SessionID: sess.ID, UserID: user.ID, Scope: selected, OIDCScopes: req.OIDCScopes, AuthTime: sess.AuthTime,
		AuthMethods: sess.AuthMethods, UpstreamAuthValid: sess.UpstreamAuthValid,
	}
	if err := o.d.Codes.Put(ctx, hash, rec, o.d.CodeTTL); err != nil {
		return AuthorizeOutcome{}, fmt.Errorf("store the code: %w", err)
	}
	return AuthorizeOutcome{Kind: AuthorizeRedirect, Location: redirectWith(req.RedirectURI,
		[2]string{"code", code}, [2]string{"state", req.State})}, nil
}

// mfaGate is the answer for a user that needs MFA and has a session with no
// mfa. A user with no second factor goes to the TOTP setup page. A user with a
// second factor logs in again, and the login asks for the second factor.
func (o *OIDC) mfaGate(ctx context.Context, req domain.AuthRequest, user domain.User) (AuthorizeOutcome, error) {
	if o.d.MFA != nil {
		state, err := o.d.MFA.State(ctx, user.ID)
		if err != nil {
			return AuthorizeOutcome{}, fmt.Errorf("read the MFA state: %w", err)
		}
		state.PasskeysOn = o.d.PasskeysOn
		if state.Enabled() {
			req.FreshLoginRequired = true
			req.CreatedAt = o.now()
			id, _, err := domain.NewSecret()
			if err != nil {
				return AuthorizeOutcome{}, err
			}
			if err := o.d.AuthRequests.Put(ctx, id, req, o.d.AuthRequestTTL); err != nil {
				return AuthorizeOutcome{}, fmt.Errorf("store the auth request: %w", err)
			}
			return AuthorizeOutcome{Kind: AuthorizeLogin, AuthRequestID: id}, nil
		}
	}
	// The user comes back to the auth request after the setup (R6).
	id, _, err := domain.NewSecret()
	if err != nil {
		return AuthorizeOutcome{}, err
	}
	if err := o.d.AuthRequests.Put(ctx, id, req, o.d.AuthRequestTTL); err != nil {
		return AuthorizeOutcome{}, fmt.Errorf("store the auth request: %w", err)
	}
	return AuthorizeOutcome{Kind: AuthorizeSetupMFA, AuthRequestID: id}, nil
}

// AuthRequestInfo is what the login page needs from an auth request.
type AuthRequestInfo struct {
	// FormActionOrigin is the origin of the redirect URI.
	FormActionOrigin string
}

// ErrAuthRequestGone means the auth request does not exist or has expired.
var ErrAuthRequestGone = errors.New("the auth request is not available")

// LookupAuthRequest reads an auth request and does not delete it. The login
// page uses it to set the CSP form-action.
func (o *OIDC) LookupAuthRequest(ctx context.Context, id string) (AuthRequestInfo, error) {
	if id == "" || len(id) > 128 {
		return AuthRequestInfo{}, ErrAuthRequestGone
	}
	req, err := o.d.AuthRequests.Get(ctx, id)
	if errors.Is(err, authflow.ErrNotFound) {
		return AuthRequestInfo{}, ErrAuthRequestGone
	}
	if err != nil {
		return AuthRequestInfo{}, fmt.Errorf("read the auth request: %w", err)
	}
	origin, ok := domain.RedirectOrigin(req.RedirectURI)
	if !ok {
		return AuthRequestInfo{}, ErrAuthRequestGone
	}
	return AuthRequestInfo{FormActionOrigin: origin}, nil
}

// --- token endpoint ---

// UserTokenResult is the answer of the token endpoint for a user.
type UserTokenResult struct {
	AccessToken  string
	IDToken      string
	RefreshToken string
	Scope        string
	ExpiresIn    int
}

func grantErr(desc string) error {
	return apperrors.NewOAuthError(apperrors.OAuthInvalidGrant, desc, nil)
}

func unavailableErr(cause error) error {
	return apperrors.NewOAuthError(apperrors.OAuthTemporarilyUnavailable, "The service is not available. Try again.", cause)
}

func serverErr(cause error) error {
	return apperrors.NewOAuthError(apperrors.OAuthServerError, "The server has an internal error.", cause)
}

func (o *OIDC) countError(ctx context.Context, grant, clientID string, err error) {
	code := apperrors.OAuthServerError
	if oe, ok := apperrors.AsOAuthError(err); ok {
		code = oe.Code
	}
	o.tokenErrors.Add(ctx, 1, metric.WithAttributes(attribute.String("error", code)))
	o.d.Log.WarnContext(ctx, "token request failed", "error_code", code, "grant_type", grant, "client.id_unverified", truncate(clientID, 64))
}

// ExchangeCode is the input of the authorization_code grant.
type ExchangeCode struct {
	ClientID     string
	Code         string
	RedirectURI  string
	CodeVerifier string
	// SecondAuthentication is true if the request has a client secret or an
	// Authorization header with the scheme Basic.
	SecondAuthentication bool
	// RepeatedParameter is true if a single-value parameter occurs more than
	// one time.
	RepeatedParameter bool
}

// ExchangeCode runs the checks of the token request for a code in the order of
// the plan, claims the code, and makes the tokens.
func (o *OIDC) ExchangeCode(ctx context.Context, in ExchangeCode) (UserTokenResult, error) {
	res, err := o.exchangeCode(ctx, in)
	if err != nil {
		o.countError(ctx, "authorization_code", in.ClientID, err)
	}
	return res, err
}

func (o *OIDC) exchangeCode(ctx context.Context, in ExchangeCode) (UserTokenResult, error) {
	if in.SecondAuthentication || in.RepeatedParameter {
		return UserTokenResult{}, apperrors.NewOAuthError(apperrors.OAuthInvalidRequest, "A public client sends client_id only. The request must not have a secret or repeated parameters.", nil)
	}
	if in.Code == "" || len(in.Code) > 512 {
		return UserTokenResult{}, apperrors.NewOAuthError(apperrors.OAuthInvalidRequest, "The code is required.", nil)
	}
	// 1. The client.
	client, ok, err := o.publicClient(ctx, in.ClientID)
	if err != nil {
		return UserTokenResult{}, serverErr(err)
	}
	if !ok {
		return UserTokenResult{}, apperrors.NewOAuthError(apperrors.OAuthInvalidClient, "The client is not known.", nil)
	}
	// 2. Read the code. A read does not delete it.
	hash := domain.HashSecret(in.Code)
	rec, err := o.d.Codes.Peek(ctx, hash)
	if errors.Is(err, authflow.ErrNotFound) {
		return UserTokenResult{}, o.unknownCode(ctx, hash, in)
	}
	if err != nil {
		return UserTokenResult{}, unavailableErr(err)
	}
	// 3 to 5. The client, the redirect URI, and the PKCE check. A failed check
	// does not use the code.
	if rec.ClientID != client.ID {
		return UserTokenResult{}, grantErr("The code is not valid.")
	}
	if in.RedirectURI == "" || in.RedirectURI != rec.RedirectURI {
		return UserTokenResult{}, grantErr("The redirect_uri is not valid.")
	}
	if !domain.VerifyPKCE(rec.CodeChallenge, in.CodeVerifier) {
		return UserTokenResult{}, grantErr("The code_verifier is not valid.")
	}
	// 6. The session and the user.
	sess, err := o.d.Sessions.GetByID(ctx, rec.SessionID)
	if errors.Is(err, sessions.ErrNotFound) {
		return UserTokenResult{}, grantErr("The session has ended.")
	}
	if err != nil {
		return UserTokenResult{}, serverErr(err)
	}
	user, err := o.d.Users.GetByID(ctx, rec.UserID)
	if errors.Is(err, users.ErrNotFound) {
		return UserTokenResult{}, grantErr("The session has ended.")
	}
	if err != nil {
		return UserTokenResult{}, serverErr(err)
	}
	now := o.now()
	if !sess.Valid(now) || user.Status != domain.UserActive {
		return UserTokenResult{}, grantErr("The session has ended.")
	}
	// 7. The tokens are signed before the code is claimed. If the key or the
	// signer fails, the code stays valid and the client can try again.
	access, idToken, err := o.mint(ctx, client, user, rec.Scope, rec.OIDCScopes, tokenAuth{AuthTime: rec.AuthTime, Methods: rec.AuthMethods, UpstreamAuthValid: rec.UpstreamAuthValid}, &idTokenInput{
		Nonce: rec.Nonce, AuthTime: rec.AuthTime, SessionID: sess.ID,
	})
	if err != nil {
		return UserTokenResult{}, err
	}
	// 8. Claim the code. The first request that claims it wins.
	if _, err := o.d.Codes.Claim(ctx, hash); errors.Is(err, authflow.ErrNotFound) {
		return UserTokenResult{}, grantErr("The code is not valid.")
	} else if err != nil {
		return UserTokenResult{}, unavailableErr(err)
	}
	marker := domain.UsedCode{SessionID: rec.SessionID, CodeChallenge: rec.CodeChallenge, ClientID: rec.ClientID}
	if err := o.d.Codes.MarkUsed(ctx, hash, marker, usedCodeTTL); err != nil {
		return UserTokenResult{}, unavailableErr(err)
	}
	// 9. The refresh token. The family is made now, in one statement that checks the
	// session.
	refresh := ""
	if slices.Contains(rec.OIDCScopes, domain.ScopeOfflineAccess) {
		value, tokenHash, err := domain.NewSecret()
		if err != nil {
			return UserTokenResult{}, serverErr(err)
		}
		fam := domain.RefreshFamily{
			ID: newUUID(), SessionID: sess.ID, ClientID: client.ID, UserID: user.ID,
			Scope: rec.Scope, OIDCScopes: rec.OIDCScopes, CreatedAt: now,
			AuthTime: rec.AuthTime, AuthMethods: rec.AuthMethods, UpstreamAuthValid: rec.UpstreamAuthValid,
		}
		tok := domain.RefreshToken{Hash: tokenHash, FamilyID: fam.ID, CreatedAt: now, ExpiresAt: sess.ExpiresAt}
		inserted, err := o.d.Refresh.InsertFamilyIfSessionValid(ctx, fam, tok, now)
		if err != nil {
			return UserTokenResult{}, serverErr(err)
		}
		if !inserted {
			return UserTokenResult{}, grantErr("The session has ended.")
		}
		refresh = value
	} else {
		again, err := o.d.Sessions.GetByID(ctx, sess.ID)
		if err != nil || !again.Valid(now) {
			return UserTokenResult{}, grantErr("The session has ended.")
		}
	}
	o.issued.Add(ctx, 1, metric.WithAttributes(attribute.String("grant_type", "authorization_code"), attribute.String("principal_type", domain.PrincipalUser)))
	return UserTokenResult{
		AccessToken: access, IDToken: idToken, RefreshToken: refresh,
		Scope: strings.Join(rec.Scope, " "), ExpiresIn: int(o.d.UserTokenTTL / time.Second),
	}, nil
}

// unknownCode handles a code that has no record. A marker with the same client
// ID and a matching verifier shows a reuse. Only then the service revokes the
// session. A read error revokes nothing.
func (o *OIDC) unknownCode(ctx context.Context, hash string, in ExchangeCode) error {
	marker, err := o.d.Codes.GetUsed(ctx, hash)
	if errors.Is(err, authflow.ErrNotFound) {
		return grantErr("The code is not valid.")
	}
	if err != nil {
		return unavailableErr(err)
	}
	if marker.ReuseRevokes(in.ClientID, in.CodeVerifier) {
		if _, err := o.d.Sessions.RevokeCascade(ctx, marker.SessionID, o.now()); err != nil {
			return serverErr(err)
		}
		o.codeReuse.Add(ctx, 1)
		o.d.Log.WarnContext(ctx, "authorization code reuse", "event", "identity.code.reuse",
			"session_id", marker.SessionID, "client_id", marker.ClientID)
	}
	return grantErr("The code is not valid.")
}

type idTokenInput struct {
	Nonce     string
	AuthTime  time.Time
	SessionID string
}

// tokenAuth is the login data of a user token: the auth time and the methods.
// A zero time and an empty list give no claim.
type tokenAuth struct {
	AuthTime time.Time
	Methods  []string
	// UpstreamAuthValid makes the service store the jti of the access token. The
	// value is not in a token (P24).
	UpstreamAuthValid bool
}

// mint signs the access token, and the ID token if the scope has openid.
func (o *OIDC) mint(ctx context.Context, client domain.Client, user domain.User, scopes, oidcScopes []string, auth tokenAuth, idt *idTokenInput) (string, string, error) {
	key, err := o.d.Keys.ActiveKey()
	if err != nil {
		return "", "", unavailableErr(err)
	}
	now := o.now()
	jti := newUUID()
	access, err := o.d.Signer.Sign(key, domain.UserAccessToken{
		Issuer: o.d.Issuer, Audience: client.App, UserID: user.ID, ClientID: client.ID,
		Scopes: scopes, Now: now, TTL: o.d.UserTokenTTL, JTI: jti,
		AuthMethods: auth.Methods, AuthTime: auth.AuthTime,
	}.Claims(), map[string]any{"typ": domain.AccessTokenType})
	if err != nil {
		return "", "", serverErr(err)
	}
	if auth.UpstreamAuthValid {
		// The service keeps the fact in its storage. The tokens do not have it.
		if err := o.d.Sessions.MarkAccessToken(ctx, jti, user.ID, now.Add(o.d.UserTokenTTL), now); err != nil {
			return "", "", serverErr(err)
		}
	}
	if idt == nil || !slices.Contains(oidcScopes, domain.ScopeOpenID) {
		return access, "", nil
	}
	t := domain.IDToken{
		Issuer: o.d.Issuer, UserID: user.ID, ClientID: client.ID, AuthTime: idt.AuthTime, Nonce: idt.Nonce,
		SessionID: idt.SessionID, Now: now, TTL: o.d.UserTokenTTL, AuthMethods: auth.Methods,
	}
	if slices.Contains(oidcScopes, domain.ScopeEmail) {
		email := user.Email
		t.Email = &email
	}
	if slices.Contains(oidcScopes, domain.ScopeProfile) {
		name := user.Name
		t.Name = &name
	}
	id, err := o.d.Signer.Sign(key, t.Claims(), map[string]any{"typ": domain.IDTokenType})
	if err != nil {
		return "", "", serverErr(err)
	}
	return access, id, nil
}

// RefreshTokens is the input of the refresh_token grant.
type RefreshTokens struct {
	ClientID             string
	RefreshToken         string
	Scope                string
	SecondAuthentication bool
	RepeatedParameter    bool
}

// errRefreshRejected rolls back a rotation with no change. The use case maps
// it to invalid_grant.
var errRefreshRejected = errors.New("the refresh token is rejected")

// errRefreshScope rolls back a rotation. The use case maps it to invalid_scope.
var errRefreshScope = errors.New("the refresh scope is not valid")

// RefreshTokens rotates a refresh token. All checks run inside the family lock,
// before the token is marked as used.
func (o *OIDC) RefreshTokens(ctx context.Context, in RefreshTokens) (UserTokenResult, error) {
	res, err := o.refresh(ctx, in)
	if err != nil {
		o.countError(ctx, "refresh_token", in.ClientID, err)
	}
	return res, err
}

func (o *OIDC) refresh(ctx context.Context, in RefreshTokens) (UserTokenResult, error) {
	if in.SecondAuthentication || in.RepeatedParameter {
		return UserTokenResult{}, apperrors.NewOAuthError(apperrors.OAuthInvalidRequest, "A public client sends client_id only. The request must not have a secret or repeated parameters.", nil)
	}
	if in.RefreshToken == "" || len(in.RefreshToken) > 512 {
		return UserTokenResult{}, apperrors.NewOAuthError(apperrors.OAuthInvalidRequest, "The refresh_token is required.", nil)
	}
	if in.ClientID == "" {
		return UserTokenResult{}, apperrors.NewOAuthError(apperrors.OAuthInvalidRequest, "The client_id is required.", nil)
	}
	c, err := o.d.Clients.Get(ctx, in.ClientID)
	if err != nil && !errors.Is(err, clients.ErrNotFound) {
		return UserTokenResult{}, serverErr(err)
	}
	if err == nil && c.Type != domain.ClientTypePublic {
		return UserTokenResult{}, apperrors.NewOAuthError(apperrors.OAuthInvalidClient, "The client is not known.", nil)
	}
	hash := domain.HashSecret(in.RefreshToken)
	value, tokenHash, err := domain.NewSecret()
	if err != nil {
		return UserTokenResult{}, serverErr(err)
	}
	var (
		reused    bool
		reusedFam domain.RefreshFamily
		scopes    []string
		access    string
		mintErr   error
	)
	err = o.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		// 0. The session row first. 1. The family row. This is the lock order of
		// all paths.
		if _, ok, err := o.d.Refresh.LockSessionOfToken(ctx, hash); err != nil {
			return err
		} else if !ok {
			return errRefreshRejected
		}
		f, ok, err := o.d.Refresh.LockFamilyOfToken(ctx, hash)
		if err != nil {
			return err
		}
		if !ok || f.RevokedAt != nil {
			return errRefreshRejected
		}
		tok, err := o.d.Refresh.GetToken(ctx, hash)
		if err != nil {
			return err
		}
		now := o.now()
		// 2. A used token is a reuse, also with a wrong client_id. The plan says
		// that a used token that comes back shows a theft. Revoke the family, the session, and all
		// other families of the session. The transaction commits. The error comes
		// after the commit.
		if tok.UsedAt != nil {
			reused, reusedFam = true, f
			if err := o.d.Refresh.RevokeFamily(ctx, f.ID, now); err != nil {
				return err
			}
			_, err := o.d.Sessions.RevokeCascade(ctx, f.SessionID, now)
			return err
		}
		// 3. The checks, inside the lock.
		st, err := o.d.Refresh.RefreshState(ctx, f.ID)
		if err != nil {
			return err
		}
		if in.ClientID != f.ClientID || st.ClientDisabled || !st.UserActive || !st.Session.Valid(now) || !now.Before(tok.ExpiresAt) {
			return errRefreshRejected
		}
		u, err := o.d.Users.GetByID(ctx, f.UserID)
		if err != nil {
			return err
		}
		granted, err := o.d.UserRoles.GrantedPermissions(ctx, f.UserID, domain.ImplicitUserRoles(u.Status)...)
		if err != nil {
			return err
		}
		narrowed, err := domain.NarrowScope(f.Scope, f.OIDCScopes, in.Scope)
		if err != nil {
			return errRefreshScope
		}
		effective := domain.IntersectScopes(narrowed, granted)
		if len(effective) == 0 {
			return errRefreshRejected
		}
		// The rule "MFA for admins": a family with no mfa in its methods gets no
		// new token when the user needs MFA.
		if domain.NeedsMFA(o.d.RequireMFAForAdmins, granted) && !domain.HasMFA(f.AuthMethods) {
			return errRefreshRejected
		}
		// 4. Make the access token before the token is used. If the key or the
		// signer fails, the transaction rolls back and the old token stays valid.
		client, ok, err := o.publicClient(ctx, f.ClientID)
		if err != nil {
			return err
		}
		if !ok {
			return errRefreshRejected
		}
		if access, _, mintErr = o.mint(ctx, client, u, effective, nil, tokenAuth{AuthTime: f.AuthTime, Methods: f.AuthMethods, UpstreamAuthValid: f.UpstreamAuthValid}, nil); mintErr != nil {
			return mintErr
		}
		// 5. Mark the token as used.
		used, err := o.d.Refresh.MarkUsed(ctx, hash, now)
		if err != nil {
			return err
		}
		if !used {
			return errRefreshRejected
		}
		// 6. Insert the new token.
		if err := o.d.Refresh.InsertToken(ctx, domain.RefreshToken{
			Hash: tokenHash, FamilyID: f.ID, CreatedAt: now, ExpiresAt: st.Session.ExpiresAt,
		}); err != nil {
			return err
		}
		if st.Session.NeedsTouch(now) {
			if err := o.d.Sessions.Touch(ctx, st.Session.ID, now, o.d.Policy.IdleExpiry(st.Session, now)); err != nil {
				return err
			}
		}
		scopes = effective
		return nil
	})
	switch {
	case mintErr != nil && errors.Is(err, mintErr):
		return UserTokenResult{}, mintErr
	case errors.Is(err, errRefreshRejected):
		return UserTokenResult{}, grantErr("The refresh token is not valid.")
	case errors.Is(err, errRefreshScope):
		return UserTokenResult{}, apperrors.NewOAuthError(apperrors.OAuthInvalidScope, "The scope is wider than the scope of the refresh token.", nil)
	case err != nil:
		return UserTokenResult{}, serverErr(err)
	}
	if reused {
		o.refreshReuse.Add(ctx, 1)
		o.d.Log.WarnContext(ctx, "refresh token reuse", "event", "identity.refresh_token.reuse",
			"session_id", reusedFam.SessionID, "family_id", reusedFam.ID, "client_id", reusedFam.ClientID)
		return UserTokenResult{}, grantErr("The refresh token is not valid.")
	}
	o.issued.Add(ctx, 1, metric.WithAttributes(attribute.String("grant_type", "refresh_token"), attribute.String("principal_type", domain.PrincipalUser)))
	return UserTokenResult{
		AccessToken: access, RefreshToken: value,
		Scope: strings.Join(scopes, " "), ExpiresIn: int(o.d.UserTokenTTL / time.Second),
	}, nil
}

// --- userinfo ---

// Errors of the userinfo endpoint.
var (
	// ErrInvalidToken means the bearer token is not valid. The handler gives 401.
	ErrInvalidToken = errors.New("the token is not valid")
	// ErrInsufficientScope means the token is the token of a service. The
	// handler gives 403.
	ErrInsufficientScope = errors.New("the token is not a user token")
)

// verifyOwn checks the signature, the issuer, and the header typ of a token
// that the service signed. It does not check the time claims.
func (o *OIDC) verifyOwn(token, typ string) (tokenverifier.Claims, error) {
	c, err := o.d.Verifier.Verify(token, o.d.Keys.JWKS())
	if err != nil || c.Issuer != o.d.Issuer || c.Typ != typ {
		return tokenverifier.Claims{}, ErrInvalidToken
	}
	return c, nil
}

// UserInfoResult is the claims of the userinfo response.
type UserInfoResult struct {
	Subject string
	Email   string
	Name    string
}

// UserInfo is the input of the userinfo query.
type UserInfo struct{ AccessToken string }

// GetUserInfo checks the access token and returns the claims of its user. It
// accepts any audience, but only a token of the code flow: a token with act, or
// with the client ID of something other than an enabled public client, is not
// valid. An ID token is not valid here.
func (o *OIDC) GetUserInfo(ctx context.Context, in UserInfo) (UserInfoResult, error) {
	c, err := o.verifyOwn(in.AccessToken, domain.AccessTokenType)
	if err != nil {
		return UserInfoResult{}, err
	}
	if c.ExpiresAt.IsZero() || !o.now().Before(c.ExpiresAt) {
		return UserInfoResult{}, ErrInvalidToken
	}
	if c.PrincipalType != domain.PrincipalUser {
		return UserInfoResult{}, ErrInsufficientScope
	}
	// An exchanged token is for another app. It has act, or it has the client
	// ID of a service client. It must not read the profile of the user.
	if c.HasAct {
		return UserInfoResult{}, ErrInvalidToken
	}
	if _, ok, err := o.publicClient(ctx, c.ClientID); err != nil {
		return UserInfoResult{}, fmt.Errorf("get the client: %w", err)
	} else if !ok {
		return UserInfoResult{}, ErrInvalidToken
	}
	u, err := o.d.Users.GetByID(ctx, c.Subject)
	if errors.Is(err, users.ErrNotFound) {
		return UserInfoResult{}, ErrInvalidToken
	}
	if err != nil {
		return UserInfoResult{}, fmt.Errorf("get the user: %w", err)
	}
	if u.Status != domain.UserActive {
		return UserInfoResult{}, ErrInvalidToken
	}
	return UserInfoResult{Subject: u.ID, Email: u.Email, Name: u.Name}, nil
}

// --- revoke ---

// RevokeToken is the input of the token revocation (RFC 7009).
type RevokeToken struct {
	Token         string
	TokenTypeHint string
	// ClientID is the form field client_id. A public client sends it.
	ClientID             string
	AssertionType        string
	Assertion            string
	SecondAuthentication bool
	RepeatedParameter    bool
}

// RevokeToken authenticates the client and revokes the family of a refresh
// token of the client. An unknown token and an access token give no error.
func (o *OIDC) RevokeToken(ctx context.Context, in RevokeToken) error {
	if in.SecondAuthentication || in.RepeatedParameter {
		return apperrors.NewOAuthError(apperrors.OAuthInvalidRequest, "Use one client authentication method. The request must not have repeated parameters.", nil)
	}
	if in.Token == "" || len(in.Token) > 8192 {
		return apperrors.NewOAuthError(apperrors.OAuthInvalidRequest, "The token is required.", nil)
	}
	var clientID string
	if in.Assertion != "" || in.AssertionType != "" {
		c, err := o.d.ServiceAuth.AuthenticateService(ctx, in.AssertionType, in.Assertion, in.ClientID)
		if err != nil {
			return err
		}
		clientID = c.ID
	} else {
		c, ok, err := o.publicClient(ctx, in.ClientID)
		if err != nil {
			return serverErr(err)
		}
		if !ok {
			return apperrors.NewOAuthError(apperrors.OAuthInvalidClient, "The client is not known.", nil)
		}
		clientID = c.ID
	}
	switch in.TokenTypeHint {
	case "", "refresh_token", "access_token":
	default:
		return apperrors.NewOAuthError(apperrors.OAuthUnsupportedTokenType, "The token_type_hint is not supported.", nil)
	}
	hash := domain.HashSecret(in.Token)
	other := false
	err := o.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		if _, ok, err := o.d.Refresh.LockSessionOfToken(ctx, hash); err != nil || !ok {
			return err
		}
		f, ok, err := o.d.Refresh.LockFamilyOfToken(ctx, hash)
		if err != nil || !ok {
			return err
		}
		if f.ClientID != clientID {
			other = true
			return nil
		}
		return o.d.Refresh.RevokeFamily(ctx, f.ID, o.now())
	})
	if err != nil {
		return serverErr(err)
	}
	if other {
		return apperrors.NewOAuthError(apperrors.OAuthUnauthorizedClient, "The token belongs to another client.", nil)
	}
	return nil
}

// --- end session ---

// EndSession is the input of the RP-initiated logout.
type EndSession struct {
	IDTokenHint           string
	PostLogoutRedirectURI string
	State                 string
	SessionToken          string
}

// EndSessionKind is the kind of the end session result.
type EndSessionKind int

// The kinds of the end session result.
const (
	// EndSessionErrorPage means the hint is not valid.
	EndSessionErrorPage EndSessionKind = iota
	// EndSessionLoggedOut means the handler shows the page "You are logged out".
	EndSessionLoggedOut
	// EndSessionConfirm means the handler shows the confirmation form.
	EndSessionConfirm
	// EndSessionRedirect means the handler redirects to Location.
	EndSessionRedirect
)

// EndSessionOutcome is the result of the end session step.
type EndSessionOutcome struct {
	Kind        EndSessionKind
	Location    string
	ClearCookie bool
}

// StartEndSession checks the hint and decides. It revokes the session of the
// cookie at once only if the hint is valid and its sid is the ID of that
// session.
func (o *OIDC) StartEndSession(ctx context.Context, in EndSession) (EndSessionOutcome, error) {
	var (
		hintOK   bool
		hintSID  string
		postURIs []string
	)
	if in.IDTokenHint != "" {
		c, err := o.verifyOwn(in.IDTokenHint, domain.IDTokenType)
		if err != nil || len(c.Audience) != 1 {
			return EndSessionOutcome{Kind: EndSessionErrorPage}, nil
		}
		client, ok, err := o.publicClient(ctx, c.Audience[0])
		if err != nil {
			return EndSessionOutcome{}, fmt.Errorf("get the client: %w", err)
		}
		if !ok {
			return EndSessionOutcome{Kind: EndSessionErrorPage}, nil
		}
		hintOK, hintSID, postURIs = true, c.SessionID, client.PostLogoutRedirectURIs
	}
	redirect := ""
	if hintOK && in.PostLogoutRedirectURI != "" && domain.MatchRedirectURI(postURIs, in.PostLogoutRedirectURI) {
		redirect = redirectWith(in.PostLogoutRedirectURI, [2]string{"state", in.State})
	}
	done := func(clear bool) EndSessionOutcome {
		if redirect != "" {
			return EndSessionOutcome{Kind: EndSessionRedirect, Location: redirect, ClearCookie: clear}
		}
		return EndSessionOutcome{Kind: EndSessionLoggedOut, ClearCookie: clear}
	}
	sess, _, ok, err := o.sessionOf(ctx, in.SessionToken)
	if err != nil {
		return EndSessionOutcome{}, fmt.Errorf("get the session: %w", err)
	}
	switch {
	case ok && hintOK && hintSID == sess.ID:
		if _, err := o.d.Sessions.RevokeCascade(ctx, sess.ID, o.now()); err != nil {
			return EndSessionOutcome{}, fmt.Errorf("revoke the session: %w", err)
		}
		o.d.Log.InfoContext(ctx, "identity.logout", "event", "identity.logout", "user_id", sess.UserID)
		return done(true), nil
	case ok:
		return EndSessionOutcome{Kind: EndSessionConfirm}, nil
	case hintOK:
		return done(false), nil
	default:
		return EndSessionOutcome{Kind: EndSessionLoggedOut}, nil
	}
}

// ConfirmEndSession revokes the session of the cookie and its refresh token
// families. It never revokes another session. It changes nothing if the cookie
// has no valid session.
func (o *OIDC) ConfirmEndSession(ctx context.Context, token string) error {
	sess, _, ok, err := o.sessionOf(ctx, token)
	if err != nil {
		return fmt.Errorf("get the session: %w", err)
	}
	if !ok {
		return nil
	}
	if _, err := o.d.Sessions.RevokeCascade(ctx, sess.ID, o.now()); err != nil {
		return fmt.Errorf("revoke the session: %w", err)
	}
	o.d.Log.InfoContext(ctx, "identity.logout", "event", "identity.logout", "user_id", sess.UserID)
	return nil
}

// SetServiceAuthenticator sets the authenticator of the service clients for the
// revoke endpoint. The composition root calls it after it made the token use
// case, because that use case needs the key cache that starts later.
func (o *OIDC) SetServiceAuthenticator(a ServiceAuthenticator) { o.d.ServiceAuth = a }
