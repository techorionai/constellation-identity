// Package httpapi holds the HTTP handlers of the identity service. They are the
// primary adapters. They call internal/app only.
package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/techorionai/constellation-platform-go/auth"
	"github.com/techorionai/constellation-platform-go/executor"
	"github.com/techorionai/constellation-platform-go/requestid"
	"go.opentelemetry.io/otel/trace"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	"github.com/techorionai/constellation-identity/internal/app/queries"
	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/handlers/http/gen"
)

var errNotImplemented = errors.New("not implemented")

// Cache-Control values of the public documents.
const (
	jwksCacheControl      = "public, max-age=300"
	discoveryCacheControl = "public, max-age=3600"
)

// maxBodyBytes is the largest request body.
const maxBodyBytes = 1 << 20

// Server implements the generated strict server interface. The operations of
// later issues come from the embedded type and answer 501.
type Server struct {
	unimplemented
	d      Deps
	log    *slog.Logger
	authMW func(http.Handler) http.Handler
}

var _ gen.StrictServerInterface = (*Server)(nil)

// Deps are the use cases that the handlers call, and the token check of /v1.
type Deps struct {
	JWKS            executor.ExecutorWithReturn[queries.GetJWKS, queries.GetJWKSResult]
	Discovery       executor.ExecutorWithReturn[queries.GetDiscovery, queries.DiscoveryResult]
	IssueToken      executor.ExecutorWithReturn[commands.IssueServiceToken, commands.IssueServiceTokenResult]
	PublishManifest executor.ExecutorWithReturn[commands.PublishManifest, domain.PublishedManifest]
	ListManifests   executor.ExecutorWithReturn[queries.ListManifests, queries.ListManifestsResult]
	GetManifest     executor.ExecutorWithReturn[queries.GetManifest, domain.PublishedManifest]
	ListRoles       executor.ExecutorWithReturn[queries.ListRoles, queries.ListRolesResult]
	GetRole         executor.ExecutorWithReturn[queries.GetRole, domain.Role]
	// The use cases of the code flow, userinfo, and revoke.
	ExchangeToken executor.ExecutorWithReturn[commands.TokenExchange, commands.TokenExchangeResult]
	ExchangeCode  executor.ExecutorWithReturn[commands.ExchangeCode, commands.UserTokenResult]
	RefreshTokens executor.ExecutorWithReturn[commands.RefreshTokens, commands.UserTokenResult]
	RevokeToken   executor.Executor[commands.RevokeToken]
	UserInfo      executor.ExecutorWithReturn[commands.UserInfo, commands.UserInfoResult]
	// The use cases of the admin API.
	Admin        *commands.Admin
	APITokens    *commands.APITokens
	Introspect   executor.ExecutorWithReturn[commands.Introspect, commands.IntrospectResult]
	CreateUser   executor.ExecutorWithReturn[commands.CreateUser, commands.CreateUserResult]
	CreateInvite executor.ExecutorWithReturn[commands.CreateInvite, commands.Link]
	// MFA holds the use cases of the MFA operations.
	MFA *commands.MFA
	// IdentityLinks holds the use cases of the upstream links.
	IdentityLinks *commands.IdentityLinks
	// Now is the clock of the step-up check. The default is time.Now.
	Now func() time.Time
	// CORSOrigins gives the login redirect URIs of the public clients that are
	// not disabled. The CORS middleware answers for these origins only.
	CORSOrigins CORSOrigins
	// Denied writes the audit entry of an admin request that fails the scope
	// check. A nil value writes no entry.
	Denied DeniedRecorder
	// Verifier checks the bearer token of each /v1 request. Scopes gives the
	// scopes of each /v1 operation. Without them, each /v1 request fails with
	// a 500 Problem, because the service fails closed.
	// RateLimits counts the requests of the IP buckets. It can be nil.
	RateLimits *commands.RateLimits
	Verifier   auth.Verifier
	Scopes     ScopeTable
	Log        *slog.Logger
}

// New makes the server.
func New(d Deps) *Server {
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	s := &Server{d: d, log: log}
	if d.Verifier != nil {
		s.authMW = auth.Middleware(d.Verifier)
	}
	return s
}

// Handler returns the router of all operations of the contract, with the
// error handlers that write Problem and OAuthError bodies. The chain of each
// /v1 route is auth.Middleware, then auth.RequireScopes with the scopes of the
// operation, then the handler.
func (s *Server) Handler() http.Handler {
	strict := gen.NewStrictHandlerWithOptions(s, []gen.StrictMiddlewareFunc{captureTokenRequest, captureAccessTokenID}, gen.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  s.requestError,
		ResponseErrorHandlerFunc: s.responseError,
	})
	router := gen.HandlerWithOptions(strict, gen.StdHTTPServerOptions{
		ErrorHandlerFunc: s.requestError,
		Middlewares:      []gen.MiddlewareFunc{s.protect},
	})
	h := cors(s.d.CORSOrigins, s.rateLimit(router))
	return http.MaxBytesHandler(h, maxBodyBytes)
}

// protect runs the token check on the /v1 routes. The route pattern gives the
// scopes. A route with no entry in the scope table is an error of the service,
// and the request fails (fail closed).
func (s *Server) protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/") {
			next.ServeHTTP(w, r)
			return
		}
		scopes, ok := s.d.Scopes[r.Pattern]
		if !ok || s.authMW == nil {
			s.log.ErrorContext(r.Context(), "a /v1 route has no scope table entry or the service has no verifier", "pattern", r.Pattern)
			s.writeProblem(w, r, http.StatusInternalServerError, "auth_not_configured", "Authentication not configured", "The server has an internal error.")
			return
		}
		s.authMW(s.auditDenied(r.Pattern, scopes, auth.RequireScopes(scopes...)(s.rejectUnknownClientFields(next)))).ServeHTTP(w, r)
	})
}

type tokenRequestKey struct{}

// tokenRequest holds the parts of the HTTP request that the generated code does
// not pass to the handler.
type tokenRequest struct {
	post                 url.Values
	repeated             bool
	secondAuthentication bool
	authorization        string
}

// captureTokenRequest puts the form of the token request in the context.
func captureTokenRequest(f gen.StrictHandlerFunc, operation string) gen.StrictHandlerFunc {
	if operation != "OAuthToken" && operation != "OAuthRevoke" && operation != "OAuthUserinfo" && operation != "OAuthIntrospect" {
		return f
	}
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, request any) (any, error) {
		tr := tokenRequest{
			post:                 r.PostForm,
			secondAuthentication: r.Form.Has("client_secret") || hasBasicAuthorization(r),
			authorization:        r.Header.Get("Authorization"),
		}
		for _, name := range []string{"grant_type", "client_assertion_type", "client_assertion", "client_id", "audience", "scope",
			"code", "code_verifier", "redirect_uri", "refresh_token", "token", "token_type_hint",
			"subject_token", "subject_token_type", "actor_token", "actor_token_type", "requested_token_type"} {
			if len(r.Form[name]) > 1 {
				tr.repeated = true
			}
		}
		return f(context.WithValue(ctx, tokenRequestKey{}, tr), w, r, request)
	}
}

type accessTokenIDKey struct{}

// captureAccessTokenID puts the jti of the bearer token in the context for the
// link removal. The auth middleware verified the token before this step, so the
// step only reads the claim.
func captureAccessTokenID(f gen.StrictHandlerFunc, operation string) gen.StrictHandlerFunc {
	if operation != "MeIdentityLinksRemove" {
		return f
	}
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, request any) (any, error) {
		return f(context.WithValue(ctx, accessTokenIDKey{}, bearerJTI(r.Header.Get("Authorization"))), w, r, request)
	}
}

// accessTokenID returns the jti that captureAccessTokenID stored, or "".
func accessTokenID(ctx context.Context) string {
	v, _ := ctx.Value(accessTokenIDKey{}).(string)
	return v
}

// bearerJTI reads the jti claim of a bearer token without a signature check. Use
// it only after the verification of the token.
func bearerJTI(header string) string {
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		JTI string `json:"jti"`
	}
	if json.Unmarshal(raw, &c) != nil {
		return ""
	}
	return c.JTI
}

// hasBasicAuthorization reports whether the request has an Authorization header
// with the scheme Basic. This is a second authentication method. A header with
// another scheme, for example one that a gateway adds, does not change the
// result.
func hasBasicAuthorization(r *http.Request) bool {
	scheme, _, _ := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
	return strings.EqualFold(scheme, "Basic")
}

// jwksResponse adds the Cache-Control header to the JWKS response.
type jwksResponse struct {
	body gen.DiscoveryJwks200JSONResponse
}

func (r jwksResponse) VisitDiscoveryJwksResponse(w http.ResponseWriter) error {
	w.Header().Set("Cache-Control", jwksCacheControl)
	return r.body.VisitDiscoveryJwksResponse(w)
}

// discoveryResponse adds the Cache-Control header to the discovery response.
type discoveryResponse struct {
	body gen.DiscoveryOpenidConfiguration200JSONResponse
}

func (r discoveryResponse) VisitDiscoveryOpenidConfigurationResponse(w http.ResponseWriter) error {
	w.Header().Set("Cache-Control", discoveryCacheControl)
	return r.body.VisitDiscoveryOpenidConfigurationResponse(w)
}

// DiscoveryJwks serves the public signing keys.
func (s *Server) DiscoveryJwks(ctx context.Context, _ gen.DiscoveryJwksRequestObject) (gen.DiscoveryJwksResponseObject, error) {
	res, err := s.d.JWKS.Execute(ctx, queries.GetJWKS{})
	if err != nil {
		return nil, err
	}
	set := gen.JsonWebKeySet{Keys: make([]gen.JsonWebKey, 0, len(res.Keys))}
	for _, k := range res.Keys {
		jwk := gen.JsonWebKey{
			Kty: gen.JsonWebKeyKty(k.Kty),
			Crv: gen.JsonWebKeyCrv(k.Crv),
			X:   k.X,
			Y:   k.Y,
			Kid: k.Kid,
		}
		if k.Use != "" {
			use := gen.JsonWebKeyUse(k.Use)
			jwk.Use = &use
		}
		if k.Alg != "" {
			alg := gen.JsonWebKeyAlg(k.Alg)
			jwk.Alg = &alg
		}
		set.Keys = append(set.Keys, jwk)
	}
	return jwksResponse{body: gen.DiscoveryJwks200JSONResponse(set)}, nil
}

// DiscoveryOpenidConfiguration serves the OIDC discovery document.
func (s *Server) DiscoveryOpenidConfiguration(ctx context.Context, _ gen.DiscoveryOpenidConfigurationRequestObject) (gen.DiscoveryOpenidConfigurationResponseObject, error) {
	d, err := s.d.Discovery.Execute(ctx, queries.GetDiscovery{})
	if err != nil {
		return nil, err
	}
	introspection := d.IntrospectionEndpoint
	doc := gen.DiscoveryDocument{
		Issuer:                                     d.Issuer,
		AuthorizationEndpoint:                      d.AuthorizationEndpoint,
		TokenEndpoint:                              d.TokenEndpoint,
		UserinfoEndpoint:                           d.UserinfoEndpoint,
		EndSessionEndpoint:                         d.EndSessionEndpoint,
		RevocationEndpoint:                         d.RevocationEndpoint,
		IntrospectionEndpoint:                      &introspection,
		JwksUri:                                    d.JWKSURI,
		ScopesSupported:                            d.ScopesSupported,
		ResponseTypesSupported:                     d.ResponseTypesSupported,
		SubjectTypesSupported:                      d.SubjectTypesSupported,
		GrantTypesSupported:                        d.GrantTypesSupported,
		CodeChallengeMethodsSupported:              d.CodeChallengeMethodsSupported,
		IdTokenSigningAlgValuesSupported:           d.IDTokenSigningAlgValuesSupported,
		TokenEndpointAuthMethodsSupported:          d.TokenEndpointAuthMethodsSupported,
		TokenEndpointAuthSigningAlgValuesSupported: d.TokenEndpointAuthSigningAlgValuesSupported,
	}
	return discoveryResponse{body: gen.DiscoveryOpenidConfiguration200JSONResponse(doc)}, nil
}

// OAuthToken dispatches by grant_type. The grants authorization_code and
// refresh_token are for public clients. Any other value goes to the client
// credentials use case, which answers unsupported_grant_type for an unknown
// grant. The rule for a client secret or a Basic header is the same for all
// grants.
func (s *Server) OAuthToken(ctx context.Context, _ gen.OAuthTokenRequestObject) (gen.OAuthTokenResponseObject, error) {
	tr, _ := ctx.Value(tokenRequestKey{}).(tokenRequest)
	field := func(name string) string { return tr.post.Get(name) }
	switch field("grant_type") {
	case "authorization_code":
		res, err := s.d.ExchangeCode.Execute(ctx, commands.ExchangeCode{
			ClientID: field("client_id"), Code: field("code"), RedirectURI: field("redirect_uri"),
			CodeVerifier: field("code_verifier"), SecondAuthentication: tr.secondAuthentication, RepeatedParameter: tr.repeated,
		})
		if err != nil {
			return nil, err
		}
		return userTokenResponse(res), nil
	case domain.GrantTypeTokenExchange:
		res, err := s.d.ExchangeToken.Execute(ctx, commands.TokenExchange{
			AssertionType: field("client_assertion_type"), Assertion: field("client_assertion"), ClientID: field("client_id"),
			SubjectToken: field("subject_token"), SubjectTokenType: field("subject_token_type"),
			ActorToken: field("actor_token"), ActorTokenType: field("actor_token_type"),
			RequestedTokenType: field("requested_token_type"), Audience: field("audience"), Scope: field("scope"),
			SecondAuthentication: tr.secondAuthentication, RepeatedParameter: tr.repeated,
		})
		if err != nil {
			return nil, err
		}
		var issuedType gen.TokenType
		_ = issuedType.FromTokenType0(gen.TokenType0(res.IssuedTokenType))
		return gen.OAuthToken200JSONResponse{
			Body: gen.TokenResponse{
				AccessToken:     res.AccessToken,
				ExpiresIn:       int32(res.ExpiresIn), //nolint:gosec // The lifetime is a small value.
				Scope:           res.Scope,
				TokenType:       gen.Bearer,
				IssuedTokenType: &issuedType,
			},
			Headers: gen.OAuthToken200ResponseHeaders{CacheControl: "no-store", Pragma: "no-cache"},
		}, nil
	case "refresh_token":
		res, err := s.d.RefreshTokens.Execute(ctx, commands.RefreshTokens{
			ClientID: field("client_id"), RefreshToken: field("refresh_token"), Scope: field("scope"),
			SecondAuthentication: tr.secondAuthentication, RepeatedParameter: tr.repeated,
		})
		if err != nil {
			return nil, err
		}
		return userTokenResponse(res), nil
	}
	res, err := s.d.IssueToken.Execute(ctx, commands.IssueServiceToken{
		GrantType:            field("grant_type"),
		AssertionType:        field("client_assertion_type"),
		Assertion:            field("client_assertion"),
		ClientID:             field("client_id"),
		Audience:             field("audience"),
		Scope:                field("scope"),
		SecondAuthentication: tr.secondAuthentication,
		RepeatedParameter:    tr.repeated,
	})
	if err != nil {
		return nil, err
	}
	return gen.OAuthToken200JSONResponse{
		Body: gen.TokenResponse{
			AccessToken: res.AccessToken,
			ExpiresIn:   int32(res.ExpiresIn), //nolint:gosec // The lifetime is a small constant.
			Scope:       res.Scope,
			TokenType:   gen.Bearer,
		},
		Headers: gen.OAuthToken200ResponseHeaders{CacheControl: "no-store", Pragma: "no-cache"},
	}, nil
}

func userTokenResponse(res commands.UserTokenResult) gen.OAuthTokenResponseObject {
	body := gen.TokenResponse{
		AccessToken: res.AccessToken,
		ExpiresIn:   int32(res.ExpiresIn), //nolint:gosec // The lifetime is a small value.
		Scope:       res.Scope,
		TokenType:   gen.Bearer,
	}
	if res.IDToken != "" {
		body.IdToken = &res.IDToken
	}
	if res.RefreshToken != "" {
		body.RefreshToken = &res.RefreshToken
	}
	return gen.OAuthToken200JSONResponse{
		Body:    body,
		Headers: gen.OAuthToken200ResponseHeaders{CacheControl: "no-store", Pragma: "no-cache"},
	}
}

// OAuthRevoke revokes a refresh token (RFC 7009).
func (s *Server) OAuthRevoke(ctx context.Context, _ gen.OAuthRevokeRequestObject) (gen.OAuthRevokeResponseObject, error) {
	tr, _ := ctx.Value(tokenRequestKey{}).(tokenRequest)
	field := func(name string) string { return tr.post.Get(name) }
	err := s.d.RevokeToken.Execute(ctx, commands.RevokeToken{
		Token: field("token"), TokenTypeHint: field("token_type_hint"), ClientID: field("client_id"),
		AssertionType: field("client_assertion_type"), Assertion: field("client_assertion"),
		SecondAuthentication: tr.secondAuthentication, RepeatedParameter: tr.repeated,
	})
	if err != nil {
		return nil, err
	}
	return gen.OAuthRevoke200Response{}, nil
}

// OAuthUserinfo returns the claims of the user of an access token.
func (s *Server) OAuthUserinfo(ctx context.Context, _ gen.OAuthUserinfoRequestObject) (gen.OAuthUserinfoResponseObject, error) {
	tr, _ := ctx.Value(tokenRequestKey{}).(tokenRequest)
	scheme, token, _ := strings.Cut(strings.TrimSpace(tr.authorization), " ")
	if !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		return gen.OAuthUserinfo401Response{Headers: gen.OAuthUserinfo401ResponseHeaders{WWWAuthenticate: `Bearer`}}, nil
	}
	res, err := s.d.UserInfo.Execute(ctx, commands.UserInfo{AccessToken: strings.TrimSpace(token)})
	switch {
	case errors.Is(err, commands.ErrInvalidToken):
		return gen.OAuthUserinfo401Response{Headers: gen.OAuthUserinfo401ResponseHeaders{WWWAuthenticate: `Bearer error="invalid_token"`}}, nil
	case errors.Is(err, commands.ErrInsufficientScope):
		return gen.OAuthUserinfo403Response{Headers: gen.OAuthUserinfo403ResponseHeaders{WWWAuthenticate: `Bearer error="insufficient_scope"`}}, nil
	case err != nil:
		return nil, err
	}
	email, name, verified := res.Email, res.Name, true
	return gen.OAuthUserinfo200JSONResponse{
		Body:    gen.UserInfo{Sub: res.Subject, Email: &email, EmailVerified: &verified, Name: &name},
		Headers: gen.OAuthUserinfo200ResponseHeaders{CacheControl: "no-store", Pragma: "no-cache"},
	}, nil
}

// OAuthAuthorize and OAuthEndSession are served by the pages router, because
// they need the raw query, the cookie, and HTML pages. See the package pages.
// The generated operations stay for the contract. The router of the public
// server never calls them.

// userProblem maps the errors of the user use cases to a Problem.
func userProblem(err error) (status int, code, detail string, ok bool) {
	switch {
	case errors.Is(err, commands.ErrEmailTaken):
		return http.StatusConflict, "email_taken", "A user with this email exists.", true
	case errors.Is(err, commands.ErrUserNotFound):
		return http.StatusNotFound, "not_found", "The user does not exist.", true
	case errors.Is(err, commands.ErrUserDisabled):
		return http.StatusConflict, "user_disabled", "The user is disabled.", true
	case errors.Is(err, commands.ErrUserNotInvited):
		return http.StatusConflict, "user_not_invited", "The user is not in the status invited.", true
	case errors.Is(err, domain.ErrInvalidEmail), errors.Is(err, domain.ErrInvalidName):
		return http.StatusUnprocessableEntity, "invalid_user", "The email or the name breaks the rules of the identity service.", true
	}
	return 0, "", "", false
}

func (s *Server) requestError(w http.ResponseWriter, r *http.Request, _ error) {
	if strings.HasPrefix(r.URL.Path, "/oauth/") {
		s.writeOAuthErrorCode(w, http.StatusBadRequest, apperrors.OAuthInvalidRequest, "The request is not valid.")
		return
	}
	s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", "The request is not valid.")
}

func (s *Server) responseError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errReauthRequired) {
		s.writeReauthRequired(w, r)
		return
	}
	if errors.Is(err, errFreshLoginRequired) {
		s.writeFreshLoginRequired(w, r)
		return
	}
	if errors.Is(err, errNotImplemented) {
		s.writeProblem(w, r, http.StatusNotImplemented, "not_implemented", "Not implemented", "The operation is not implemented.")
		return
	}
	if oe, ok := apperrors.AsOAuthError(err); ok {
		if oe.Code == apperrors.OAuthServerError {
			// The cause can hold internal data. It goes to the log only.
			s.log.ErrorContext(r.Context(), "token request failed", "error", err)
		}
		setRetryAfter(w, oe.RetryAfter)
		s.writeOAuthErrorCode(w, oe.Status(), oe.Code, oe.Description)
		return
	}
	if ve, ok := apperrors.AsValidationError(err); ok {
		s.writeValidation(w, r, ve)
		return
	}
	if re, ok := apperrors.AsRateLimited(err); ok {
		setRetryAfter(w, re.RetryAfter)
		s.writeProblem(w, r, http.StatusTooManyRequests, "rate_limited", "Too many requests", "Too many requests. Try again later.")
		return
	}
	if errors.Is(err, apperrors.ErrRateLimiterUnavailable) {
		setRetryAfter(w, apperrors.DefaultUnavailableRetryAfter)
		s.writeProblem(w, r, http.StatusServiceUnavailable, "unavailable", "Service unavailable", "The service is not available.")
		return
	}
	if pe, ok := apperrors.AsProblem(err); ok {
		setRetryAfter(w, pe.RetryAfter)
		s.writeProblem(w, r, pe.Status, pe.Code, http.StatusText(pe.Status), pe.Detail)
		return
	}
	if status, code, detail, ok := userProblem(err); ok {
		s.writeProblem(w, r, status, code, http.StatusText(status), detail)
		return
	}
	switch apperrors.CodeOf(err) {
	case apperrors.InvalidInput:
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", "The request is not valid.")
	case apperrors.NotFound:
		s.writeProblem(w, r, http.StatusNotFound, "not_found", "Not found", "The resource does not exist.")
	case apperrors.Forbidden:
		s.writeProblem(w, r, http.StatusForbidden, "forbidden", "Forbidden", "The request is not allowed.")
	case apperrors.Unavailable:
		s.writeProblem(w, r, http.StatusServiceUnavailable, "unavailable", "Service unavailable", "The service is not available.")
	default:
		// The error text can hold internal data. It goes to the log only.
		s.log.ErrorContext(r.Context(), "request failed", "error", err)
		s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "Internal error", "The server has an internal error.")
	}
}

func (s *Server) problem(r *http.Request, status int, code, title, detail string) gen.Problem {
	p := gen.Problem{
		Type:   "about:blank",
		Title:  title,
		Status: int32(status), //nolint:gosec // The status is a small constant.
		Code:   code,
		Detail: &detail,
	}
	if id := requestid.FromContext(r.Context()); id != "" {
		p.RequestId = &id
	}
	if sc := trace.SpanContextFromContext(r.Context()); sc.HasTraceID() {
		t := sc.TraceID().String()
		p.TraceId = &t
	}
	return p
}

func (s *Server) writeProblem(w http.ResponseWriter, r *http.Request, status int, code, title, detail string) {
	p := s.problem(r, status, code, title, detail)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(p)
}

// writeValidation writes a 422 Problem with the field errors. The code of the
// Problem is the code of the first field error.
func (s *Server) writeValidation(w http.ResponseWriter, r *http.Request, ve *apperrors.ValidationError) {
	fields := make([]gen.FieldError, 0, len(ve.Fields))
	for _, f := range ve.Fields {
		fields = append(fields, gen.FieldError{Code: f.Code, Field: f.Field, Message: f.Message})
	}
	p := s.problem(r, http.StatusUnprocessableEntity, ve.Code, "Unprocessable content", "The content of the request is not valid.")
	p.Errors = &fields
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusUnprocessableEntity)
	_ = json.NewEncoder(w).Encode(p)
}

func (s *Server) writeOAuthErrorCode(w http.ResponseWriter, status int, code, desc string) {
	var c gen.OAuthErrorCode
	_ = c.FromOAuthErrorCode1(code)
	body := gen.OAuthError{Error: c, ErrorDescription: &desc}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
