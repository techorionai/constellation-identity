// Package httpapi holds the HTTP handlers of the identity service. They are the
// primary adapters. They call internal/app only.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/techorionai/constellation-platform-go/executor"
	"github.com/techorionai/constellation-platform-go/requestid"
	"go.opentelemetry.io/otel/trace"

	"github.com/techorionai/constellation-identity/internal/app/queries"
	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/handlers/http/gen"
)

var errNotImplemented = errors.New("not implemented")

// Cache-Control values of the public documents.
const (
	jwksCacheControl      = "public, max-age=300"
	discoveryCacheControl = "public, max-age=3600"
)

// Server implements the generated strict server interface. The operations of
// later issues come from the embedded type and answer 501.
type Server struct {
	unimplemented
	jwks      executor.ExecutorWithReturn[queries.GetJWKS, queries.GetJWKSResult]
	discovery executor.ExecutorWithReturn[queries.GetDiscovery, queries.DiscoveryResult]
	log       *slog.Logger
}

var _ gen.StrictServerInterface = (*Server)(nil)

// Deps are the use cases that the handlers call.
type Deps struct {
	JWKS      executor.ExecutorWithReturn[queries.GetJWKS, queries.GetJWKSResult]
	Discovery executor.ExecutorWithReturn[queries.GetDiscovery, queries.DiscoveryResult]
	Log       *slog.Logger
}

// New makes the server.
func New(d Deps) *Server {
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	return &Server{jwks: d.JWKS, discovery: d.Discovery, log: log}
}

// Handler returns the router of all operations of the contract, with the
// error handlers that write Problem and OAuthError bodies.
func (s *Server) Handler() http.Handler {
	strict := gen.NewStrictHandlerWithOptions(s, nil, gen.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  s.requestError,
		ResponseErrorHandlerFunc: s.responseError,
	})
	return gen.HandlerWithOptions(strict, gen.StdHTTPServerOptions{ErrorHandlerFunc: s.requestError})
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
	res, err := s.jwks.Execute(ctx, queries.GetJWKS{})
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
	d, err := s.discovery.Execute(ctx, queries.GetDiscovery{})
	if err != nil {
		return nil, err
	}
	doc := gen.DiscoveryDocument{
		Issuer:                                     d.Issuer,
		AuthorizationEndpoint:                      d.AuthorizationEndpoint,
		TokenEndpoint:                              d.TokenEndpoint,
		UserinfoEndpoint:                           d.UserinfoEndpoint,
		EndSessionEndpoint:                         d.EndSessionEndpoint,
		RevocationEndpoint:                         d.RevocationEndpoint,
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

// OAuthToken answers every grant with unsupported_grant_type until issue 2
// adds the grants.
func (s *Server) OAuthToken(context.Context, gen.OAuthTokenRequestObject) (gen.OAuthTokenResponseObject, error) {
	var code gen.OAuthErrorCode
	if err := code.FromOAuthErrorCode0(gen.UnsupportedGrantType); err != nil {
		return nil, err
	}
	desc := "The grant type is not supported."
	return gen.OAuthToken400JSONResponse(gen.OAuthError{Error: code, ErrorDescription: &desc}), nil
}

func (s *Server) requestError(w http.ResponseWriter, r *http.Request, err error) {
	if strings.HasPrefix(r.URL.Path, "/oauth/") {
		s.writeOAuthError(w, http.StatusBadRequest, gen.InvalidRequest, "The request is not valid.")
		return
	}
	s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", "The request is not valid.")
}

func (s *Server) responseError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errNotImplemented) {
		s.writeProblem(w, r, http.StatusNotImplemented, "not_implemented", "Not implemented", "The operation is not implemented.")
		return
	}
	switch apperrors.CodeOf(err) {
	case apperrors.InvalidInput:
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", "The request is not valid.")
	case apperrors.NotFound:
		s.writeProblem(w, r, http.StatusNotFound, "not_found", "Not found", "The resource does not exist.")
	case apperrors.Unavailable:
		s.writeProblem(w, r, http.StatusServiceUnavailable, "unavailable", "Service unavailable", "The service is not available.")
	default:
		// The error text can hold internal data. It goes to the log only.
		s.log.ErrorContext(r.Context(), "request failed", "error", err)
		s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "Internal error", "The server has an internal error.")
	}
}

func (s *Server) writeProblem(w http.ResponseWriter, r *http.Request, status int, code, title, detail string) {
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
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(p)
}

func (s *Server) writeOAuthError(w http.ResponseWriter, status int, code gen.OAuthErrorCode0, desc string) {
	var c gen.OAuthErrorCode
	_ = c.FromOAuthErrorCode0(code)
	body := gen.OAuthError{Error: c, ErrorDescription: &desc}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
