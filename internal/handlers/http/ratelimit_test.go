package httpapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	"github.com/techorionai/constellation-identity/internal/app/queries"
	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/config"
	"github.com/techorionai/constellation-identity/internal/domain"
	httpapi "github.com/techorionai/constellation-identity/internal/handlers/http"
	"github.com/techorionai/constellation-identity/internal/ports/ratelimit"
	"github.com/techorionai/constellation-identity/resources/test/mock"
)

type allowAll struct{}

func (allowAll) Allowed(context.Context, string) bool { return true }

func limitedServer(t *testing.T, rl *mock.RateLimiter) http.Handler {
	t.Helper()
	limits, err := commands.NewRateLimits(commands.RateLimitsDeps{Limiter: rl, Rules: config.DefaultRateRules()})
	if err != nil {
		t.Fatal(err)
	}
	return httpapi.New(httpapi.Deps{
		JWKS:        queries.NewGetJWKS(fakeKeys{[]domain.PublicJWK{{Kty: "EC", Kid: "a"}}}),
		Discovery:   queries.NewGetDiscovery("https://id.example.com"),
		RateLimits:  limits,
		CORSOrigins: allowAll{},
	}).Handler()
}

// U5: an OAuth error with RateLimited gives 429 and the OAuth headers.
func TestU5_OAuthRateLimitedWriter(t *testing.T) {
	h := limitedServer(t, &mock.RateLimiter{Deny: true, RetryAfter: 7 * time.Second})
	rec := get(h, http.MethodPost, "/oauth/token", "grant_type=client_credentials")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "7" || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("headers = %v", rec.Header())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] != "temporarily_unavailable" {
		t.Fatalf("body = %s, err = %v", rec.Body.String(), err)
	}
}

// U6: a limiter that denies gives 429 Problem for JWKS, 429 OAuth JSON for the
// token endpoint, and does not count a CORS preflight request.
func TestU6_MiddlewareDenies(t *testing.T) {
	rl := &mock.RateLimiter{Deny: true}
	h := limitedServer(t, rl)
	rec := get(h, http.MethodGet, "/.well-known/jwks.json", "")
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Content-Type") != "application/problem+json" || rec.Header().Get("Retry-After") != "7" {
		t.Fatalf("jwks: status %d, headers %v", rec.Code, rec.Header())
	}
	var p map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil || p["code"] != "rate_limited" {
		t.Fatalf("jwks body = %s", rec.Body.String())
	}
	rec = get(h, http.MethodPost, "/oauth/token", "x=1")
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("token: status %d, headers %v", rec.Code, rec.Header())
	}
	before := len(rl.Calls)
	req := httptest.NewRequestWithContext(t0(), http.MethodOptions, "/oauth/token", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || len(rl.Calls) != before {
		t.Fatalf("preflight: status %d, calls %d, want 204 and %d", rec.Code, len(rl.Calls), before)
	}
	if got := rl.Calls[0].Rule; got != ratelimit.BucketPublicMeta {
		t.Fatalf("first rule = %s", got)
	}
	if got := rl.Calls[1].Rule; got != ratelimit.BucketTokenIP {
		t.Fatalf("second rule = %s", got)
	}
}

// U6: the buckets of the other paths.
func TestU6_BucketOfEachPath(t *testing.T) {
	for path, want := range map[string]string{
		"/.well-known/openid-configuration": ratelimit.BucketPublicMeta,
		"/oauth/introspect":                 ratelimit.BucketIntrospectIP,
		"/oauth/revoke":                     ratelimit.BucketOAuthBackendIP,
		"/oauth/userinfo":                   ratelimit.BucketOAuthBackendIP,
	} {
		rl := &mock.RateLimiter{Deny: true}
		get(limitedServer(t, rl), http.MethodPost, path, "")
		if len(rl.Calls) != 1 || rl.Calls[0].Rule != want {
			t.Errorf("%s: calls = %+v, want one call of %s", path, rl.Calls, want)
		}
	}
}

// U7: a limiter error lets JWKS pass (fail open) and gives a 503 for the token
// endpoint.
func TestU7_MiddlewareLimiterError(t *testing.T) {
	h := limitedServer(t, &mock.RateLimiter{Err: errors.New("down")})
	rec := get(h, http.MethodGet, "/.well-known/jwks.json", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("jwks: status = %d, want 200", rec.Code)
	}
	rec = get(h, http.MethodPost, "/oauth/token", "x=1")
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "5" {
		t.Fatalf("token: status %d, headers %v", rec.Code, rec.Header())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] != "temporarily_unavailable" {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

// The wait time of an error in the chain is the header of the response.
func TestRateLimitedErrorHeaders(t *testing.T) {
	if apperrors.RetryAfterSeconds(1500*time.Millisecond) != 2 || apperrors.RetryAfterSeconds(0) != 0 {
		t.Fatal("RetryAfterSeconds rounds up")
	}
}
