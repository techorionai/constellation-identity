package httpapi

import (
	"net/http"
	"strconv"
	"time"

	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/handlers/http/clientip"
	"github.com/techorionai/constellation-identity/internal/ports/ratelimit"
)

// ipBucket is the IP bucket of a path of the API router.
type ipBucket struct {
	name     string
	failOpen bool
}

// ipBuckets gives the IP bucket of each path. The client buckets run in the
// use cases, after the check of the client assertion. The pages router has the
// buckets of the pages.
var ipBuckets = map[string]ipBucket{
	"/.well-known/jwks.json":            {ratelimit.BucketPublicMeta, true},
	"/.well-known/openid-configuration": {ratelimit.BucketPublicMeta, true},
	"/oauth/token":                      {ratelimit.BucketTokenIP, false},
	"/oauth/introspect":                 {ratelimit.BucketIntrospectIP, false},
	"/oauth/revoke":                     {ratelimit.BucketOAuthBackendIP, false},
	"/oauth/userinfo":                   {ratelimit.BucketOAuthBackendIP, false},
}

// rateLimit counts each request of a limited path in its IP bucket. It runs
// before any database call, hash, or token check. A CORS preflight request
// (OPTIONS) is not counted. A request over the limit gets a 429. If the
// limiter does not answer, a bucket that fails closed gives a 503, and a bucket
// that fails open lets the request pass.
func (s *Server) rateLimit(next http.Handler) http.Handler {
	if s.d.RateLimits == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := ipBuckets[r.URL.Path]
		if !ok || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		ip := clientip.FromRequest(r)
		err := s.d.RateLimits.CheckIP(r.Context(), b.name, clientip.Key(ip), clientip.CoarseKey(ip), b.failOpen)
		if err == nil {
			next.ServeHTTP(w, r)
			return
		}
		s.writeRateError(w, r, err)
	})
}

// writeRateError writes the 429 or the 503 of a rate limit error. An OAuth
// endpoint gets an OAuth JSON body. Another path gets a Problem.
func (s *Server) writeRateError(w http.ResponseWriter, r *http.Request, err error) {
	var status int
	var retry time.Duration
	var code, title, detail string
	if re, ok := apperrors.AsRateLimited(err); ok {
		status, retry = http.StatusTooManyRequests, re.RetryAfter
		code, title, detail = "rate_limited", "Too many requests", "Too many requests. Try again later."
	} else {
		status, retry = http.StatusServiceUnavailable, apperrors.DefaultUnavailableRetryAfter
		code, title, detail = "unavailable", "Service unavailable", "The service is not available."
	}
	setRetryAfter(w, retry)
	if isOAuthPath(r.URL.Path) {
		oauthCode := apperrors.OAuthTemporarilyUnavailable
		desc := "Too many requests. Try again later."
		if status == http.StatusServiceUnavailable {
			desc = "The service is not available. Try again."
		}
		s.writeOAuthErrorCode(w, status, oauthCode, desc)
		return
	}
	s.writeProblem(w, r, status, code, title, detail)
}

func isOAuthPath(p string) bool { return len(p) > 7 && p[:7] == "/oauth/" }

// setRetryAfter sets the header Retry-After in whole seconds. It does nothing
// for a wait time of 0.
func setRetryAfter(w http.ResponseWriter, d time.Duration) {
	if n := apperrors.RetryAfterSeconds(d); n > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(n))
	}
}
