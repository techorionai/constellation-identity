package pages

import (
	"net/http"
	"strconv"

	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/handlers/http/clientip"
	"github.com/techorionai/constellation-identity/internal/ports/ratelimit"
)

// pageBuckets gives the IP bucket of each page path. All of them fail closed.
var pageBuckets = map[string]string{
	"/oauth/authorize":          ratelimit.BucketOAuthPublic,
	"/oauth/authorize/continue": ratelimit.BucketOAuthPublic,
	"/oauth/end_session":        ratelimit.BucketOAuthPublic,
	"/setup":                    ratelimit.BucketSetupInvite,
	"/invite":                   ratelimit.BucketSetupInvite,
}

// rateLimit counts each request of a limited page in its IP bucket. It runs
// before the handler, so a request over the limit makes no database call. A
// request over the limit gets a 429 page. If the limiter does not answer, the
// request gets a 503 page. An OPTIONS request is not counted.
func (h *Handler) rateLimit(next http.Handler) http.Handler {
	if h.d.RateLimits == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bucket, ok := pageBuckets[r.URL.Path]
		if !ok || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		err := h.d.RateLimits.Check(r.Context(), bucket, clientip.Key(h.clientIP(r)))
		if err == nil {
			next.ServeHTTP(w, r)
			return
		}
		if re, ok := apperrors.AsRateLimited(err); ok {
			w.Header().Set("Retry-After", strconv.Itoa(max(apperrors.RetryAfterSeconds(re.RetryAfter), 1)))
			h.message(w, r, http.StatusTooManyRequests, "Too many requests", "Too many requests. Try again later.")
			return
		}
		w.Header().Set("Retry-After", strconv.Itoa(apperrors.RetryAfterSeconds(apperrors.DefaultUnavailableRetryAfter)))
		h.message(w, r, http.StatusServiceUnavailable, "Service not available", "The service is not available. Try again later.")
	})
}
