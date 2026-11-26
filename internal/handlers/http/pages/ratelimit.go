package pages

import (
	"net/http"
	"strconv"
	"strings"

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
	"/login/mfa":                ratelimit.BucketMFAVerify,
	// The six JSON routes of the passkeys share one bucket.
	"/login/passkey/options":     ratelimit.BucketPasskey,
	"/login/passkey/finish":      ratelimit.BucketPasskey,
	"/login/mfa/passkey/options": ratelimit.BucketPasskey,
	"/login/mfa/passkey/finish":  ratelimit.BucketPasskey,
	"/account/passkeys/options":  ratelimit.BucketPasskey,
	"/account/passkeys/finish":   ratelimit.BucketPasskey,
	// The passkey check before a link and before a link removal (P23).
	"/account/identity-links/passkey/options": ratelimit.BucketPasskey,
	"/account/identity-links/passkey/link":    ratelimit.BucketPasskey,
	"/account/identity-links/passkey/remove":  ratelimit.BucketPasskey,
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
		if strings.HasPrefix(r.URL.Path, "/login/oidc/") {
			bucket, ok = ratelimit.BucketIdp, true
		}
		// The bucket mfa_verify counts the check of a code (POST) only.
		countsPostOnly := bucket == ratelimit.BucketMFAVerify || bucket == ratelimit.BucketPasskey
		if !ok || r.Method == http.MethodOptions || (countsPostOnly && r.Method != http.MethodPost) {
			next.ServeHTTP(w, r)
			return
		}
		// A cross-site request that is not a navigation to the setup or invite
		// page is never a use of the page. It gets 403 and does not use the
		// bucket of the victim. A cross-site POST is refused before this
		// handler runs. The OAuth pages can load in a frame of a client, so
		// they are not in this rule.
		if bucket == ratelimit.BucketSetupInvite && r.Header.Get("Sec-Fetch-Site") == "cross-site" &&
			r.Header.Get("Sec-Fetch-Dest") != "document" {
			h.message(w, r, http.StatusForbidden, "Request not allowed", "This request is not allowed.")
			return
		}
		ip := h.clientIP(r)
		err := h.d.RateLimits.CheckIP(r.Context(), bucket, clientip.Key(ip), clientip.CoarseKey(ip), false)
		if err == nil {
			next.ServeHTTP(w, r)
			return
		}
		if re, ok := apperrors.AsRateLimited(err); ok {
			if jsonRoutes[r.URL.Path] {
				h.jsonRateLimited(w, re)
				return
			}
			w.Header().Set("Retry-After", strconv.Itoa(max(apperrors.RetryAfterSeconds(re.RetryAfter), 1)))
			h.message(w, r, http.StatusTooManyRequests, "Too many requests", "Too many requests. Try again later.")
			return
		}
		w.Header().Set("Retry-After", strconv.Itoa(apperrors.RetryAfterSeconds(apperrors.DefaultUnavailableRetryAfter)))
		if jsonRoutes[r.URL.Path] {
			h.jsonError(w, http.StatusServiceUnavailable, "unavailable")
			return
		}
		h.message(w, r, http.StatusServiceUnavailable, "Service not available", "The service is not available. Try again later.")
	})
}
