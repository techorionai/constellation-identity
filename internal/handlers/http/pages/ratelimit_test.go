package pages_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	"github.com/techorionai/constellation-identity/internal/config"
	"github.com/techorionai/constellation-identity/internal/handlers/http/pages"
	"github.com/techorionai/constellation-identity/resources/test/mock"
)

// R14: a cross-site request does not use the page bucket of a victim. A
// cross-site POST gets 403 from the cross origin check before the limiter. A
// cross-site GET that is not a navigation to the page gets 403, and the limiter
// does not count it. A same-site navigation is counted.
func TestR14_CrossSiteRequestIsNotCounted(t *testing.T) {
	rl := &mock.RateLimiter{Deny: true}
	limits, err := commands.NewRateLimits(commands.RateLimitsDeps{Limiter: rl, Rules: config.DefaultRateRules()})
	if err != nil {
		t.Fatal(err)
	}
	h, err := pages.New(pages.Deps{RateLimits: limits})
	if err != nil {
		t.Fatal(err)
	}
	routes := h.Routes()
	do := func(method, path, site, dest string) int {
		req := newRequest(method, path, nil)
		req.RemoteAddr = "203.0.113.9:5000"
		if site != "" {
			req.Header.Set("Sec-Fetch-Site", site)
		}
		if dest != "" {
			req.Header.Set("Sec-Fetch-Dest", dest)
		}
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)
		return rec.Code
	}
	for _, c := range []struct{ method, path, site, dest string }{
		{http.MethodPost, "/invite", "cross-site", "document"},
		{http.MethodGet, "/invite?token=x", "cross-site", "image"},
		{http.MethodGet, "/setup?token=x", "cross-site", "iframe"},
	} {
		if got := do(c.method, c.path, c.site, c.dest); got != http.StatusForbidden {
			t.Errorf("%s %s (%s, %s): status = %d, want 403", c.method, c.path, c.site, c.dest, got)
		}
	}
	if len(rl.Calls) != 0 {
		t.Fatalf("cross-site requests used the limiter: %+v", rl.Calls)
	}
	if got := do(http.MethodGet, "/invite?token=x", "same-origin", "document"); got != http.StatusTooManyRequests {
		t.Fatalf("same-origin navigation: status = %d, want 429", got)
	}
	if len(rl.Calls) != 1 {
		t.Fatalf("calls = %+v, want one", rl.Calls)
	}
}
