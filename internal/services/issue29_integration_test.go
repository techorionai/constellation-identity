//go:build integration

package services_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/techorionai/constellation-identity/internal/config"
	"github.com/techorionai/constellation-identity/internal/ports/ratelimit"
	"github.com/techorionai/constellation-identity/resources/test/testserver"
)

// deniedDropCount returns the sum of the counter identity.audit.denied_dropped
// for a reason, since the start of the test process.
func deniedDropCount(t *testing.T, reason string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := metricReader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			sum, ok := m.Data.(metricdata.Sum[int64])
			if m.Name != "identity.audit.denied_dropped" || !ok {
				continue
			}
			for _, dp := range sum.DataPoints {
				if v, ok := dp.Attributes.Value("reason"); ok && v.AsString() == reason {
					total += dp.Value
				}
			}
		}
	}
	return total
}

// postTokenFrom sends a token request with the header X-Forwarded-For. It
// returns the status and the body.
func postTokenFrom(t *testing.T, s *testserver.Server, form url.Values, xff string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.PublicURL+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

// deniedTokenEntries counts the denied token entries on the audit stream.
func deniedTokenEntries(t *testing.T, g *fixture) int {
	t.Helper()
	g.a.WaitAuditRelayed(t)
	n := 0
	for _, e := range g.a.audit.Find(t, "identity:token:issue") {
		if e.Data.Result == "denied" {
			n++
		}
	}
	return n
}

// The tests of the limits of the denied token entries. Each test uses its own
// Valkey container, because the tests set limits.
func TestIssue29Integration(t *testing.T) {
	observability()
	h := &harness{env: testserver.NewEnv(t), ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
	trusted := testserver.WithConfigure(func(c *config.Config) { c.HTTP.TrustedProxies = []string{"127.0.0.0/8", "::1/128"} })
	bad := func(g *fixture) url.Values {
		wrong := testserver.NewServiceClient(t, "demo", "demo")
		return testserver.TokenForm(g.a.Assertion(t, wrong, nil), "identity", "identity:manifest:publish")
	}

	// I1: more bad requests than the limit of one IP. The responses do not
	// change. The entries stop at the limit. The counter has the drops.
	t.Run("I1_token_denied_limit", func(t *testing.T) {
		before := deniedDropCount(t, "rate_limit_token_denied")
		g, _ := withOwnValkey(t, h, testserver.WithRateLimits(map[string]ratelimit.Rule{
			ratelimit.BucketTokenDenied: {Limit: 5, Window: time.Hour}, ratelimit.BucketTokenIP: {Limit: 1000, Window: time.Hour},
		}))
		for i := range 8 {
			resp, body := g.a.PostToken(t, bad(g))
			if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(body), "invalid_client") {
				t.Fatalf("request %d: %d %s", i, resp.StatusCode, body)
			}
		}
		if n := deniedTokenEntries(t, g); n != 5 {
			t.Fatalf("entries = %d, want 5", n)
		}
		if got := deniedDropCount(t, "rate_limit_token_denied") - before; got != 3 {
			t.Fatalf("counter = %d, want 3", got)
		}
	})

	// I2: the global limit holds for many IP addresses.
	t.Run("I2_token_denied_global", func(t *testing.T) {
		before := deniedDropCount(t, "rate_limit_token_denied_global")
		g, _ := withOwnValkey(t, h, trusted, testserver.WithRateLimits(map[string]ratelimit.Rule{
			ratelimit.BucketTokenDeniedGlobal: {Limit: 4, Window: time.Hour},
		}))
		for _, ip := range []string{"203.0.113.1", "203.0.113.2"} {
			for range 3 {
				if status, body := postTokenFrom(t, g.a.Server, bad(g), ip); status != http.StatusUnauthorized || !strings.Contains(body, "invalid_client") {
					t.Fatalf("%s: %d %s", ip, status, body)
				}
			}
		}
		if n := deniedTokenEntries(t, g); n != 4 {
			t.Fatalf("entries = %d, want 4", n)
		}
		if got := deniedDropCount(t, "rate_limit_token_denied_global") - before; got != 2 {
			t.Fatalf("counter = %d, want 2", got)
		}
	})

	// I3: the limit holds for all grants. Bad authorization code requests and
	// random refresh tokens share the budget.
	t.Run("I3_all_grants", func(t *testing.T) {
		before := deniedDropCount(t, "rate_limit_token_denied")
		g, _ := withOwnValkey(t, h, testserver.WithRateLimits(map[string]ratelimit.Rule{
			ratelimit.BucketTokenDenied: {Limit: 2, Window: time.Hour},
		}))
		for range 3 {
			code := url.Values{
				"grant_type": {"authorization_code"}, "code": {"bad-code"}, "client_id": {"unknown-client"},
				"redirect_uri": {"https://app.example.com/cb"}, "code_verifier": {strings.Repeat("a", 50)},
			}
			resp, body := g.a.PostToken(t, code)
			if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("code: %d %s", resp.StatusCode, body)
			}
			refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"random-refresh-token"}, "client_id": {"unknown-client"}}
			resp, body = g.a.PostToken(t, refresh)
			if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("refresh: %d %s", resp.StatusCode, body)
			}
		}
		if n := deniedTokenEntries(t, g); n != 2 {
			t.Fatalf("entries = %d, want 2", n)
		}
		if got := deniedDropCount(t, "rate_limit_token_denied") - before; got != 4 {
			t.Fatalf("counter = %d, want 4", got)
		}
	})

	// I4: with the rate limits off, the in-process limit of 10 entries for each
	// IP applies.
	t.Run("I4_rate_limits_off", func(t *testing.T) {
		before := deniedDropCount(t, "fallback_limit")
		g, _ := withOwnValkey(t, h, testserver.WithConfigure(func(c *config.Config) { c.RateLimit.Enabled = false }))
		for i := range 15 {
			resp, body := g.a.PostToken(t, bad(g))
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("request %d: %d %s", i, resp.StatusCode, body)
			}
		}
		if n := deniedTokenEntries(t, g); n != 10 {
			t.Fatalf("entries = %d, want 10", n)
		}
		if got := deniedDropCount(t, "fallback_limit") - before; got != 5 {
			t.Fatalf("counter = %d, want 5", got)
		}
	})
}
