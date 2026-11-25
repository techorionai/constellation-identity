//go:build integration

package services_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/techorionai/constellation-platform-go/auth"
	"github.com/techorionai/constellation-platform-go/auth/introspect"
	"github.com/techorionai/constellation-platform-go/clients/identity"
	"github.com/techorionai/constellation-platform-go/manifest"
	"github.com/techorionai/constellation-platform-go/resources/test/containers"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/techorionai/constellation-identity/internal/config"
	"github.com/techorionai/constellation-identity/internal/ports/ratelimit"
	"github.com/techorionai/constellation-identity/resources/test/testserver"
)

// rl makes a rule with a limit and the default window of the bucket.
func rl(limit int64) ratelimit.Rule { return ratelimit.Rule{Limit: limit} }

// startRL starts a server with an own Valkey container, so that the counters
// of other tests do not count. It returns the container.
func (h *harness) startRL(t *testing.T, opts ...testserver.Option) (*containers.ValkeyInstance, *app) {
	t.Helper()
	vk := containers.Valkey(t, containers.WithValkeyImage(testserver.ValkeyImage))
	return vk, h.startOn(t, vk, opts...)
}

// startOn starts a server on a Valkey container.
func (h *harness) startOn(t *testing.T, vk *containers.ValkeyInstance, opts ...testserver.Option) *app {
	t.Helper()
	env := &testserver.Env{PG: h.env.PG, VK: vk}
	logs := testserver.NewLogCapture()
	h.ledger.mu.Lock()
	h.ledger.logs = append(h.ledger.logs, logs)
	h.ledger.mu.Unlock()
	opts = append([]testserver.Option{testserver.WithLogger(logs.Logger()), testserver.WithMasterKey(h.masterKey, "test")}, opts...)
	return &app{Server: env.Start(t, opts...), logs: logs, ledger: h.ledger}
}

// resetRateLimits deletes the rate limit counters. A test calls it after the
// setup of the fixture, so that the setup does not use the low limits.
func resetRateLimits(t *testing.T, vk *containers.ValkeyInstance) {
	t.Helper()
	admin := vk.Admin(t)
	keys, err := admin.Do(ctx, admin.B().Keys().Pattern("identity:rl:*").Build()).AsStrSlice()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		return
	}
	if err := admin.Do(ctx, admin.B().Del().Key(keys...).Build()).Error(); err != nil {
		t.Fatal(err)
	}
}

func retryAfter(t *testing.T, resp testserver.Response) int {
	t.Helper()
	n, err := strconv.Atoi(resp.Header.Get("Retry-After"))
	if err != nil || n < 1 {
		t.Fatalf("Retry-After = %q, want a whole number of seconds from 1", resp.Header.Get("Retry-After"))
	}
	return n
}

func errorCode(b []byte) string {
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	s, _ := m["error"].(string)
	return s
}

func problemCode(b []byte) string {
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	s, _ := m["code"].(string)
	return s
}

func tokenRequest(a *app, t *testing.T, c testserver.ServiceClient) (testserver.Response, []byte) {
	t.Helper()
	return a.PostToken(t, testserver.TokenForm(a.Assertion(t, c, nil), "identity", "identity:manifest:publish"))
}

// rlFixture starts the fixture of the other tests on an own Valkey container.
func rlFixture(t *testing.T, h *harness, opts ...testserver.Option) (*fixture, *containers.ValkeyInstance) {
	t.Helper()
	var vk *containers.ValkeyInstance
	start := func(t *testing.T, o ...testserver.Option) *app {
		var a *app
		vk, a = h.startRL(t, o...)
		return a
	}
	f := newFixtureOn(t, start, append([]testserver.Option{
		testserver.WithConfigure(func(c *config.Config) { c.APIToken.MaxPerUser = 5 }),
	}, opts...)...)
	resetRateLimits(t, vk)
	return f, vk
}

func TestRateLimitIntegration(t *testing.T) {
	observability()
	h := &harness{env: testserver.NewEnv(t), ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}

	// I6: two instances use the same counters.
	t.Run("I6_two_instances", func(t *testing.T) {
		vk, a := h.startRL(t, testserver.WithRateLimits(map[string]ratelimit.Rule{ratelimit.BucketSetupInvite: rl(10)}))
		b := h.startOn(t, vk, testserver.WithDB(a.DB), testserver.WithRateLimits(map[string]ratelimit.Rule{ratelimit.BucketSetupInvite: rl(10)}))
		instances := []*app{a, b}
		for i := range 12 {
			resp, _ := instances[i%2].NewWeb().Get(t, "/setup?token=bad")
			if i < 10 {
				if resp.StatusCode == http.StatusTooManyRequests {
					t.Fatalf("request %d: status = 429, want a page", i+1)
				}
				continue
			}
			status(t, resp, http.StatusTooManyRequests, "request over the limit")
			retryAfter(t, resp)
		}
	})

	// I7: a request over the limit runs no use case.
	t.Run("I7_no_use_case_when_limited", func(t *testing.T) {
		_, a := h.startRL(t, testserver.WithRateLimits(map[string]ratelimit.Rule{ratelimit.BucketSetupInvite: rl(1)}))
		web := a.NewWeb()
		form := url.Values{"token": {"bad"}, "email": {"a@example.com"}, "name": {"A"}, "password": {"long password 12345"}, "password2": {"long password 12345"}}
		resp, _ := web.PostForm(t, "/setup", form)
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatal("the first request must not be limited")
		}
		spansBefore := len(spanExporter.GetSpans())
		resp, _ = web.PostForm(t, "/setup", form)
		status(t, resp, http.StatusTooManyRequests, "limited POST /setup")
		for _, s := range spanExporter.GetSpans()[spansBefore:] {
			if s.Name == "CompleteSetup" || s.Name == "CheckOneTimeToken" {
				t.Fatalf("the use case %s ran for a limited request", s.Name)
			}
		}
	})

	// I8, I9, I10: the client bucket.
	t.Run("I8_I9_I10_token_client", func(t *testing.T) {
		demo := testserver.NewServiceClient(t, "demo", "demo")
		_, a := h.startRL(t, testserver.WithClients(t, demo),
			testserver.WithRateLimits(map[string]ratelimit.Rule{ratelimit.BucketTokenClient: rl(3)}))
		// I9: an attacker names the client but signs with another key.
		evil := testserver.NewServiceClient(t, "demo", "demo")
		for i := range 10 {
			resp, body := tokenRequest(a, t, evil)
			if resp.StatusCode != http.StatusUnauthorized || errorCode(body) != "invalid_client" {
				t.Fatalf("attacker request %d: status %d, body %s, want 401 invalid_client", i+1, resp.StatusCode, body)
			}
		}
		// I8: the real client gets 3 tokens, then 429.
		for i := range 3 {
			resp, body := tokenRequest(a, t, demo)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("call %d: status %d, body %s", i+1, resp.StatusCode, body)
			}
		}
		resp, body := tokenRequest(a, t, demo)
		if resp.StatusCode != http.StatusTooManyRequests || errorCode(body) != "temporarily_unavailable" {
			t.Fatalf("call 4: status %d, body %s", resp.StatusCode, body)
		}
		retryAfter(t, resp)
		if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Pragma") != "no-cache" {
			t.Fatalf("headers = %v", resp.Header)
		}
		// I10: the token source of platform-go.
		_, err := a.TokenSource(t, demo).Token(ctx, "identity", "identity:manifest:publish")
		if !errors.Is(err, auth.ErrTokenUnavailable) {
			t.Fatalf("err = %v, want ErrTokenUnavailable", err)
		}
		if d, ok := auth.RetryAfter(err); !ok || d <= 0 {
			t.Fatalf("RetryAfter = %v, %v", d, ok)
		}
	})

	// I11: the verifier of platform-go and the introspection bucket.
	t.Run("I11_introspect_client", func(t *testing.T) {
		g, vk := rlFixture(t, h, testserver.WithRateLimits(map[string]ratelimit.Rule{ratelimit.BucketIntrospectClient: rl(2)}))
		gadmin := g.adminToken(apiAdminScopes)
		_, access := g.apiUser(gadmin, "svc", "demo:agent")
		var values []string
		for _, n := range []string{"a", "b", "c"} {
			_, v := g.mustCreate(access, n, "demo:ticket:read")
			values = append(values, v)
		}
		resetRateLimits(t, vk)
		v, err := introspect.New(introspect.Config{
			Issuer: g.a.Config.Issuer, IntrospectURL: g.a.PublicURL + "/oauth/introspect", Audience: "demo",
			CacheTTL: time.Second, InactiveTTL: 0, CacheSize: 100, InactiveCacheSize: 10, MaxConcurrent: 16,
			HTTPTimeout: 5 * time.Second, AllowInsecureHTTP: true,
		}, g.a.TokenSource(t, g.serviceClient))
		if err != nil {
			t.Fatal(err)
		}
		for i, value := range values[:2] {
			if _, err := v.Verify(ctx, value); err != nil {
				t.Fatalf("token %d: %v", i+1, err)
			}
		}
		_, err = v.Verify(ctx, values[2])
		if !errors.Is(err, auth.ErrIntrospectionUnavailable) {
			t.Fatalf("err = %v, want ErrIntrospectionUnavailable", err)
		}
		if d, ok := auth.RetryAfter(err); !ok || d <= 0 {
			t.Fatalf("RetryAfter = %v, %v", d, ok)
		}
		resp, m := g.introspectAt(g.serviceClient, values[2])
		if resp.StatusCode != http.StatusTooManyRequests || m["error"] != "temporarily_unavailable" {
			t.Fatalf("status %d, body %v", resp.StatusCode, m)
		}
	})

	// I12: the creation of API tokens.
	t.Run("I12_api_token_create", func(t *testing.T) {
		g, vk := rlFixture(t, h, testserver.WithRateLimits(map[string]ratelimit.Rule{ratelimit.BucketAPITokenCreate: rl(2)}))
		gadmin := g.adminToken(apiAdminScopes)
		id, access := g.apiUser(gadmin, "svc", "demo:agent")
		resetRateLimits(t, vk)
		for i := range 2 {
			if resp, m := g.createToken(access, "t", "demo:ticket:read", 0); resp.StatusCode != http.StatusCreated {
				t.Fatalf("token %d: %d %v", i+1, resp.StatusCode, m)
			}
		}
		resp, m := g.createToken(access, "t", "demo:ticket:read", 0)
		if resp.StatusCode != http.StatusTooManyRequests || m["code"] != "rate_limited" || resp.Header.Get("Content-Type") != "application/problem+json" {
			t.Fatalf("third: %d %v", resp.StatusCode, m)
		}
		retryAfter(t, resp)
		if n := g.countWhere(`SELECT count(*) FROM api_tokens WHERE user_id = $1`, id); n != 2 {
			t.Fatalf("rows = %d, want 2", n)
		}
	})

	// I13: the publish of manifests.
	t.Run("I13_manifest_publish", func(t *testing.T) {
		demo := testserver.NewServiceClient(t, "demo", "demo")
		opts := []testserver.Option{testserver.WithClients(t, demo),
			testserver.WithRateLimits(map[string]ratelimit.Rule{ratelimit.BucketManifestPublish: rl(1)})}
		vk, a := h.startRL(t, opts...)
		idc, err := identity.New(identity.Config{URL: a.PublicURL, Timeout: 10 * time.Second, AllowInsecureHTTP: true},
			a.TokenSource(t, demo), []string{"identity:manifest:publish"})
		if err != nil {
			t.Fatal(err)
		}
		reg := identity.NewManifestRegistry(idc)
		m := manifest.PermissionManifest{
			App:          "demo",
			Permissions:  []manifest.PermissionDefinition{{Key: "demo:ticket:read", Description: "Read tickets."}},
			DefaultRoles: []manifest.RoleDefinition{{Key: "agent", Name: "Agent", Description: "Reads tickets.", Permissions: []string{"demo:ticket:read"}}},
		}
		if err := reg.Publish(ctx, m); err != nil {
			t.Fatalf("first publish: %v", err)
		}
		err = reg.Publish(ctx, m)
		if !errors.Is(err, manifest.ErrUnavailable) {
			t.Fatalf("second publish: %v, want ErrUnavailable", err)
		}
		if d, ok := manifest.RetryAfter(err); !ok || d <= 0 {
			t.Fatalf("RetryAfter = %v, %v", d, ok)
		}
		// The own publish at the start of the service is not counted.
		db := a.DB
		a.Stop()
		_ = h.startOn(t, vk, append(opts, testserver.WithDB(db))...)
	})

	// I14: the counters are not available.
	t.Run("I14_valkey_down", func(t *testing.T) {
		demo := testserver.NewServiceClient(t, "demo", "demo")
		vk, a := h.startRL(t, testserver.WithClients(t, demo))
		if err := vk.Stop(ctx); err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{"/.well-known/jwks.json", "/.well-known/openid-configuration"} {
			resp, _ := a.Get(t, p)
			status(t, resp, http.StatusOK, p+" with Valkey down")
		}
		resp, body := tokenRequest(a, t, demo)
		if resp.StatusCode != http.StatusServiceUnavailable || errorCode(body) != "temporarily_unavailable" || resp.Header.Get("Retry-After") != "5" {
			t.Fatalf("token: status %d, body %s, headers %v", resp.StatusCode, body, resp.Header)
		}
		resp, body = a.Get(t, "/setup?token=bad")
		status(t, resp, http.StatusServiceUnavailable, "GET /setup with Valkey down")
		if resp.Header.Get("Retry-After") != "5" || !strings.Contains(string(body), "The service is not available") {
			t.Fatalf("headers %v, body %s", resp.Header, body)
		}
	})

	// I15: the page buckets.
	t.Run("I15_oauth_public", func(t *testing.T) {
		_, a := h.startRL(t, testserver.WithRateLimits(map[string]ratelimit.Rule{ratelimit.BucketOAuthPublic: rl(2)}))
		web := a.NewWeb()
		for i := range 2 {
			if resp, _ := web.Get(t, "/oauth/authorize"); resp.StatusCode == http.StatusTooManyRequests {
				t.Fatalf("request %d is limited", i+1)
			}
		}
		resp, body := web.Get(t, "/oauth/authorize")
		status(t, resp, http.StatusTooManyRequests, "third request")
		retryAfter(t, resp)
		if resp.Header.Get("Content-Security-Policy") == "" || !strings.Contains(string(body), "Too many requests") {
			t.Fatalf("headers %v, body %s", resp.Header, body)
		}
	})

	// I16: a trusted proxy gives each client IP its own counter.
	t.Run("I16_trusted_proxy", func(t *testing.T) {
		_, a := h.startRL(t,
			testserver.WithConfigure(func(c *config.Config) { c.HTTP.TrustedProxies = []string{"127.0.0.0/8", "::1/128"} }),
			testserver.WithRateLimits(map[string]ratelimit.Rule{ratelimit.BucketSetupInvite: rl(1)}))
		get := func(xff string) testserver.Response {
			web := a.NewWeb()
			web.Header.Set("X-Forwarded-For", xff)
			resp, _ := web.Get(t, "/setup?token=bad")
			return resp
		}
		for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
			if resp := get(ip); resp.StatusCode == http.StatusTooManyRequests {
				t.Fatalf("first request of %s is limited", ip)
			}
		}
		for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
			if resp := get(ip); resp.StatusCode != http.StatusTooManyRequests {
				t.Fatalf("second request of %s: status %d, want 429", ip, resp.StatusCode)
			}
		}
	})

	// I22: the introspection IP bucket does not use the token budget.
	t.Run("I22_introspect_ip", func(t *testing.T) {
		demo := testserver.NewServiceClient(t, "demo", "demo")
		_, a := h.startRL(t, testserver.WithClients(t, demo), testserver.WithRateLimits(map[string]ratelimit.Rule{
			ratelimit.BucketIntrospectIP: rl(2), ratelimit.BucketTokenIP: rl(5)}))
		for i := range 3 {
			resp, m := a.PostIntrospect(t, url.Values{"token": {"cpat_" + strings.Repeat("a", 43)}})
			if i < 2 && resp.StatusCode == http.StatusTooManyRequests {
				t.Fatalf("request %d is limited", i+1)
			}
			if i == 2 && (resp.StatusCode != http.StatusTooManyRequests || m["error"] != "temporarily_unavailable") {
				t.Fatalf("request 3: status %d, body %v", resp.StatusCode, m)
			}
		}
		resp, body := tokenRequest(a, t, demo)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("token: status %d, body %s", resp.StatusCode, body)
		}
	})

	// I23: the buckets are separate.
	t.Run("I23_backend_and_public", func(t *testing.T) {
		_, a := h.startRL(t, testserver.WithRateLimits(map[string]ratelimit.Rule{
			ratelimit.BucketOAuthBackendIP: rl(2), ratelimit.BucketOAuthPublic: rl(1)}))
		for i := range 3 {
			resp, body := a.Post(t, "/oauth/revoke", "token=x")
			if i < 2 && resp.StatusCode == http.StatusTooManyRequests {
				t.Fatalf("request %d is limited", i+1)
			}
			if i == 2 && (resp.StatusCode != http.StatusTooManyRequests || errorCode(body) != "temporarily_unavailable") {
				t.Fatalf("request 3: status %d, body %s", resp.StatusCode, body)
			}
		}
		resp, _ := a.NewWeb().Get(t, "/oauth/authorize")
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatal("the authorize page must not share the bucket of revoke")
		}
	})

	// I20: no IP address, email, token, or assertion in a rate limit log record
	// or a metric attribute.
	t.Run("I20_no_secrets_in_rate_limit_telemetry", func(t *testing.T) {
		h.ledger.mu.Lock()
		var lines []string
		for _, l := range h.ledger.logs {
			for _, line := range strings.Split(l.Text(), "\n") {
				if strings.Contains(line, "identity.rate_limit") {
					lines = append(lines, line)
				}
			}
		}
		h.ledger.mu.Unlock()
		if len(lines) == 0 {
			t.Fatal("no rate limit log record, so the test checks nothing")
		}
		for _, line := range lines {
			for _, bad := range []string{"127.0.0.1", "[::1]", "198.51.100", "@", "client_assertion", "cpat_", "eyJ", "bad"} {
				if strings.Contains(line, bad) {
					t.Fatalf("a rate limit log record has %q: %s", bad, line)
				}
			}
		}
		var rm metricdata.ResourceMetrics
		if err := metricReader.Collect(ctx, &rm); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				sum, ok := m.Data.(metricdata.Sum[int64])
				if m.Name != "identity.rate_limit.decisions" || !ok {
					continue
				}
				for _, dp := range sum.DataPoints {
					found = true
					if dp.Attributes.Len() != 2 {
						t.Fatalf("attributes = %v, want bucket and outcome only", dp.Attributes)
					}
					for _, k := range []string{"bucket", "outcome"} {
						if _, ok := dp.Attributes.Value(attribute.Key(k)); !ok {
							t.Fatalf("attributes = %v, want %s", dp.Attributes, k)
						}
					}
				}
			}
		}
		if !found {
			t.Fatal("no counter identity.rate_limit.decisions")
		}
	})
}
