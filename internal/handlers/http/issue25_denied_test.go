package httpapi_test

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	"github.com/techorionai/constellation-identity/internal/app/queries"
	"github.com/techorionai/constellation-identity/internal/config"
	httpapi "github.com/techorionai/constellation-identity/internal/handlers/http"
	"github.com/techorionai/constellation-identity/resources/test/mock"
)

func deniedServer(t *testing.T, ev *mock.Events, rl *mock.RateLimiter, scopes ...string) http.Handler {
	t.Helper()
	return deniedServerLog(t, ev, rl, nil, scopes...)
}

func deniedServerLog(t *testing.T, ev *mock.Events, rl *mock.RateLimiter, log *slog.Logger, scopes ...string) http.Handler {
	t.Helper()
	limits, err := commands.NewRateLimits(commands.RateLimitsDeps{Limiter: rl, Rules: config.DefaultRateRules()})
	if err != nil {
		t.Fatal(err)
	}
	return httpapi.New(httpapi.Deps{
		JWKS: queries.NewGetJWKS(fakeKeys{}), Discovery: queries.NewGetDiscovery("https://id.example.com"),
		Verifier: allScopes{scopes: scopes}, Scopes: realScopes(t),
		Admin: commands.NewAdmin(commands.AdminDeps{Clients: noClients{}, Users: noUsers{}}),
		Log:   log, RateLimits: limits, Denied: commands.NewDeniedAudit(mock.Tx{}, ev),
	}).Handler()
}

// Issue25_U7: a principal with no admin scope gets 403 and one entry with the
// result denied. A limiter that denies gives 429 with Retry-After and no entry.
// A limiter that fails gives one entry and 403 (fail open). A request that
// passes the scope check writes no entry. A route of the own account writes
// no entry.
func TestIssue25_U7_DeniedStep(t *testing.T) {
	t.Run("missing scope", func(t *testing.T) {
		ev, rl := &mock.Events{}, &mock.RateLimiter{}
		rec := call(deniedServer(t, ev, rl, "identity:user:read"), http.MethodPatch, "/v1/users/u1", "ok", `{"name":"x"}`)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
		}
		if len(ev.Audits) != 1 || ev.Audits[0].Action != "identity:user:update" || ev.Audits[0].Result != "denied" || ev.Audits[0].TargetUserID != "" {
			t.Fatalf("audits = %+v", ev.Audits)
		}
		if ev.Audits[0].Actor != "tester" {
			t.Fatalf("the actor = %q, want the principal", ev.Audits[0].Actor)
		}
		if calls := rl.CallsOf("admin_denied"); len(calls) != 1 || calls[0].Key != "tester" {
			t.Fatalf("limiter calls = %+v", rl.Calls)
		}
	})
	t.Run("limiter denies", func(t *testing.T) {
		ev, rl := &mock.Events{}, &mock.RateLimiter{DenyRules: map[string]bool{"admin_denied": true}}
		rec := call(deniedServer(t, ev, rl, "identity:user:read"), http.MethodPatch, "/v1/users/u1", "ok", `{"name":"x"}`)
		if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
			t.Fatalf("status = %d, retry = %q", rec.Code, rec.Header().Get("Retry-After"))
		}
		if len(ev.Audits) != 0 {
			t.Fatalf("audits = %+v", ev.Audits)
		}
	})
	t.Run("limiter denies, logs the dropped entry (R11)", func(t *testing.T) {
		var buf bytes.Buffer
		ev, rl := &mock.Events{}, &mock.RateLimiter{DenyRules: map[string]bool{"admin_denied": true}}
		h := deniedServerLog(t, ev, rl, slog.New(slog.NewJSONHandler(&buf, nil)), "identity:user:read")
		_ = call(h, http.MethodPatch, "/v1/users/u1", "ok", `{"name":"x"}`)
		if out := buf.String(); !strings.Contains(out, "identity.audit.denied_dropped") || !strings.Contains(out, "rate_limit_admin_denied") {
			t.Fatalf("log = %s", out)
		}
	})
	t.Run("daily limit denies (R16)", func(t *testing.T) {
		ev, rl := &mock.Events{}, &mock.RateLimiter{DenyRules: map[string]bool{"admin_denied_daily": true}}
		rec := call(deniedServer(t, ev, rl, "identity:user:read"), http.MethodPatch, "/v1/users/u1", "ok", `{"name":"x"}`)
		if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" || len(ev.Audits) != 0 {
			t.Fatalf("status = %d, audits = %+v", rec.Code, ev.Audits)
		}
		if len(rl.CallsOf("admin_denied")) != 1 || len(rl.CallsOf("admin_denied_daily")) != 1 {
			t.Fatalf("limiter calls = %+v", rl.Calls)
		}
	})
	t.Run("limiter fails, the process limit applies (R17)", func(t *testing.T) {
		var buf bytes.Buffer
		ev, rl := &mock.Events{}, &mock.RateLimiter{Err: errors.New("down")}
		h := deniedServerLog(t, ev, rl, slog.New(slog.NewJSONHandler(&buf, nil)), "identity:user:read")
		for i := 0; i < 15; i++ {
			rec := call(h, http.MethodPatch, "/v1/users/u1", "ok", `{"name":"x"}`)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("request %d: status = %d", i, rec.Code)
			}
		}
		if len(ev.Audits) != 10 {
			t.Fatalf("entries = %d, want 10", len(ev.Audits))
		}
		if n := strings.Count(buf.String(), "fallback_limit"); n != 5 {
			t.Fatalf("dropped records = %d, want 5: %s", n, buf.String())
		}
	})
	t.Run("the entry cannot be written", func(t *testing.T) {
		ev, rl := &mock.Events{AuditErr: errors.New("down")}, &mock.RateLimiter{}
		rec := call(deniedServer(t, ev, rl, "identity:user:read"), http.MethodPatch, "/v1/users/u1", "ok", `{"name":"x"}`)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})
	t.Run("scope present", func(t *testing.T) {
		ev, rl := &mock.Events{}, &mock.RateLimiter{}
		_ = call(deniedServer(t, ev, rl, "identity:user:read"), http.MethodGet, "/v1/users/u1", "ok", "")
		if len(ev.Audits) != 0 || len(rl.Calls) != 0 {
			t.Fatalf("audits = %+v, limiter calls = %+v", ev.Audits, rl.Calls)
		}
	})
	t.Run("account route", func(t *testing.T) {
		ev, rl := &mock.Events{}, &mock.RateLimiter{}
		rec := call(deniedServer(t, ev, rl, "identity:user:read"), http.MethodGet, "/v1/me/api-tokens", "ok", "")
		if rec.Code != http.StatusForbidden || len(ev.Audits) != 0 {
			t.Fatalf("status = %d, audits = %+v", rec.Code, ev.Audits)
		}
	})
}
