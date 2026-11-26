package pages_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/techorionai/constellation-platform-go/executor"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	"github.com/techorionai/constellation-identity/internal/app/queries"
	"github.com/techorionai/constellation-identity/internal/config"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/handlers/http/pages"
	"github.com/techorionai/constellation-identity/resources/test/mock"
)

const testUser = "00000000-0000-4000-8000-00000000000a"

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// passkeyPages makes a handler with the passkeys on, a session of a user with
// a fresh login, and a pending login of the same user.
func passkeyPages(t *testing.T, limits *commands.RateLimits) (http.Handler, string) {
	t.Helper()
	keys := mock.NewPasskeys()
	mfa := mock.NewMFA()
	mfa.Passkeys = keys
	keys.Add(domain.PasskeyCredential{
		Passkey: domain.Passkey{ID: "00000000-0000-4000-8000-0000000000e1", UserID: testUser, Name: "key", CreatedAt: time.Now()}, CredentialID: []byte("c"),
	})
	pending := mock.NewPending()
	const token = "pending-token"
	if err := pending.Put(context.Background(), domain.HashSecret(token), domain.PendingLogin{
		UserID: testUser, Methods: []string{"pwd"}, AuthRequest: "ar-1", ExpiresAt: time.Now().Add(time.Minute),
	}, time.Minute); err != nil {
		t.Fatal(err)
	}
	users := mock.NewUsers()
	cmd, err := commands.NewMFA(commands.MFADeps{
		Users: users, UserRoles: mock.NewUserRoles(users), Sessions: mock.NewSessions(), MFA: mfa, Passkeys: keys, WebAuthn: &mock.WebAuthn{},
		Ceremonies: mock.NewCeremonies(), PasskeysOn: true, Pending: pending, Setups: mock.NewSetups(), Failures: mock.NewFailures(),
		Events: &mock.Events{}, Tx: mock.Tx{}, MaxFailures: 10, FailureWindow: time.Minute,
		Log: slog.New(slog.NewTextHandler(discardWriter{}, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	h, err := pages.New(pages.Deps{
		MFA: cmd, PasskeysOn: true, Issuer: "http://localhost:8080", RateLimits: limits,
		LookupAuthRequest: executor.FuncWithReturn[string, commands.AuthRequestInfo](func(_ context.Context, id string) (commands.AuthRequestInfo, error) {
			return commands.AuthRequestInfo{FormActionOrigin: "https://client.example"}, nil
		}),
		CheckToken: executor.FuncWithReturn[queries.CheckOneTimeToken, bool](func(context.Context, queries.CheckOneTimeToken) (bool, error) {
			return true, nil
		}),
		Session: executor.FuncWithReturn[queries.SessionFromCookie, queries.SessionResult](func(_ context.Context, q queries.SessionFromCookie) (queries.SessionResult, error) {
			if q.Token == "" {
				return queries.SessionResult{}, queries.ErrNoSession
			}
			return queries.SessionResult{
				Session: domain.Session{ID: "s1", UserID: testUser, AuthTime: time.Now()},
				User:    domain.User{ID: testUser, Email: "a@example.com", Name: "A"},
			}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return h.Routes(), token
}

func csp(t *testing.T, routes http.Handler, path string, cookies ...*http.Cookie) string {
	t.Helper()
	req := newRequest(http.MethodGet, path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	routes.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status = %d: %s", path, rec.Code, rec.Body.String())
	}
	return rec.Header().Get("Content-Security-Policy")
}

// U7: the pages that use the script have script-src 'self' and connect-src
// 'self'. The pages with an auth request also have the client origin in
// form-action. The other pages have no script-src.
func TestIssue15_U7_ContentSecurityPolicy(t *testing.T) {
	routes, token := passkeyPages(t, nil)
	session := &http.Cookie{Name: pages.CookieName, Value: "session"} //nolint:gosec // G124: a request cookie has no attributes.
	pending := &http.Cookie{Name: pages.MFACookieName, Value: token}  //nolint:gosec // G124: a request cookie has no attributes.
	withScript := map[string]string{
		"/login":                  "",
		"/login?authRequest=ar-1": "https://client.example",
		"/account/passkeys":       "",
	}
	for path, origin := range withScript {
		got := csp(t, routes, path, session)
		if !strings.Contains(got, "script-src 'self'") || !strings.Contains(got, "connect-src 'self'") {
			t.Errorf("%s: CSP = %q", path, got)
		}
		if origin != "" && !strings.Contains(got, "form-action 'self' "+origin) {
			t.Errorf("%s: CSP = %q, want the client origin in form-action", path, got)
		}
	}
	got := csp(t, routes, "/login/mfa", pending)
	if !strings.Contains(got, "script-src 'self'") || !strings.Contains(got, "connect-src 'self'") || !strings.Contains(got, "form-action 'self' https://client.example") {
		t.Errorf("/login/mfa: CSP = %q", got)
	}
	for _, path := range []string{"/setup?token=x", "/account/security"} {
		req := newRequest(http.MethodGet, path, nil)
		req.AddCookie(session)
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)
		if c := rec.Header().Get("Content-Security-Policy"); strings.Contains(c, "script-src") {
			t.Errorf("%s: CSP = %q must have no script-src", path, c)
		}
	}
	if got := pages.ContentSecurityPolicyWithScript(""); strings.Contains(got, "unsafe") ||
		got != "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'" {
		t.Errorf("policy = %q", got)
	}
}

// U7a: the pages of a service with passkeys off keep the policy with no script.
func TestIssue15_U7_PasskeysOff(t *testing.T) {
	h, err := pages.New(pages.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	routes := h.Routes()
	for _, p := range []struct{ method, path string }{
		{http.MethodGet, "/assets/passkey.js"}, {http.MethodGet, "/account/passkeys"},
		{http.MethodPost, "/login/passkey/options"}, {http.MethodPost, "/login/mfa/passkey/finish"},
	} {
		req := newRequest(p.method, p.path, nil)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s: status = %d, want 404", p.method, p.path, rec.Code)
		}
	}
	req := newRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	routes.ServeHTTP(rec, req)
	if strings.Contains(rec.Header().Get("Content-Security-Policy"), "script-src") || strings.Contains(rec.Body.String(), "passkey") {
		t.Errorf("the login page of a service with passkeys off must have no passkey: %s", rec.Body.String())
	}
}

// U8: a JSON route needs the content type application/json and at most 64 KiB.
func TestIssue15_U8_JSONRouteLimits(t *testing.T) {
	routes, _ := passkeyPages(t, nil)
	do := func(contentType string, body []byte) *httptest.ResponseRecorder {
		req := newRequest(http.MethodPost, "/login/passkey/options", bytes.NewReader(body))
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)
		return rec
	}
	if rec := do("text/plain", []byte("{}")); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain: status = %d, want 415", rec.Code)
	}
	if rec := do("", []byte("{}")); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("no content type: status = %d, want 415", rec.Code)
	}
	if rec := do("application/json", bytes.Repeat([]byte{' '}, 65<<10)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("65 KiB: status = %d, want 413", rec.Code)
	}
	if rec := do("application/json; charset=utf-8", []byte("{}")); rec.Code != http.StatusOK {
		t.Errorf("a good request: status = %d, want 200", rec.Code)
	}
}

// U14: the rate limit handler of a JSON route answers with JSON.
func TestIssue15_U14_RateLimitJSON(t *testing.T) {
	rl := &mock.RateLimiter{Deny: true}
	limits, err := commands.NewRateLimits(commands.RateLimitsDeps{Limiter: rl, Rules: config.DefaultRateRules()})
	if err != nil {
		t.Fatal(err)
	}
	routes, _ := passkeyPages(t, limits)
	do := func() *httptest.ResponseRecorder {
		req := newRequest(http.MethodPost, "/login/mfa/passkey/finish", strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.9:5000"
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)
		return rec
	}
	rec := do()
	if rec.Code != http.StatusTooManyRequests || strings.TrimSpace(rec.Body.String()) != `{"error":"rate_limited"}` ||
		rec.Header().Get("Retry-After") == "" || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("over the limit: %d %q %v", rec.Code, rec.Body.String(), rec.Header())
	}
	if calls := rl.CallsOf("passkey"); len(calls) == 0 {
		t.Fatalf("the bucket passkey was not used: %+v", rl.Calls)
	}
	rl.Deny, rl.Err = false, context.DeadlineExceeded
	rec = do()
	if rec.Code != http.StatusServiceUnavailable || strings.TrimSpace(rec.Body.String()) != `{"error":"unavailable"}` {
		t.Fatalf("limiter down: %d %q", rec.Code, rec.Body.String())
	}
}
