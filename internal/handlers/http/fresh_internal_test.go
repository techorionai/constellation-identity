package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/techorionai/constellation-platform-go/auth"
)

// U19 of issue 16: the check of a fresh login. An auth_time of 1 minute is good.
// An auth_time of 6 minutes, a token with act, an API token, and a token with no
// auth_time get the error that gives the 401 with the challenge of a fresh login.
// The check does not look at mfa.
func TestIssue16_U19_CheckFreshLogin(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	s := &Server{d: Deps{Now: func() time.Time { return now }}}
	user := func(mod func(*auth.Principal)) context.Context {
		p := auth.Principal{ID: "u", Type: auth.PrincipalUser, AuthMethods: []string{"pwd"}, AuthTime: now.Add(-time.Minute)}
		if mod != nil {
			mod(&p)
		}
		return auth.ContextWithPrincipal(context.Background(), p)
	}
	if err := s.checkFreshLogin(user(nil)); err != nil {
		t.Fatalf("1 minute: %v", err)
	}
	if err := s.checkFreshLogin(user(func(p *auth.Principal) { p.AuthMethods = nil })); err != nil {
		t.Fatalf("no methods: %v", err)
	}
	for name, ctx := range map[string]context.Context{
		"6 minutes":    user(func(p *auth.Principal) { p.AuthTime = now.Add(-6 * time.Minute) }),
		"act":          user(func(p *auth.Principal) { p.Act = &auth.Actor{ID: "a", Type: auth.PrincipalAgent} }),
		"api token":    user(func(p *auth.Principal) { p.TokenType = auth.TokenTypeAPI }),
		"no auth time": user(func(p *auth.Principal) { p.AuthTime = time.Time{} }),
		"no principal": context.Background(),
	} {
		if err := s.checkFreshLogin(ctx); !errors.Is(err, errFreshLoginRequired) {
			t.Errorf("%s: err = %v, want errFreshLoginRequired", name, err)
		}
	}
	// The 5 minute limit is inclusive.
	if err := s.checkFreshLogin(user(func(p *auth.Principal) { p.AuthTime = now.Add(-5 * time.Minute) })); err != nil {
		t.Errorf("5 minutes: %v", err)
	}
	// The response has the status 401, the header, and the code.
	rec := httptest.NewRecorder()
	s.responseError(rec, httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/v1/me/identity-links/google", nil), errFreshLoginRequired)
	if rec.Code != http.StatusUnauthorized ||
		rec.Header().Get("WWW-Authenticate") != `Bearer error="insufficient_user_authentication", error_description="A fresh login is necessary", max_age="300"` {
		t.Fatalf("response: %d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
}
