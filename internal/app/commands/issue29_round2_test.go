package commands_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/ports/ratelimit"
	"github.com/techorionai/constellation-identity/resources/test/mock"
)

// Issue29_R11: the global refusal does not share the bounded table of the IP
// refusals. A flood of IP refusals fills the table. Then the global bucket
// refuses. New /64 prefixes make no call to the limiter.
func TestIssue29_R11_FullTableKeepsGlobalRefusal(t *testing.T) {
	rl := &mock.RateLimiter{DenyRules: map[string]bool{ratelimit.BucketTokenDenied: true}}
	g := newGate(t, rl, nil, func() time.Time { return now })
	for i := range 10000 {
		g.Allow(fromIP(fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256)), gateAction, "")
	}
	// The table of IP refusals is full. The global bucket refuses now.
	rl.DenyRules = map[string]bool{ratelimit.BucketTokenDeniedGlobal: true}
	if g.Allow(fromIP("203.0.113.9"), gateAction, "") {
		t.Fatal("the global bucket must refuse")
	}
	rl.Calls = nil
	for i := range 1000 {
		if g.Allow(fromIP(fmt.Sprintf("2001:db8:%x:%x::1", i, i)), gateAction, "") {
			t.Fatalf("request %d allowed", i)
		}
	}
	if len(rl.Calls) != 0 {
		t.Fatalf("limiter calls = %d, want 0", len(rl.Calls))
	}
}

// Issue29_R12: only a client that authenticated gets the per-client budget. A
// bad signature, an unknown client, and a public client use the IP, daily, and
// global path.
func TestIssue29_R12_OnlyAuthenticatedClientBudget(t *testing.T) {
	newF := func() (*fixture, *mock.RateLimiter) {
		rl := &mock.RateLimiter{}
		return gateFixture(t, rl, nil, func() time.Time { return now }), rl
	}
	t.Run("bad signature of a known client", func(t *testing.T) {
		f, rl := newF()
		bad := signES256(t, newKey(t), "k1", map[string]any{
			"iss": "helpdesk", "sub": "helpdesk", "aud": issuer, "jti": "j1",
			"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		})
		if _, err := f.cmd.Execute(fromIP("203.0.113.5"), request(bad)); oauthCode(t, err) != apperrors.OAuthInvalidClient {
			t.Fatalf("err = %v", err)
		}
		if n := len(rl.CallsOf(ratelimit.BucketTokenDeniedClient)); n != 0 {
			t.Fatalf("client bucket calls = %d, want 0", n)
		}
		if n := len(rl.CallsOf(ratelimit.BucketTokenDeniedGlobal)); n != 1 {
			t.Fatalf("global bucket calls = %d, want 1", n)
		}
	})
	t.Run("public client", func(t *testing.T) {
		f, rl := newF()
		a := f.assertion(t, func(c map[string]any) { c["iss"], c["sub"] = "web", "web" })
		if _, err := f.cmd.Execute(fromIP("203.0.113.5"), request(a)); oauthCode(t, err) != apperrors.OAuthInvalidClient {
			t.Fatalf("err = %v", err)
		}
		if n := len(rl.CallsOf(ratelimit.BucketTokenDeniedClient)); n != 0 {
			t.Fatalf("client bucket calls = %d, want 0", n)
		}
	})
	t.Run("authenticated client", func(t *testing.T) {
		f, rl := newF()
		in := request(f.assertion(t, nil))
		in.Scope = "demo:nope:none"
		if _, err := f.cmd.Execute(fromIP("203.0.113.5"), in); oauthCode(t, err) != apperrors.OAuthInvalidScope {
			t.Fatalf("err = %v", err)
		}
		c := rl.CallsOf(ratelimit.BucketTokenDeniedClient)
		if len(c) != 1 || c[0].Key != "helpdesk" || len(rl.CallsOf(ratelimit.BucketTokenDeniedGlobal)) != 0 {
			t.Fatalf("calls = %+v", rl.Calls)
		}
	})
}

// Issue29_R12: an attacker who uses up the shared budget does not stop all audit
// signal. The gate gives one summary entry for each window, action, and reason,
// with the number of dropped entries. The entry has no IP and no client ID.
func TestIssue29_R12_SummaryEntry(t *testing.T) {
	at := now
	rl := &mock.RateLimiter{DenyRules: map[string]bool{ratelimit.BucketTokenDeniedGlobal: true}}
	f := gateFixture(t, rl, nil, func() time.Time { return at })
	for range 5 {
		badRequest(t, f, fromIP("203.0.113.5"))
	}
	if countDenied(f) != 0 {
		t.Fatalf("entries = %d, want 0", countDenied(f))
	}
	s := summaries(f)
	if len(s) != 1 || s[0].Action != commands.ActionTokenIssue || s[0].Details["dropped"] != 1 ||
		s[0].Details["droppedReason"] != "rate_limit_token_denied_global" || s[0].Details["windowSeconds"] != 60 ||
		s[0].TargetType != "" || s[0].TargetUserID != "" {
		t.Fatalf("summaries = %+v", s)
	}
	// The next window: one more summary with the count of the window.
	at = at.Add(61 * time.Second)
	for range 5 {
		badRequest(t, f, fromIP("203.0.113.5"))
	}
	s = summaries(f)
	if len(s) != 2 || s[1].Details["dropped"] != 5 {
		t.Fatalf("summaries = %+v", s)
	}
}
