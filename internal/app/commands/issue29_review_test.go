package commands_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/ports/ratelimit"
	"github.com/techorionai/constellation-identity/resources/test/mock"
)

const gateAction = "identity:token:issue"

func newGate(t *testing.T, rl *mock.RateLimiter, log *slog.Logger, clock func() time.Time) *commands.TokenDeniedGate {
	t.Helper()
	var limits *commands.RateLimits
	if rl != nil {
		limits = newLimits(t, rl)
	}
	g, err := commands.NewTokenDeniedGate(limits, log)
	if err != nil {
		t.Fatal(err)
	}
	if clock != nil {
		g.WithClock(clock)
	}
	return g
}

// Issue29_R1: a refresh token reuse writes its entry with a limiter that refuses
// all. The same limiter drops a denied token entry. The login path has no gate
// and no limiter dependency, so the login entries do not depend on the limiter.
func TestIssue29_R1_ReuseEntryNotGated(t *testing.T) {
	limits := newLimits(t, &mock.RateLimiter{Deny: true})
	r := newOIDCRig(t, func(d *commands.OIDCDeps) { d.RateLimits = limits })
	res, err := r.oidc.ExchangeCode(ctx, r.exchange(r.putCode("offline_access")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.oidc.RefreshTokens(ctx, commands.RefreshTokens{ClientID: "helpdesk-ui", RefreshToken: res.RefreshToken}); err != nil {
		t.Fatal(err)
	}
	r.ev.Audits = nil
	if _, err = r.oidc.RefreshTokens(ctx, commands.RefreshTokens{ClientID: "other-ui", RefreshToken: res.RefreshToken}); oauthCode(t, err) != apperrors.OAuthInvalidGrant {
		t.Fatalf("err = %v", err)
	}
	if a := oneTokenEntry(t, r.ev, "denied"); a.Details["reason"] != commands.ReasonRefreshTokenReuse {
		t.Fatalf("entry = %+v", a)
	}
	// A bad code is a denied entry that the same limiter drops.
	r.ev.Audits = nil
	if _, err = r.oidc.ExchangeCode(ctx, r.exchange("bad-code")); oauthCode(t, err) != apperrors.OAuthInvalidGrant {
		t.Fatalf("err = %v", err)
	}
	if a := oneTokenEntry(t, r.ev, "denied"); a.Details["reason"] != commands.ReasonDeniedDropped {
		t.Fatalf("entries = %+v, want the summary only", r.ev.Audits)
	}
}

// Issue29_R2: NewOIDC uses the shared limits for its own gate.
func TestIssue29_R2_OIDCGateUsesSharedLimits(t *testing.T) {
	rl := &mock.RateLimiter{}
	r := newOIDCRig(t, func(d *commands.OIDCDeps) { d.RateLimits = newLimits(t, rl) })
	if _, err := r.oidc.ExchangeCode(fromIP("203.0.113.5"), r.exchange("bad-code")); oauthCode(t, err) != apperrors.OAuthInvalidGrant {
		t.Fatalf("err = %v", err)
	}
	if len(rl.CallsOf(ratelimit.BucketTokenDenied)) == 0 || len(r.ev.Audits) != 1 {
		t.Fatalf("calls = %+v, entries = %d", rl.Calls, len(r.ev.Audits))
	}
}

// Issue29_R3: while the shared limiter is down, requests with no client IP do
// not share the per-IP budget of 10.
func TestIssue29_R3_NoIPFallback(t *testing.T) {
	metrics := dropMetrics(t)
	g := newGate(t, &mock.RateLimiter{Err: errors.New("down")}, nil, nil)
	for i := range 15 {
		if !g.Allow(context.Background(), gateAction, "") {
			t.Fatalf("request %d dropped", i)
		}
	}
	if len(metrics()) != 0 {
		t.Fatalf("drops = %v", metrics())
	}
}

// Issue29_R4_R11: after the global bucket refuses, the gate makes no call to the
// limiter until the wait time ends. New IPv6 /64 prefixes make no key.
func TestIssue29_R4_R11_GlobalRefusalKept(t *testing.T) {
	metrics := dropMetrics(t)
	rl := &mock.RateLimiter{DenyRules: map[string]bool{ratelimit.BucketTokenDeniedGlobal: true}}
	at := now
	g := newGate(t, rl, nil, func() time.Time { return at })
	for i := range 20 {
		if g.Allow(fromIP(fmt.Sprintf("2001:db8:%x:%x::1", i, i)), gateAction, "") {
			t.Fatalf("request %d allowed", i)
		}
	}
	if len(rl.Calls) != 5 {
		t.Fatalf("limiter calls = %d, want 5", len(rl.Calls))
	}
	if got := metrics()["rate_limit_token_denied_global"]; got != 20 {
		t.Fatalf("counter = %d, want 20", got)
	}
	at = at.Add(8 * time.Second)
	g.Allow(fromIP("203.0.113.9"), gateAction, "")
	if len(rl.Calls) <= 5 {
		t.Fatalf("limiter calls = %d, want more after the wait time", len(rl.Calls))
	}
}

// Issue29_R5: the drop record has one action. Two actions make two records.
func TestIssue29_R5_LogKeyedByAction(t *testing.T) {
	var buf bytes.Buffer
	g := newGate(t, &mock.RateLimiter{Deny: true}, slog.New(slog.NewJSONHandler(&buf, nil)), func() time.Time { return now })
	g.Allow(context.Background(), "action:one", "")
	g.Allow(context.Background(), "action:two", "")
	out := buf.String()
	if strings.Count(out, `"msg":"identity.audit.denied_dropped"`) != 2 ||
		!strings.Contains(out, `"action":"action:one"`) || !strings.Contains(out, `"action":"action:two"`) {
		t.Fatalf("log = %s", out)
	}
}

// Issue29_R12: the global bucket does not stop the entries of a registered
// client. A registered client has its own bucket with the client ID as key.
func TestIssue29_R12_KnownClientBucket(t *testing.T) {
	t.Run("global refusal", func(t *testing.T) {
		rl := &mock.RateLimiter{DenyRules: map[string]bool{ratelimit.BucketTokenDeniedGlobal: true}}
		g := newGate(t, rl, nil, nil)
		if g.Allow(fromIP("203.0.113.5"), gateAction, "") {
			t.Fatal("an unknown caller must be refused")
		}
		if !g.Allow(fromIP("203.0.113.6"), gateAction, "helpdesk") {
			t.Fatal("a registered client must pass")
		}
		c := rl.CallsOf(ratelimit.BucketTokenDeniedClient)
		if len(c) != 1 || c[0].Key != "helpdesk" {
			t.Fatalf("client calls = %+v", c)
		}
		if n := len(rl.CallsOf(ratelimit.BucketTokenDeniedGlobal)); n != 1 {
			t.Fatalf("global calls = %d, want 1 (the unknown caller only)", n)
		}
	})
	t.Run("client refusal", func(t *testing.T) {
		metrics := dropMetrics(t)
		rl := &mock.RateLimiter{DenyRules: map[string]bool{ratelimit.BucketTokenDeniedClient: true}}
		g := newGate(t, rl, nil, nil)
		if g.Allow(fromIP("203.0.113.6"), gateAction, "helpdesk") {
			t.Fatal("the client bucket must refuse")
		}
		if metrics()["rate_limit_token_denied_client"] != 1 {
			t.Fatalf("drops = %v", metrics())
		}
	})
	t.Run("fallback", func(t *testing.T) {
		g := newGate(t, &mock.RateLimiter{Err: errors.New("down")}, nil, nil)
		for i := range 600 {
			if !g.Allow(fromIP(fmt.Sprintf("10.%d.%d.1", i/200, i%200)), gateAction, "") {
				t.Fatalf("unknown request %d dropped", i)
			}
		}
		if g.Allow(fromIP("10.9.9.9"), gateAction, "") {
			t.Fatal("the total must refuse an unknown caller")
		}
		if !g.Allow(fromIP("10.9.9.9"), gateAction, "helpdesk") {
			t.Fatal("a registered client must pass after the total is used")
		}
	})
}
