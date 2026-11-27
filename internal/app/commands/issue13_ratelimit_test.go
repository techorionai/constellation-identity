package commands_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/adapters/jose"
	"github.com/techorionai/constellation-identity/internal/app/commands"
	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/config"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/manifests"
	"github.com/techorionai/constellation-identity/internal/ports/ratelimit"
	"github.com/techorionai/constellation-identity/internal/ports/tokensigner"
	"github.com/techorionai/constellation-identity/resources/test/mock"
)

func newLimits(t *testing.T, l ratelimit.Limiter) *commands.RateLimits {
	t.Helper()
	r, err := commands.NewRateLimits(commands.RateLimitsDeps{Limiter: l, Rules: config.DefaultRateRules()})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func requireRateLimited(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, apperrors.ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited", err)
	}
	re, ok := apperrors.AsRateLimited(err)
	if !ok || re.RetryAfter != 7*time.Second {
		t.Fatalf("rate limited error = %+v, want a wait time of 7 s", re)
	}
}

func requireLimiterUnavailable(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, apperrors.ErrRateLimiterUnavailable) {
		t.Fatalf("err = %v, want ErrRateLimiterUnavailable", err)
	}
}

// issueWithLimits makes the command of the fixture again, with rate limits.
func issueWithLimits(t *testing.T, f *fixture, rl *commands.RateLimits) *commands.IssueServiceTokenCommand {
	t.Helper()
	cmd, err := commands.NewIssueServiceToken(commands.IssueServiceTokenDeps{
		Issuer: issuer, Clients: f.clients, ClientRoles: f.roles,
		Manifests: &fakeManifests{apps: map[string]bool{"demo": true, "identity": true}},
		JTI:       f.jti, Keys: fakeKeySource{key: tokensigner.Key{KID: "sig-1", Private: f.sign}},
		Signer: jose.Signer{}, Parser: jose.AssertionParser{},
		Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return now }, RateLimits: rl,
		Tx: mock.Tx{}, Audit: f.ev,
	})
	if err != nil {
		t.Fatal(err)
	}
	return cmd
}

// Issue13_U8: the client bucket uses the verified client ID, and a denied
// request gives a RateLimitedError with the OAuth status 429.
func TestIssue13_U8_IssueServiceTokenDenied(t *testing.T) {
	f := newFixture(t)
	rl := &mock.RateLimiter{Deny: true}
	cmd := issueWithLimits(t, f, newLimits(t, rl))
	in := request(f.assertion(t, nil))
	in.ClientID = "helpdesk"
	_, err := cmd.Execute(ctx, in)
	requireRateLimited(t, err)
	oe, ok := apperrors.AsOAuthError(err)
	if !ok || oe.Status() != http.StatusTooManyRequests || oe.Code != apperrors.OAuthTemporarilyUnavailable || oe.RetryAfter != 7*time.Second {
		t.Fatalf("oauth error = %+v", oe)
	}
	calls := rl.CallsOf(ratelimit.BucketTokenClient)
	if len(calls) != 1 || calls[0].Key != "helpdesk" {
		t.Fatalf("calls = %+v, want one call with the verified client ID", rl.Calls)
	}
}

// Issue13_U8: a bad signature gives no call of the client bucket, so a spoofed
// client ID cannot use the budget of a real client.
func TestIssue13_U8_BadSignatureNoCall(t *testing.T) {
	f := newFixture(t)
	rl := &mock.RateLimiter{}
	cmd := issueWithLimits(t, f, newLimits(t, rl))
	bad := signES256(t, newKey(t), "k1", map[string]any{
		"iss": "helpdesk", "sub": "helpdesk", "aud": issuer, "jti": "x", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	})
	_, err := cmd.Execute(ctx, request(bad))
	if oe, ok := apperrors.AsOAuthError(err); !ok || oe.Code != apperrors.OAuthInvalidClient {
		t.Fatalf("err = %v, want invalid_client", err)
	}
	if len(rl.Calls) != 0 {
		t.Fatalf("calls = %+v, want none", rl.Calls)
	}
}

// Issue13_U14: a limiter error gives ErrRateLimiterUnavailable and a 503 with
// a wait time of 5 s.
func TestIssue13_U14_IssueServiceTokenLimiterError(t *testing.T) {
	f := newFixture(t)
	cmd := issueWithLimits(t, f, newLimits(t, &mock.RateLimiter{Err: errors.New("down")}))
	_, err := cmd.Execute(ctx, request(f.assertion(t, nil)))
	requireLimiterUnavailable(t, err)
	oe, ok := apperrors.AsOAuthError(err)
	if !ok || oe.Status() != http.StatusServiceUnavailable || oe.RetryAfter != 5*time.Second || oe.Code != apperrors.OAuthTemporarilyUnavailable {
		t.Fatalf("oauth error = %+v", oe)
	}
}

// Issue13_U8 and U14: the introspection uses the bucket introspect_client with
// the verified client ID.
func TestIssue13_Introspect(t *testing.T) {
	e := newIntrospectEnv(t)
	rl := &mock.RateLimiter{Deny: true}
	deps := commands.IntrospectDeps{
		Auth: e.fixture.cmd, Tokens: e.api, UserRoles: e.roles, Now: func() time.Time { return now }, RateLimits: newLimits(t, rl),
	}
	cmd, err := commands.NewIntrospect(deps)
	if err != nil {
		t.Fatal(err)
	}
	_, err = cmd.Execute(ctx, e.in(t))
	requireRateLimited(t, err)
	if c := rl.CallsOf(ratelimit.BucketIntrospectClient); len(c) != 1 || c[0].Key != "helpdesk" {
		t.Fatalf("calls = %+v", rl.Calls)
	}
	if e.api.Lookups != 0 {
		t.Fatal("a limited request must not read the token")
	}
	deps.RateLimits = newLimits(t, &mock.RateLimiter{Err: errors.New("down")})
	cmd, err = commands.NewIntrospect(deps)
	if err != nil {
		t.Fatal(err)
	}
	_, err = cmd.Execute(ctx, e.in(t))
	requireLimiterUnavailable(t, err)
	if oe, ok := apperrors.AsOAuthError(err); !ok || oe.Status() != http.StatusServiceUnavailable || oe.RetryAfter != 5*time.Second {
		t.Fatalf("oauth error = %+v", oe)
	}
}

// Issue13: the token exchange counts in the same bucket token_client as the
// client credentials grant. The platform-go token source uses one wait time for
// both grants.
func TestIssue13_TokenExchangeSharesTokenClientBucket(t *testing.T) {
	e := newExchangeEnv(t)
	rl := &mock.RateLimiter{Deny: true}
	n := 0
	cmd, err := commands.NewTokenExchange(commands.TokenExchangeDeps{
		Issuer: issuer, Auth: e.fixture.cmd, Clients: e.clients, ClientRoles: e.fixture.roles,
		Manifests: &fakeManifests{apps: map[string]bool{"mail": true, "identity": true}},
		Users:     e.users, UserRoles: e.roles, Agents: e.agents, AgentRoles: e.aroles,
		Keys:   keySet{t: t, f: e.fixture, key: tokensigner.Key{KID: "sig-1", Private: e.sign}},
		Signer: jose.Signer{}, Verifier: jose.Verifier{},
		Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return now },
		NewID:      func() string { n++; return fmt.Sprintf("x-%d", n) },
		RateLimits: newLimits(t, rl),
		Tx:         mock.Tx{}, Audit: e.ev,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = cmd.Execute(ctx, commands.TokenExchange{AssertionType: domain.AssertionType, Assertion: e.assertion(t, nil)})
	requireRateLimited(t, err)
	if c := rl.CallsOf(ratelimit.BucketTokenClient); len(c) != 1 || c[0].Key != "helpdesk" {
		t.Fatalf("calls = %+v, want one call of token_client", rl.Calls)
	}
}

type publishRepo struct {
	manifests.Repository
	published int
}

func (r *publishRepo) Publish(_ context.Context, m domain.Manifest, by string) (domain.PublishedManifest, error) {
	r.published++
	return domain.PublishedManifest{Manifest: m, Version: 1, PublishedBy: by}, nil
}

// Issue13_U9: the own publish at startup is not counted, and a service publish
// over the limit is denied. U14: a limiter error gives ErrRateLimiterUnavailable.
func TestIssue13_U9_PublishManifest(t *testing.T) {
	f := newFixture(t)
	rl := &mock.RateLimiter{Deny: true}
	repo := &publishRepo{}
	cmd := commands.NewPublishManifest(repo, f.clients, nil).WithAudit(mock.Tx{}, &mock.Events{}).WithRateLimits(newLimits(t, rl))
	own := domain.Manifest{App: "identity", Permissions: []domain.PermissionDef{{Key: "identity:admin", Description: "Administer the identity service."}}}
	if _, err := cmd.Execute(ctx, commands.PublishManifest{Manifest: own, PublishedBy: "identity", Internal: true}); err != nil {
		t.Fatalf("internal publish: %v", err)
	}
	if len(rl.Calls) != 0 || repo.published != 1 {
		t.Fatalf("calls = %+v, published = %d", rl.Calls, repo.published)
	}
	in := commands.PublishManifest{
		PathApp: "helpdesk", CallerClientID: "helpdesk", CallerIsService: true, PublishedBy: "helpdesk",
		Manifest: domain.Manifest{App: "helpdesk"},
	}
	_, err := cmd.Execute(ctx, in)
	requireRateLimited(t, err)
	if c := rl.CallsOf(ratelimit.BucketManifestPublish); len(c) != 1 || c[0].Key != "helpdesk" || repo.published != 1 {
		t.Fatalf("calls = %+v, published = %d", rl.Calls, repo.published)
	}
	cmd = commands.NewPublishManifest(repo, f.clients, nil).WithAudit(mock.Tx{}, &mock.Events{}).WithRateLimits(newLimits(t, &mock.RateLimiter{Err: errors.New("down")}))
	_, err = cmd.Execute(ctx, in)
	requireLimiterUnavailable(t, err)
}

// Issue13_U10: a denied creation of an API token stops before any other check.
func TestIssue13_U10_CreateAPIToken(t *testing.T) {
	e := newTokenEnv()
	rl := &mock.RateLimiter{Deny: true}
	build := func(l ratelimit.Limiter) *commands.APITokens {
		return commands.NewAPITokens(commands.APITokensDeps{
			Tokens: e.api, Users: e.users, UserRoles: e.roles, Tx: mock.Tx{}, Audit: &mock.Events{}, Log: e.logger(), Now: e.clock, RateLimits: newLimits(t, l),
			Settings: commands.APITokenSettings{DefaultTTLDays: 90, MaxTTLDays: 365, MaxPerUser: e.max},
		})
	}
	_, err := e.create(build(rl), user1, "name", "helpdesk:ticket:read", nil)
	requireRateLimited(t, err)
	if calls := rl.CallsOf(ratelimit.BucketAPITokenCreate); len(calls) != 1 || calls[0].Key != user1 {
		t.Fatalf("calls = %+v", rl.Calls)
	}
	if len(e.api.Rows) != 0 {
		t.Fatalf("rows = %d, want 0", len(e.api.Rows))
	}
	_, err = e.create(build(&mock.RateLimiter{Err: errors.New("down")}), user1, "name", "helpdesk:ticket:read", nil)
	requireLimiterUnavailable(t, err)
}

// Issue13: a nil RateLimits does not limit, and a fail-open check lets a
// request pass when the limiter has an error.
func TestIssue13_RateLimitsModes(t *testing.T) {
	var none *commands.RateLimits
	if err := none.Check(ctx, ratelimit.BucketTokenIP, "k"); err != nil {
		t.Fatal(err)
	}
	rl := newLimits(t, &mock.RateLimiter{Err: errors.New("down")})
	if err := rl.CheckOpen(ctx, ratelimit.BucketPublicMeta, "k"); err != nil {
		t.Fatalf("fail open: %v", err)
	}
	requireLimiterUnavailable(t, rl.Check(ctx, ratelimit.BucketTokenIP, "k"))
}

// Issue13_U15: two IPv6 addresses of one /64 share one login counter, and the
// session keeps the full address.
func TestIssue13_U15_LoginIPKey(t *testing.T) {
	e := newEnv()
	e.addUser("active", "active@example.com", domain.UserActive, "right password 1")
	cmd := e.login()
	a, b := "2001:db8:1:2::1", "2001:db8:1:2::2"
	key := "2001:db8:1:2::/64"
	for _, ip := range []string{a, b} {
		_, err := cmd.Execute(ctx, commands.Login{Email: "active@example.com", Password: "wrong password 1", IP: ip, IPKey: key})
		if !errors.Is(err, commands.ErrBadCredentials) {
			t.Fatalf("err = %v", err)
		}
	}
	if e.limiter.IPs[key] != 2 || len(e.limiter.IPs) != 1 {
		t.Fatalf("counters = %v, want one counter of 2", e.limiter.IPs)
	}
	issued, err := cmd.Execute(ctx, commands.Login{Email: "active@example.com", Password: "right password 1", IP: b, IPKey: key})
	if err != nil {
		t.Fatal(err)
	}
	if got := e.sessions.Rows[issued.SessionID].IPAddress; got != b {
		t.Fatalf("session IP = %q, want %q", got, b)
	}
}

// Issue13: the unlock command uses the same email rule as the login.
func TestIssue13_UnlockLogin(t *testing.T) {
	l := mock.NewLimiter()
	l.Emails["a@example.com"] = 6
	cmd := commands.NewUnlockLogin(l, nil).WithAudit(mock.NewUsers(), mock.Tx{}, &mock.Events{})
	got, err := cmd.Execute(ctx, commands.UnlockLogin{Email: "  A@Example.COM "})
	if err != nil || !got {
		t.Fatalf("got %v, err %v, want unlocked", got, err)
	}
	got, err = cmd.Execute(ctx, commands.UnlockLogin{Email: "a@example.com"})
	if err != nil || got {
		t.Fatalf("got %v, err %v, want not locked", got, err)
	}
	l.Err = errors.New("down")
	if _, err = cmd.Execute(ctx, commands.UnlockLogin{Email: "a@example.com"}); err == nil {
		t.Fatal("want an error")
	}
}

// R5: a user caller has one publish bucket for each user. An OAuth client of
// users does not share one bucket for all its users.
func TestR5_PublishKeyOfUserCaller(t *testing.T) {
	f := newFixture(t)
	rl := &mock.RateLimiter{Deny: true}
	cmd := commands.NewPublishManifest(&publishRepo{}, f.clients, nil).WithAudit(mock.Tx{}, &mock.Events{}).WithRateLimits(newLimits(t, rl))
	for _, caller := range []string{"user-1", "user-2"} {
		_, err := cmd.Execute(ctx, commands.PublishManifest{
			PathApp: "helpdesk", CallerClientID: "web", CallerIsService: false, PublishedBy: caller,
			Manifest: domain.Manifest{App: "helpdesk"},
		})
		requireRateLimited(t, err)
	}
	c := rl.CallsOf(ratelimit.BucketManifestPublish)
	if len(c) != 2 || c[0].Key != "user-1" || c[1].Key != "user-2" {
		t.Fatalf("calls = %+v, want the keys user-1 and user-2", rl.Calls)
	}
}

// countLimiter counts the requests of each rule and key. It denies a request
// over the limit of the rule.
type countLimiter struct{ n map[string]int64 }

func (l *countLimiter) Allow(_ context.Context, rule ratelimit.Rule, key string) (ratelimit.Decision, error) {
	if l.n == nil {
		l.n = map[string]int64{}
	}
	k := rule.Name + "|" + key
	l.n[k]++
	return ratelimit.Decision{Allowed: l.n[k] <= rule.Limit, Count: l.n[k], RetryAfter: 7 * time.Second}, nil
}

// R11: an attacker with many /64 prefixes in one /48 prefix gets the coarse
// limit, 16 times the limit of the bucket. The request over the coarse limit
// makes no key for its /64 prefix.
func TestR11_CoarseIPLimit(t *testing.T) {
	rules := config.DefaultRateRules()
	rule := rules[ratelimit.BucketOAuthPublic]
	rule.Limit = 2
	rules[ratelimit.BucketOAuthPublic] = rule
	l := &countLimiter{}
	limits, err := commands.NewRateLimits(commands.RateLimitsDeps{Limiter: l, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	coarse := "2001:db8:1::/48"
	allowed := 0
	for i := range 100 {
		key := fmt.Sprintf("2001:db8:1:%x::/64", i)
		if err := limits.CheckIP(ctx, ratelimit.BucketOAuthPublic, key, coarse, false); err == nil {
			allowed++
		} else {
			requireRateLimited(t, err)
		}
	}
	if allowed != 2*commands.CoarseFactor {
		t.Fatalf("allowed = %d, want %d", allowed, 2*commands.CoarseFactor)
	}
	// One counter for the coarse key and one for each /64 prefix that passed.
	if len(l.n) != 1+allowed {
		t.Fatalf("counters = %d, want %d", len(l.n), 1+allowed)
	}
	// A client with one /64 prefix keeps the normal limit.
	one := "2001:db8:2:1::/64"
	for i := range 3 {
		err := limits.CheckIP(ctx, ratelimit.BucketOAuthPublic, one, "2001:db8:2::/48", false)
		if (i < 2) != (err == nil) {
			t.Fatalf("request %d: err = %v", i+1, err)
		}
	}
	// An IPv4 client has no coarse key.
	if err := limits.CheckIP(ctx, ratelimit.BucketOAuthPublic, "203.0.113.5", "", false); err != nil {
		t.Fatal(err)
	}
}

// R11: the coarse login counter stops an attacker with many /64 prefixes in one
// /48 prefix. The limit is 16 times the limit of the IP counter.
func TestR11_LoginCoarseCounter(t *testing.T) {
	e := newEnv()
	e.addUser("active", "active@example.com", domain.UserActive, "right password 1")
	cmd := e.login()
	var limited int
	const maxIP = 50 // MaxFailuresPerIP of the test environment
	for i := range maxIP*commands.CoarseFactor + 10 {
		in := commands.Login{
			Email: fmt.Sprintf("user%d@example.com", i), Password: "wrong password 1",
			IP:          fmt.Sprintf("2001:db8:1:%x::1", i),
			IPKey:       fmt.Sprintf("2001:db8:1:%x::/64", i),
			IPCoarseKey: "2001:db8:1::/48",
		}
		if _, err := cmd.Execute(ctx, in); errors.Is(err, commands.ErrTooManyAttempts) {
			limited++
		}
	}
	if limited != 10 {
		t.Fatalf("limited = %d, want 10", limited)
	}
}
