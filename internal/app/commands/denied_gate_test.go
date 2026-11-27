package commands_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/techorionai/constellation-platform-go/clientinfo"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/config"
	"github.com/techorionai/constellation-identity/internal/ports/ratelimit"
	"github.com/techorionai/constellation-identity/resources/test/mock"
)

// dropMetrics replaces the meter provider and returns a function that gives the
// sum of identity.audit.denied_dropped for each reason.
func dropMetrics(t *testing.T) func() map[string]int64 {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	old := otel.GetMeterProvider()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	t.Cleanup(func() { otel.SetMeterProvider(old) })
	return func() map[string]int64 {
		var rm metricdata.ResourceMetrics
		if err := reader.Collect(context.Background(), &rm); err != nil {
			t.Fatal(err)
		}
		got := map[string]int64{}
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				if m.Name != "identity.audit.denied_dropped" {
					continue
				}
				for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints {
					r, _ := dp.Attributes.Value("reason")
					if a, _ := dp.Attributes.Value("action"); a.AsString() != "identity:token:issue" {
						t.Errorf("action = %q", a.AsString())
					}
					got[r.AsString()] += dp.Value
				}
			}
		}
		return got
	}
}

func fromIP(ip string) context.Context {
	return clientinfo.ContextWith(context.Background(), clientinfo.Info{IP: netip.MustParseAddr(ip)})
}

// badRequest sends a request with an assertion that cannot be parsed. The
// result is invalid_client, and the command writes a denied entry.
func badRequest(t *testing.T, f *fixture, c context.Context) {
	t.Helper()
	_, err := f.cmd.Execute(c, request("not-a-jwt"))
	if oe, ok := apperrors.AsOAuthError(err); !ok || oe.Code != apperrors.OAuthInvalidClient {
		t.Fatalf("err = %v, want invalid_client", err)
	}
}

func gateFixture(t *testing.T, rl *mock.RateLimiter, log *slog.Logger, clock func() time.Time) *fixture {
	t.Helper()
	f := newFixture(t)
	var limits *commands.RateLimits
	if rl != nil {
		limits = newLimits(t, rl)
	}
	gate, err := commands.NewTokenDeniedGate(limits, log)
	if err != nil {
		t.Fatal(err)
	}
	if clock != nil {
		gate.WithClock(clock)
	}
	f.cmd = issueWithGate(t, f, limits, gate)
	return f
}

func countDenied(f *fixture) int {
	n := 0
	for _, a := range f.ev.Audits {
		if a.Result == "denied" {
			n++
		}
	}
	return n
}

// U6: a limiter that allows all gives one entry and no drop.
func TestU6_GateAllows(t *testing.T) {
	metrics := dropMetrics(t)
	f := gateFixture(t, &mock.RateLimiter{}, nil, nil)
	badRequest(t, f, fromIP("203.0.113.5"))
	if countDenied(f) != 1 || len(metrics()) != 0 {
		t.Fatalf("entries = %d, drops = %v", countDenied(f), metrics())
	}
}

// U7 and U8: each bucket that refuses writes no entry, adds 1 to the counter,
// writes no identity.rate_limit.limited record, and writes a drop record a
// maximum of one time each minute. The record has no IP and no client ID.
func TestU7_U8_GateRefuses(t *testing.T) {
	for _, bucket := range []string{ratelimit.BucketTokenDenied, ratelimit.BucketTokenDeniedDaily, ratelimit.BucketTokenDeniedGlobal} {
		t.Run(bucket, func(t *testing.T) {
			metrics := dropMetrics(t)
			var buf bytes.Buffer
			log := slog.New(slog.NewJSONHandler(&buf, nil))
			f := gateFixture(t, &mock.RateLimiter{DenyRules: map[string]bool{bucket: true}}, log, func() time.Time { return now })
			for range 5 {
				badRequest(t, f, fromIP("203.0.113.5"))
			}
			if countDenied(f) != 0 {
				t.Fatalf("entries = %d, want 0", countDenied(f))
			}
			if got := metrics()["rate_limit_"+bucket]; got != 5 {
				t.Fatalf("counter = %d, want 5", got)
			}
			out := buf.String()
			if strings.Contains(out, "identity.rate_limit.limited") {
				t.Fatalf("log has the limited record: %s", out)
			}
			if n := strings.Count(out, `"msg":"identity.audit.denied_dropped"`); n != 1 || !strings.Contains(out, `"dropped":1`) {
				t.Fatalf("drop records = %d, log = %s", n, out)
			}
			if strings.Contains(out, "203.0.113.5") || strings.Contains(out, "helpdesk") {
				t.Fatalf("log has an IP or a client ID: %s", out)
			}
		})
	}
}

// U9: a limiter that fails gives the in-process limit of 10 for each IP.
func TestU9_GateLimiterUnavailable(t *testing.T) {
	metrics := dropMetrics(t)
	f := gateFixture(t, &mock.RateLimiter{Err: errors.New("down")}, nil, nil)
	for range 15 {
		badRequest(t, f, fromIP("203.0.113.5"))
	}
	if countDenied(f) != 10 || metrics()["fallback_limit"] != 5 {
		t.Fatalf("entries = %d, drops = %v", countDenied(f), metrics())
	}
}

// U10: with no rate limits, the in-process limit applies to token entries.
func TestU10_GateNoRateLimits(t *testing.T) {
	metrics := dropMetrics(t)
	f := gateFixture(t, nil, nil, nil)
	for range 15 {
		badRequest(t, f, fromIP("203.0.113.5"))
	}
	if countDenied(f) != 10 || metrics()["fallback_limit"] != 5 {
		t.Fatalf("entries = %d, drops = %v", countDenied(f), metrics())
	}
}

// U13: an IPv6 client gets the /48 key at 16 times the limit, then the /64 key.
func TestU13_GateIPv6Keys(t *testing.T) {
	rl := &mock.RateLimiter{}
	f := gateFixture(t, rl, nil, nil)
	badRequest(t, f, fromIP("2001:db8:1:1::1"))
	calls := rl.CallsOf(ratelimit.BucketTokenDenied)
	if len(calls) != 2 || calls[0].Key != "2001:db8:1::/48" || calls[0].Limit != 30*commands.CoarseFactor ||
		calls[1].Key != "2001:db8:1:1::/64" || calls[1].Limit != 30 {
		t.Fatalf("calls = %+v", calls)
	}
	if g := rl.CallsOf(ratelimit.BucketTokenDeniedGlobal); len(g) != 1 || g[0].Key != "all" {
		t.Fatalf("global calls = %+v", g)
	}
}

// U14: a context with no client IP makes no IP key. Only the global bucket
// applies, so all such clients do not share one IP key.
func TestU14_GateNoIP(t *testing.T) {
	rl := &mock.RateLimiter{}
	f := gateFixture(t, rl, nil, nil)
	badRequest(t, f, context.Background())
	if n := len(rl.CallsOf(ratelimit.BucketTokenDenied)) + len(rl.CallsOf(ratelimit.BucketTokenDeniedDaily)); n != 0 {
		t.Fatalf("IP calls = %d, want 0", n)
	}
	if g := rl.CallsOf(ratelimit.BucketTokenDeniedGlobal); len(g) != 1 || countDenied(f) != 1 {
		t.Fatalf("global calls = %+v, entries = %d", g, countDenied(f))
	}
}

// U15: the drop record is at most one each minute for each reason.
func TestU15_GateLogRule(t *testing.T) {
	var buf bytes.Buffer
	at := now
	f := gateFixture(t, &mock.RateLimiter{DenyRules: map[string]bool{ratelimit.BucketTokenDenied: true}},
		slog.New(slog.NewJSONHandler(&buf, nil)), func() time.Time { return at })
	for range 3 {
		badRequest(t, f, fromIP("203.0.113.5"))
	}
	at = at.Add(time.Minute)
	for range 4 {
		badRequest(t, f, fromIP("203.0.113.5"))
	}
	out := buf.String()
	if strings.Count(out, `"msg":"identity.audit.denied_dropped"`) != 2 || !strings.Contains(out, `"dropped":1`) || !strings.Contains(out, `"dropped":3`) {
		t.Fatalf("log = %s", out)
	}
}

// U16: CheckQuiet with a failing limiter gives ErrRateLimiterUnavailable and
// one unavailable record.
func TestU16_CheckQuietUnavailable(t *testing.T) {
	var buf bytes.Buffer
	l, err := commands.NewRateLimits(commands.RateLimitsDeps{
		Limiter: &mock.RateLimiter{Err: errors.New("down")}, Rules: config.DefaultRateRules(), Log: slog.New(slog.NewJSONHandler(&buf, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.CheckQuiet(context.Background(), ratelimit.BucketTokenDeniedGlobal, "all"); !errors.Is(err, apperrors.ErrRateLimiterUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if strings.Count(buf.String(), `"msg":"identity.rate_limit.unavailable"`) != 1 {
		t.Fatalf("log = %s", buf.String())
	}
}
