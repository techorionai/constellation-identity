package commands

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/techorionai/constellation-platform-go/clientinfo"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/common/fallback"
	"github.com/techorionai/constellation-identity/internal/domain/ipkey"
	"github.com/techorionai/constellation-identity/internal/ports/ratelimit"
)

// The reason of a drop that the in-process limiter makes.
const ReasonFallbackLimit = "fallback_limit"

// The limits of the in-process fallback of the token gate. The fallback runs
// only while the shared limiter does not answer, or when the rate limits are
// off. The values are not configuration.
const (
	gateFallbackKeyLimit   = 10
	gateFallbackKeyWindow  = time.Minute
	gateFallbackMaxKeys    = 10000
	gateFallbackMinuteMax  = 600
	gateFallbackDailyMax   = 100000
	gateFallbackDailyWin   = 24 * time.Hour
	gateLogInterval        = time.Minute
	unknownClientKey       = "unknown"
	tokenDeniedGlobalKey   = "all"
	deniedDroppedCounter   = "identity.audit.denied_dropped"
	deniedDroppedLogRecord = "identity.audit.denied_dropped"
)

// DeniedDrops counts the denied audit entries that a service did not write.
// The counter has the attributes action and reason. It never has an IP or an
// ID.
type DeniedDrops struct {
	c metric.Int64Counter
}

// NewDeniedDrops makes the counter identity.audit.denied_dropped.
func NewDeniedDrops() (*DeniedDrops, error) {
	c, err := otel.Meter("identity").Int64Counter(deniedDroppedCounter,
		metric.WithDescription("Denied audit entries that the service did not write, by action and reason."))
	if err != nil {
		return nil, fmt.Errorf("make the denied drop counter: %w", err)
	}
	return &DeniedDrops{c: c}, nil
}

// Add adds 1 for one dropped entry.
func (d *DeniedDrops) Add(ctx context.Context, action, reason string) {
	if d == nil {
		return
	}
	d.c.Add(context.WithoutCancel(ctx), 1, metric.WithAttributes(
		attribute.String("action", action), attribute.String("reason", reason)))
}

// TokenDeniedGate limits the denied audit entries of the token requests. A
// refused entry is not written. The OAuth response does not change. A nil gate
// does not limit.
type TokenDeniedGate struct {
	limits *RateLimits
	fb     *fallback.Limiter
	drops  *DeniedDrops
	log    *slog.Logger
	now    func() time.Time

	mu   sync.Mutex
	logs map[string]*dropLog
}

type dropLog struct {
	last    time.Time
	pending int
}

// NewTokenDeniedGate makes the gate. limits can be nil: the in-process limiter
// then applies (the rate limits are off). The gate has one in-process limiter
// for the whole process, so share one gate between the token commands.
func NewTokenDeniedGate(limits *RateLimits, log *slog.Logger) (*TokenDeniedGate, error) {
	drops, err := NewDeniedDrops()
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	g := &TokenDeniedGate{limits: limits, drops: drops, log: log, now: time.Now, logs: map[string]*dropLog{}}
	g.fb = fallback.New(gateFallbackKeyLimit, gateFallbackKeyWindow, gateFallbackMaxKeys,
		fallback.WithTotal(gateFallbackMinuteMax, time.Minute),
		fallback.WithTotal(gateFallbackDailyMax, gateFallbackDailyWin),
		fallback.WithClock(func() time.Time { return g.now() }))
	return g, nil
}

// WithClock sets the clock of the gate. It is for tests.
func (g *TokenDeniedGate) WithClock(now func() time.Time) *TokenDeniedGate {
	g.now = now
	return g
}

// Allow reports whether the service can write one denied token entry. It never
// returns an error.
func (g *TokenDeniedGate) Allow(ctx context.Context, action string) bool {
	if g == nil {
		return true
	}
	key, coarse := unknownClientKey, ""
	if info, ok := clientinfo.FromContext(ctx); ok && info.IP.IsValid() {
		addr := info.IP.String()
		key, coarse = ipkey.Key(addr), ipkey.CoarseKey(addr)
	}
	if g.limits == nil {
		return g.fallbackAllow(ctx, action, key)
	}
	var err error
	if err = g.limits.CheckIPQuiet(ctx, ratelimit.BucketTokenDenied, key, coarse); err == nil {
		if err = g.limits.CheckIPQuiet(ctx, ratelimit.BucketTokenDeniedDaily, key, coarse); err == nil {
			err = g.limits.CheckQuiet(ctx, ratelimit.BucketTokenDeniedGlobal, tokenDeniedGlobalKey)
		}
	}
	if err == nil {
		return true
	}
	if re, ok := apperrors.AsRateLimited(err); ok {
		g.drop(ctx, action, "rate_limit_"+re.Bucket)
		return false
	}
	return g.fallbackAllow(ctx, action, key)
}

func (g *TokenDeniedGate) fallbackAllow(ctx context.Context, action, key string) bool {
	if g.fb.Allow(key) {
		return true
	}
	g.drop(ctx, action, ReasonFallbackLimit)
	return false
}

// drop counts the drop and writes the log record. The record is at most one
// each minute for each reason. It has the number of drops since the last
// record. It has no IP and no client ID.
func (g *TokenDeniedGate) drop(ctx context.Context, action, reason string) {
	g.drops.Add(ctx, action, reason)
	g.mu.Lock()
	l := g.logs[reason]
	if l == nil {
		l = &dropLog{}
		g.logs[reason] = l
	}
	l.pending++
	now := g.now()
	var n int
	if l.last.IsZero() || now.Sub(l.last) >= gateLogInterval {
		n, l.pending, l.last = l.pending, 0, now
	}
	g.mu.Unlock()
	if n > 0 {
		g.log.WarnContext(ctx, deniedDroppedLogRecord, "event", deniedDroppedLogRecord,
			"action", action, "reason", reason, "dropped", n)
	}
}
