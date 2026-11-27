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
	gateFallbackKeyLimit    = 10
	gateFallbackKeyWindow   = time.Minute
	gateFallbackMaxKeys     = 10000
	gateFallbackClientLimit = 60
	gateFallbackMinuteMax   = 600
	gateFallbackDailyMax    = 100000
	gateFallbackDailyWin    = 24 * time.Hour
	gateLogInterval         = time.Minute
	tokenDeniedGlobalKey    = "all"
	deniedDroppedCounter    = "identity.audit.denied_dropped"
	deniedDroppedLogRecord  = "identity.audit.denied_dropped"
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
//
// A request of an unauthenticated caller goes through the buckets for the IP,
// the daily IP limit, and the global limit. A bad signature, an unknown client,
// and a public client are unauthenticated callers. A request of a client that
// authenticated goes through the IP bucket and the bucket of that client. It
// does not use the global bucket. Only a caller that has the key of the client
// can use the budget of that client. Thus a flood of unauthenticated callers
// cannot stop the entries of an authenticated client.
//
// When a bucket refuses, the gate gives a DropSummary a maximum of one time each
// minute for each action and reason. The caller writes it as one audit entry.
// Thus an attacker who uses up a shared budget does not stop all audit signal.
type TokenDeniedGate struct {
	limits *RateLimits
	fb     *fallback.Limiter
	fbCli  *fallback.Limiter
	drops  *DeniedDrops
	log    *slog.Logger
	now    func() time.Time

	mu      sync.Mutex
	logs    map[string]*dropLog
	refused map[string]refusal
	// shared has the refusals of the global bucket and of the client bucket.
	// They never use the bounded table of the IP refusals, so a flood of IP
	// refusals cannot push them out. The global bucket has one key. The client
	// bucket has only keys of clients that authenticated.
	shared map[string]refusal
}

// DropSummary tells the caller to write one audit entry that says that the gate
// dropped denied token entries. It has no IP and no client ID.
type DropSummary struct {
	Action  string
	Reason  string
	Dropped int
	Window  time.Duration
}

type dropLog struct {
	last    time.Time
	pending int
}

// refusal is a refusal of the shared limiter that the gate keeps in memory
// until the wait time ends. While it holds, the gate makes no call to the
// shared limiter for the same bucket and key.
type refusal struct {
	bucket string
	until  time.Time
}

// gateStep is one check of the shared limiter.
type gateStep struct{ bucket, key, coarse string }

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
	g := &TokenDeniedGate{
		limits: limits, drops: drops, log: log, now: time.Now,
		logs: map[string]*dropLog{}, refused: map[string]refusal{}, shared: map[string]refusal{},
	}
	clock := fallback.WithClock(func() time.Time { return g.now() })
	g.fb = fallback.New(gateFallbackKeyLimit, gateFallbackKeyWindow, gateFallbackMaxKeys,
		fallback.WithTotal(gateFallbackMinuteMax, time.Minute),
		fallback.WithTotal(gateFallbackDailyMax, gateFallbackDailyWin),
		clock)
	// The client limiter has no total. Its keys are IDs of registered clients,
	// so the number of keys has a bound.
	g.fbCli = fallback.New(gateFallbackClientLimit, gateFallbackKeyWindow, gateFallbackMaxKeys, clock)
	return g, nil
}

// WithClock sets the clock of the gate. It is for tests.
func (g *TokenDeniedGate) WithClock(now func() time.Time) *TokenDeniedGate {
	g.now = now
	return g
}

// Allow reports whether the service can write one denied token entry. clientID
// is the ID of a client that authenticated, or an empty string for an
// unauthenticated caller. It never returns an error.
func (g *TokenDeniedGate) Allow(ctx context.Context, action, clientID string) bool {
	ok, _ := g.Check(ctx, action, clientID)
	return ok
}

// Check is like Allow. If the gate drops the entry, it can also return a
// summary that the caller must write as one audit entry.
func (g *TokenDeniedGate) Check(ctx context.Context, action, clientID string) (bool, *DropSummary) {
	if g == nil {
		return true, nil
	}
	key, coarse := "", ""
	if info, ok := clientinfo.FromContext(ctx); ok && info.IP.IsValid() {
		addr := info.IP.String()
		key, coarse = ipkey.Key(addr), ipkey.CoarseKey(addr)
	}
	if g.limits == nil {
		return g.fallbackCheck(ctx, action, clientID, key)
	}
	steps := gateSteps(clientID, key, coarse)
	// A refusal that the gate kept stops the request before any call. A request
	// of a new IP prefix then makes no key in the shared limiter.
	for _, s := range steps {
		if bucket, ok := g.refusedNow(s); ok {
			return false, g.drop(ctx, action, "rate_limit_"+bucket)
		}
	}
	for _, s := range steps {
		err := g.limits.CheckIPQuiet(ctx, s.bucket, s.key, s.coarse)
		if err == nil {
			continue
		}
		if re, ok := apperrors.AsRateLimited(err); ok {
			g.remember(s, re.RetryAfter)
			return false, g.drop(ctx, action, "rate_limit_"+re.Bucket)
		}
		return g.fallbackCheck(ctx, action, clientID, key)
	}
	return true, nil
}

// gateSteps lists the checks of one request, in order. A request with no client
// IP has no IP step, because all such requests would share one key.
func gateSteps(clientID, key, coarse string) []gateStep {
	var steps []gateStep
	if key != "" {
		steps = append(steps, gateStep{ratelimit.BucketTokenDenied, key, coarse})
	}
	if clientID != "" {
		return append(steps, gateStep{ratelimit.BucketTokenDeniedClient, clientID, ""})
	}
	if key != "" {
		steps = append(steps, gateStep{ratelimit.BucketTokenDeniedDaily, key, coarse})
	}
	return append(steps, gateStep{ratelimit.BucketTokenDeniedGlobal, tokenDeniedGlobalKey, ""})
}

func refusalKey(s gateStep) string { return s.bucket + "|" + s.key }

// isShared reports whether the step has its own refusal table. The IP buckets
// have one key for each caller, so they use the bounded table.
func isShared(s gateStep) bool {
	return s.bucket == ratelimit.BucketTokenDeniedGlobal || s.bucket == ratelimit.BucketTokenDeniedClient
}

func (g *TokenDeniedGate) tableOf(s gateStep) map[string]refusal {
	if isShared(s) {
		return g.shared
	}
	return g.refused
}

// refusedNow returns the bucket of a refusal that still holds for the step.
func (g *TokenDeniedGate) refusedNow(s gateStep) (string, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	table := g.tableOf(s)
	k := refusalKey(s)
	r, ok := table[k]
	if !ok {
		return "", false
	}
	if !g.now().Before(r.until) {
		delete(table, k)
		return "", false
	}
	return r.bucket, true
}

// remember keeps a refusal in memory. The table of IP refusals has a maximum of
// gateFallbackMaxKeys refusals. If it is full of live refusals, the gate does
// not keep the new IP refusal. A refusal of the global bucket or the client
// bucket goes to its own table, so the IP refusals cannot push it out. The
// global table has one key. The client table has only keys of clients that
// authenticated, and it has the same maximum.
func (g *TokenDeniedGate) remember(s gateStep, retryAfter time.Duration) {
	if retryAfter < time.Second {
		retryAfter = time.Second
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	k := refusalKey(s)
	table := g.tableOf(s)
	if _, ok := table[k]; !ok && len(table) >= gateFallbackMaxKeys {
		for rk, r := range table {
			if !now.Before(r.until) {
				delete(table, rk)
			}
		}
		if len(table) >= gateFallbackMaxKeys {
			return
		}
	}
	table[k] = refusal{bucket: s.bucket, until: now.Add(retryAfter)}
}

func (g *TokenDeniedGate) fallbackCheck(ctx context.Context, action, clientID, key string) (bool, *DropSummary) {
	var ok bool
	switch {
	case clientID != "":
		ok = g.fbCli.AllowKey(clientID)
	case key == "":
		// No client IP: only the totals apply. One key for all such clients
		// would let one client use the budget of all.
		ok = g.fb.AllowTotal()
	default:
		ok = g.fb.Allow(key)
	}
	if ok {
		return true, nil
	}
	return false, g.drop(ctx, action, ReasonFallbackLimit)
}

// drop counts the drop and writes the log record. The record is at most one
// each minute for each action and reason. It has the number of drops since the
// last record. It has no IP and no client ID. It returns a summary at the same
// rate, for the audit entry.
func (g *TokenDeniedGate) drop(ctx context.Context, action, reason string) *DropSummary {
	g.drops.Add(ctx, action, reason)
	g.mu.Lock()
	lk := action + "|" + reason
	l := g.logs[lk]
	if l == nil {
		l = &dropLog{}
		g.logs[lk] = l
	}
	l.pending++
	now := g.now()
	var n int
	if l.last.IsZero() || now.Sub(l.last) >= gateLogInterval {
		n, l.pending, l.last = l.pending, 0, now
	}
	g.mu.Unlock()
	if n == 0 {
		return nil
	}
	g.log.WarnContext(ctx, deniedDroppedLogRecord, "event", deniedDroppedLogRecord,
		"action", action, "reason", reason, "dropped", n)
	return &DropSummary{Action: action, Reason: reason, Dropped: n, Window: gateLogInterval}
}
