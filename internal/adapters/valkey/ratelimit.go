package valkey

import (
	"context"
	"fmt"
	"time"

	valkeygo "github.com/valkey-io/valkey-go"

	"github.com/techorionai/constellation-identity/internal/ports/ratelimit"
)

// RateLimiter is the adapter of the port ratelimit. The counters are plain
// Valkey keys. The adapter does not use a script, because the server ACL
// denies scripts.
type RateLimiter struct {
	client valkeygo.Client
	keys   KeyMaker
}

var _ ratelimit.Limiter = (*RateLimiter)(nil)

// NewRateLimiter makes the limiter.
func NewRateLimiter(client valkeygo.Client, keys KeyMaker) *RateLimiter {
	return &RateLimiter{client: client, keys: keys}
}

// Allow counts one request in one MULTI/EXEC transaction. PEXPIRE with NX sets
// the life at the first request of the window only, and it runs in the same
// transaction as INCR. Thus a counter never exists without an expiry.
func (l *RateLimiter) Allow(ctx context.Context, rule ratelimit.Rule, key string) (ratelimit.Decision, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	k := l.keys.Key("rl", rule.Name, digest(key))
	ms := max(rule.Window.Milliseconds(), 1)
	res := l.client.DoMulti(ctx,
		l.client.B().Multi().Build(),
		l.client.B().Incr().Key(k).Build(),
		l.client.B().Pexpire().Key(k).Milliseconds(ms).Nx().Build(),
		l.client.B().Pttl().Key(k).Build(),
		l.client.B().Exec().Build())
	for _, r := range res {
		if err := r.Error(); err != nil {
			return ratelimit.Decision{}, fmt.Errorf("count request: %w", err)
		}
	}
	replies, err := res[len(res)-1].ToArray()
	if err != nil {
		return ratelimit.Decision{}, fmt.Errorf("count request: %w", err)
	}
	if len(replies) != 3 {
		return ratelimit.Decision{}, fmt.Errorf("count request: %d replies, want 3", len(replies))
	}
	count, err := replies[0].AsInt64()
	if err != nil {
		return ratelimit.Decision{}, fmt.Errorf("count request: %w", err)
	}
	pttl, err := replies[2].AsInt64()
	if err != nil {
		return ratelimit.Decision{}, fmt.Errorf("count request: %w", err)
	}
	d := ratelimit.Decision{Allowed: count <= rule.Limit, Count: count}
	if !d.Allowed {
		if pttl <= 0 {
			pttl = ms
		}
		secs := max((pttl+999)/1000, 1)
		d.RetryAfter = time.Duration(secs) * time.Second
	}
	return d, nil
}
