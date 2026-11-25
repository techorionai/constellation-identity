package mock

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/techorionai/constellation-identity/internal/ports/ratelimit"
)

// RateCall is one call of RateLimiter.Allow.
type RateCall struct {
	Rule string
	Key  string
}

// RateLimiter is an in-memory rate limiter. It allows each call, unless Deny
// or Err is set.
type RateLimiter struct {
	mu    sync.Mutex
	Calls []RateCall
	// Deny makes each call return a denied decision.
	Deny bool
	// DenyRules makes the calls of the named rules denied.
	DenyRules map[string]bool
	// RetryAfter is the wait time of a denied decision. The default is 7 s.
	RetryAfter time.Duration
	// Err is returned by each call when it is set.
	Err error
}

var _ ratelimit.Limiter = (*RateLimiter)(nil)

// Allow records the call and returns the set decision.
func (l *RateLimiter) Allow(_ context.Context, rule ratelimit.Rule, key string) (ratelimit.Decision, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.Calls = append(l.Calls, RateCall{Rule: rule.Name, Key: key})
	if l.Err != nil {
		return ratelimit.Decision{}, errors.Join(errors.New("rate limiter"), l.Err)
	}
	if l.Deny || l.DenyRules[rule.Name] {
		ra := l.RetryAfter
		if ra == 0 {
			ra = 7 * time.Second
		}
		return ratelimit.Decision{Allowed: false, Count: rule.Limit + 1, RetryAfter: ra}, nil
	}
	return ratelimit.Decision{Allowed: true, Count: 1}, nil
}

// CallsOf returns the calls of one rule.
func (l *RateLimiter) CallsOf(rule string) []RateCall {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []RateCall
	for _, c := range l.Calls {
		if c.Rule == rule {
			out = append(out, c)
		}
	}
	return out
}
