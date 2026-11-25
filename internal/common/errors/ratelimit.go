package errors

import (
	stderrors "errors"
	"fmt"
	"time"
)

// DefaultUnavailableRetryAfter is the Retry-After value of a 503 from the
// rate limiter.
const DefaultUnavailableRetryAfter = 5 * time.Second

// ErrRateLimited is the sentinel of a request that a rate limit stops.
var ErrRateLimited = stderrors.New("rate limited")

// ErrRateLimiterUnavailable is the sentinel of a rate limiter that does not
// answer. A bucket that fails closed gives this error.
var ErrRateLimiterUnavailable = stderrors.New("rate limiter unavailable")

// RateLimitedError is a request that a rate limit stops. RetryAfter is the
// wait time.
type RateLimitedError struct {
	Bucket     string
	RetryAfter time.Duration
}

// Error returns the bucket and the wait time.
func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("rate limited in bucket %s, retry after %s", e.Bucket, e.RetryAfter)
}

// Is makes errors.Is(err, ErrRateLimited) true.
func (e *RateLimitedError) Is(target error) bool { return target == ErrRateLimited }

// AsRateLimited returns the RateLimitedError in the chain.
func AsRateLimited(err error) (*RateLimitedError, bool) {
	var re *RateLimitedError
	if stderrors.As(err, &re) {
		return re, true
	}
	return nil, false
}

// RetryAfterSeconds returns d in whole seconds, rounded up, with a minimum of
// 1 for a positive d.
func RetryAfterSeconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int((d + time.Second - 1) / time.Second)
}
