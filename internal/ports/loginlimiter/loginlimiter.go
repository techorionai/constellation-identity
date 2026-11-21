// Package loginlimiter is the port of the login attempt counters.
package loginlimiter

import "context"

// Limiter counts the login attempts of an email and of a client IP.
type Limiter interface {
	// Reserve adds one attempt to the counter of the email and to the counter
	// of the IP in one atomic step, and returns the new values. A counter
	// always has an expiry after this call. Parallel calls get different
	// values. An error means the counters are not available.
	Reserve(ctx context.Context, email, ip string) (emailAttempts, ipAttempts int64, err error)
	// RecordSuccess is for a good login. It deletes the counter of the email
	// and decreases the counter of the IP by 1, so that the IP counter counts
	// failures only. The IP counter never goes below 0, a missing counter stays
	// missing, and an existing counter keeps its expiry.
	RecordSuccess(ctx context.Context, email, ip string) error
}
