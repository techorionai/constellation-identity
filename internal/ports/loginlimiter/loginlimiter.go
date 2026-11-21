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
	// ResetEmail deletes the counter of the email.
	ResetEmail(ctx context.Context, email string) error
}
