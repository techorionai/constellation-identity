// Package loginlimiter is the port of the login failure counters.
package loginlimiter

import "context"

// Limiter counts the failed logins of an email and of a client IP.
type Limiter interface {
	// Counts returns the failures of the email and of the IP in the current
	// window. An error means the counters are not available.
	Counts(ctx context.Context, email, ip string) (emailFailures, ipFailures int64, err error)
	// RecordFailure adds one failure to the counter of the email and to the
	// counter of the IP.
	RecordFailure(ctx context.Context, email, ip string) error
	// ResetEmail deletes the counter of the email.
	ResetEmail(ctx context.Context, email string) error
}
