// Package valkey holds the Valkey adapters of the identity service.
package valkey

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	valkeygo "github.com/valkey-io/valkey-go"

	"github.com/techorionai/constellation-identity/internal/ports/loginlimiter"
)

// callTimeout is the longest time of one limiter call. The Valkey client retries
// a read after a connection error until the context ends, so without a limit a
// stopped server would block the login for a long time. A timeout is an error,
// and the login fails closed.
const callTimeout = 2 * time.Second

// KeyMaker makes a key with the key prefix of the service.
type KeyMaker interface {
	Key(parts ...string) string
}

// LoginLimiter is the adapter of the port loginlimiter. The counters are
// plain Valkey keys. No script is necessary.
type LoginLimiter struct {
	client valkeygo.Client
	keys   KeyMaker
	window time.Duration
}

var _ loginlimiter.Limiter = (*LoginLimiter)(nil)

// NewLoginLimiter makes the limiter. window is the life of a counter. It is
// set at the first failure of the window.
func NewLoginLimiter(client valkeygo.Client, keys KeyMaker, window time.Duration) *LoginLimiter {
	return &LoginLimiter{client: client, keys: keys, window: window}
}

func (l *LoginLimiter) emailKey(email string) string {
	return l.keys.Key("login", "fail", "email", digest(email))
}

func (l *LoginLimiter) ipKey(ip string) string {
	return l.keys.Key("login", "fail", "ip", digest(ip))
}

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Counts returns the failures of the email and of the IP.
func (l *LoginLimiter) Counts(ctx context.Context, email, ip string) (int64, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	res := l.client.DoMulti(ctx,
		l.client.B().Get().Key(l.emailKey(email)).Build(),
		l.client.B().Get().Key(l.ipKey(ip)).Build())
	var out [2]int64
	for i, r := range res {
		n, err := r.AsInt64()
		switch {
		case err == nil:
			out[i] = n
		case valkeygo.IsValkeyNil(err):
			out[i] = 0
		default:
			return 0, 0, fmt.Errorf("read login counters: %w", err)
		}
	}
	return out[0], out[1], nil
}

// RecordFailure adds one failure to each counter. EXPIRE with NX sets the life
// at the first failure of the window only.
func (l *LoginLimiter) RecordFailure(ctx context.Context, email, ip string) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	seconds := max(int64(l.window/time.Second), 1)
	ek, ik := l.emailKey(email), l.ipKey(ip)
	res := l.client.DoMulti(ctx,
		l.client.B().Incr().Key(ek).Build(),
		l.client.B().Expire().Key(ek).Seconds(seconds).Nx().Build(),
		l.client.B().Incr().Key(ik).Build(),
		l.client.B().Expire().Key(ik).Seconds(seconds).Nx().Build())
	var errs []error
	for _, r := range res {
		if err := r.Error(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("record login failure: %w", err)
	}
	return nil
}

// ResetEmail deletes the counter of the email.
func (l *LoginLimiter) ResetEmail(ctx context.Context, email string) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	if err := l.client.Do(ctx, l.client.B().Del().Key(l.emailKey(email)).Build()).Error(); err != nil {
		return fmt.Errorf("reset login counter: %w", err)
	}
	return nil
}
