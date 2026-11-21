// Package valkey holds the Valkey adapters of the identity service.
package valkey

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
// plain Valkey keys.
type LoginLimiter struct {
	client valkeygo.Client
	keys   KeyMaker
	window time.Duration
}

var _ loginlimiter.Limiter = (*LoginLimiter)(nil)

// NewLoginLimiter makes the limiter. window is the life of a counter. It is
// set at the first attempt of the window.
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

// Reserve adds one attempt to each counter in one MULTI/EXEC transaction.
// EXPIRE with NX sets the life at the first attempt of the window only, and it
// runs in the same transaction as INCR. Thus a counter never exists without an
// expiry, and parallel calls get different values. The server ACL denies
// scripts, so the adapter does not use one.
func (l *LoginLimiter) Reserve(ctx context.Context, email, ip string) (int64, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	seconds := max(int64(l.window/time.Second), 1)
	ek, ik := l.emailKey(email), l.ipKey(ip)
	res := l.client.DoMulti(ctx,
		l.client.B().Multi().Build(),
		l.client.B().Incr().Key(ek).Build(),
		l.client.B().Expire().Key(ek).Seconds(seconds).Nx().Build(),
		l.client.B().Incr().Key(ik).Build(),
		l.client.B().Expire().Key(ik).Seconds(seconds).Nx().Build(),
		l.client.B().Exec().Build())
	for _, r := range res {
		if err := r.Error(); err != nil {
			return 0, 0, fmt.Errorf("reserve login attempt: %w", err)
		}
	}
	replies, err := res[len(res)-1].ToArray()
	if err != nil {
		return 0, 0, fmt.Errorf("reserve login attempt: %w", err)
	}
	if len(replies) != 4 {
		return 0, 0, fmt.Errorf("reserve login attempt: %d replies, want 4", len(replies))
	}
	emailN, err := replies[0].AsInt64()
	if err != nil {
		return 0, 0, fmt.Errorf("reserve login attempt: %w", err)
	}
	ipN, err := replies[2].AsInt64()
	if err != nil {
		return 0, 0, fmt.Errorf("reserve login attempt: %w", err)
	}
	return emailN, ipN, nil
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
