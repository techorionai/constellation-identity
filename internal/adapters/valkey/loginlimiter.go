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

func (l *LoginLimiter) coarseKey(key string) string {
	return l.keys.Key("login", "fail", "ipc", digest(key))
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

// ReserveCoarse adds one attempt to the coarse counter in one MULTI/EXEC
// transaction. EXPIRE with NX sets the life at the first attempt of the window.
func (l *LoginLimiter) ReserveCoarse(ctx context.Context, key string) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	seconds := max(int64(l.window/time.Second), 1)
	k := l.coarseKey(key)
	res := l.client.DoMulti(ctx,
		l.client.B().Multi().Build(),
		l.client.B().Incr().Key(k).Build(),
		l.client.B().Expire().Key(k).Seconds(seconds).Nx().Build(),
		l.client.B().Exec().Build())
	for _, r := range res {
		if err := r.Error(); err != nil {
			return 0, fmt.Errorf("reserve coarse login attempt: %w", err)
		}
	}
	replies, err := res[len(res)-1].ToArray()
	if err != nil {
		return 0, fmt.Errorf("reserve coarse login attempt: %w", err)
	}
	if len(replies) != 2 {
		return 0, fmt.Errorf("reserve coarse login attempt: %d replies, want 2", len(replies))
	}
	n, err := replies[0].AsInt64()
	if err != nil {
		return 0, fmt.Errorf("reserve coarse login attempt: %w", err)
	}
	return n, nil
}

// successTries is the number of tries of RecordSuccess when WATCH shows a
// change of the IP counter.
const successTries = 64

// RecordSuccess deletes the counter of the email and decreases the counter of
// the IP by 1. It uses WATCH, so the decrease runs only if the IP counter
// exists and is more than 0, and it never creates a key. DECR keeps the expiry
// of the key. The server ACL denies scripts, so the adapter does not use one.
func (l *LoginLimiter) RecordSuccess(ctx context.Context, email, ip string) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	ek, ik := l.emailKey(email), l.ipKey(ip)
	err := l.client.Dedicated(func(c valkeygo.DedicatedClient) error {
		for range successTries {
			if err := c.Do(ctx, c.B().Watch().Key(ik).Build()).Error(); err != nil {
				return err
			}
			n, err := c.Do(ctx, c.B().Get().Key(ik).Build()).AsInt64()
			if err != nil && !valkeygo.IsValkeyNil(err) {
				c.Do(ctx, c.B().Unwatch().Build())
				return err
			}
			cmds := valkeygo.Commands{c.B().Multi().Build(), c.B().Del().Key(ek).Build()}
			if err == nil && n > 0 {
				cmds = append(cmds, c.B().Decr().Key(ik).Build())
			}
			cmds = append(cmds, c.B().Exec().Build())
			res := c.DoMulti(ctx, cmds...)
			for _, r := range res[:len(res)-1] {
				if err := r.Error(); err != nil {
					return err
				}
			}
			exec := res[len(res)-1]
			if valkeygo.IsValkeyNil(exec.Error()) {
				continue // WATCH showed a change, so try again
			}
			return exec.Error()
		}
		return fmt.Errorf("the IP counter changed %d times", successTries)
	})
	if err != nil {
		return fmt.Errorf("record login success: %w", err)
	}
	return nil
}

// Unlock deletes the counter of the email. It returns true if the counter
// existed.
func (l *LoginLimiter) Unlock(ctx context.Context, email string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	n, err := l.client.Do(ctx, l.client.B().Del().Key(l.emailKey(email)).Build()).AsInt64()
	if err != nil {
		return false, fmt.Errorf("unlock login: %w", err)
	}
	return n > 0, nil
}
