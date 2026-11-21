//go:build integration

package valkey

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/techorionai/constellation-platform-go/resources/test/containers"
	valkeygo "github.com/valkey-io/valkey-go"
)

// The image is the same as ValkeyImage in resources/test/testserver. That
// package imports this one through the composition root, so a test here
// cannot import it.
const valkeyImage = "valkey/valkey:9.0.7-alpine"

type testKeys struct{}

func (testKeys) Key(parts ...string) string { return "identity:" + strings.Join(parts, ":") }

// limiterEnv starts Valkey and makes a client of an ACL user like the user of
// the service. The ACL denies scripts, so the test shows that the limiter works
// without one.
func limiterEnv(t *testing.T) valkeygo.Client {
	t.Helper()
	vk := containers.Valkey(t, containers.WithValkeyImage(valkeyImage))
	user, password := vk.NewACLUser(t, "identity")
	c, err := valkeygo.NewClient(valkeygo.ClientOption{
		InitAddress: []string{vk.Address()}, Username: user, Password: string(password), DisableCache: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func ttlMillis(t *testing.T, c valkeygo.Client, key string) int64 {
	t.Helper()
	n, err := c.Do(context.Background(), c.B().Pttl().Key(key).Build()).AsInt64()
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// R6: parallel reservations get different values, so the limit cannot be passed
// by a burst of requests.
func TestR6_ParallelReserveGivesDistinctValues(t *testing.T) {
	c := limiterEnv(t)
	l := NewLoginLimiter(c, testKeys{}, time.Minute)
	const n = 60
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		emails = map[int64]int{}
		ips    = map[int64]int{}
		errs   []error
	)
	for range n {
		wg.Go(func() {
			e, i, err := l.Reserve(context.Background(), "a@example.com", "1.2.3.4")
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			emails[e]++
			ips[i]++
		})
	}
	wg.Wait()
	if len(errs) != 0 {
		t.Fatalf("errors: %v", errs)
	}
	for v := int64(1); v <= n; v++ {
		if emails[v] != 1 || ips[v] != 1 {
			t.Fatalf("value %d: email count %d, ip count %d, want 1 and 1", v, emails[v], ips[v])
		}
	}
}

// R10: a counter that has no TTL gets one at the next reservation.
func TestR10_CounterWithoutTTLGetsOne(t *testing.T) {
	c := limiterEnv(t)
	l := NewLoginLimiter(c, testKeys{}, time.Minute)
	ctx := context.Background()
	if _, _, err := l.Reserve(ctx, "a@example.com", "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	key := l.emailKey("a@example.com")
	if err := c.Do(ctx, c.B().Persist().Key(key).Build()).Error(); err != nil {
		t.Fatal(err)
	}
	if got := ttlMillis(t, c, key); got != -1 {
		t.Fatalf("TTL after PERSIST = %d, want -1", got)
	}
	if _, _, err := l.Reserve(ctx, "a@example.com", "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if got := ttlMillis(t, c, key); got <= 0 || got > 60_000 {
		t.Fatalf("TTL after Reserve = %d ms, want 1 to 60000", got)
	}
}

// R10: after each reservation both counters have a TTL.
func TestR10_BothCountersHaveATTL(t *testing.T) {
	c := limiterEnv(t)
	l := NewLoginLimiter(c, testKeys{}, time.Minute)
	if _, _, err := l.Reserve(context.Background(), "a@example.com", "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{l.emailKey("a@example.com"), l.ipKey("1.2.3.4")} {
		if got := ttlMillis(t, c, key); got <= 0 {
			t.Fatalf("TTL of %s = %d, want more than 0", key, got)
		}
	}
}

// R11: the window ends at the first attempt plus the window. A later attempt
// does not move it. After the window the counter starts again.
func TestR11_WindowExpiresAndIsNotExtended(t *testing.T) {
	c := limiterEnv(t)
	l := NewLoginLimiter(c, testKeys{}, 2*time.Second)
	ctx := context.Background()
	key := l.emailKey("a@example.com")
	start := time.Now()
	for range 2 {
		if _, _, err := l.Reserve(ctx, "a@example.com", "1.2.3.4"); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(1100 * time.Millisecond)
	e, _, err := l.Reserve(ctx, "a@example.com", "1.2.3.4")
	if err != nil || e != 3 {
		t.Fatalf("third reserve = %d, %v, want 3", e, err)
	}
	// About 0.9 s remain. An extended window would show about 2 s.
	if got := ttlMillis(t, c, key); got <= 0 || got > 1500 {
		t.Fatalf("TTL after the later attempt = %d ms, want 1 to 1500 (not extended)", got)
	}
	for ttlMillis(t, c, key) > 0 {
		if time.Since(start) > 6*time.Second {
			t.Fatal("the counter did not expire")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got := ttlMillis(t, c, key); got != -2 {
		t.Fatalf("TTL after the window = %d, want -2 (no key)", got)
	}
	e, _, err = l.Reserve(ctx, "a@example.com", "1.2.3.4")
	if err != nil || e != 1 {
		t.Fatalf("reserve after the window = %d, %v, want 1", e, err)
	}
}

// ResetEmail deletes the email counter and keeps the IP counter.
func TestResetEmail(t *testing.T) {
	c := limiterEnv(t)
	l := NewLoginLimiter(c, testKeys{}, time.Minute)
	ctx := context.Background()
	for range 3 {
		if _, _, err := l.Reserve(ctx, "a@example.com", "1.2.3.4"); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.ResetEmail(ctx, "a@example.com"); err != nil {
		t.Fatal(err)
	}
	e, i, err := l.Reserve(ctx, "a@example.com", "1.2.3.4")
	if err != nil || e != 1 || i != 4 {
		t.Fatalf("after reset: email %d, ip %d, %v, want 1 and 4", e, i, err)
	}
}
