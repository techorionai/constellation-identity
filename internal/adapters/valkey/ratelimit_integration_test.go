//go:build integration

package valkey

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/techorionai/constellation-platform-go/resources/test/containers"
	valkeygo "github.com/valkey-io/valkey-go"

	"github.com/techorionai/constellation-identity/internal/ports/ratelimit"
)

// I1: parallel calls get different counts, so the limit holds.
func TestI1_RateLimitParallel(t *testing.T) {
	c := limiterEnv(t)
	l := NewRateLimiter(c, testKeys{})
	rule := ratelimit.Rule{Name: "token_ip", Limit: 10, Window: time.Minute}
	const n = 20
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		counts  = map[int64]int{}
		allowed int
		errs    []error
	)
	for range n {
		wg.Go(func() {
			d, err := l.Allow(context.Background(), rule, "1.2.3.4")
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			counts[d.Count]++
			if d.Allowed {
				allowed++
			}
		})
	}
	wg.Wait()
	if len(errs) != 0 {
		t.Fatalf("errors: %v", errs)
	}
	for v := int64(1); v <= n; v++ {
		if counts[v] != 1 {
			t.Fatalf("count %d occurred %d times, want 1", v, counts[v])
		}
	}
	if allowed != 10 {
		t.Fatalf("allowed = %d, want 10", allowed)
	}
}

// I2: the key has a TTL after the first call. More calls do not make the
// window longer.
func TestI2_RateLimitTTL(t *testing.T) {
	c := limiterEnv(t)
	l := NewRateLimiter(c, testKeys{})
	rule := ratelimit.Rule{Name: "token_ip", Limit: 100, Window: 10 * time.Second}
	ctx := context.Background()
	if _, err := l.Allow(ctx, rule, "k"); err != nil {
		t.Fatal(err)
	}
	key := "identity:rl:token_ip:" + digest("k")
	first := ttlMillis(t, c, key)
	if first <= 0 || first > 10_000 {
		t.Fatalf("TTL = %d ms, want 1 to 10000", first)
	}
	time.Sleep(50 * time.Millisecond)
	for range 3 {
		if _, err := l.Allow(ctx, rule, "k"); err != nil {
			t.Fatal(err)
		}
	}
	if second := ttlMillis(t, c, key); second <= 0 || second >= first {
		t.Fatalf("TTL after more calls = %d ms, first = %d ms, want less", second, first)
	}
}

// I3: the wait time of a denied call.
func TestI3_RateLimitRetryAfter(t *testing.T) {
	c := limiterEnv(t)
	l := NewRateLimiter(c, testKeys{})
	rule := ratelimit.Rule{Name: "setup_invite", Limit: 1, Window: 10 * time.Second}
	ctx := context.Background()
	d, err := l.Allow(ctx, rule, "k")
	if err != nil || !d.Allowed || d.RetryAfter != 0 {
		t.Fatalf("first: %+v, %v", d, err)
	}
	d, err = l.Allow(ctx, rule, "k")
	if err != nil || d.Allowed {
		t.Fatalf("second: %+v, %v", d, err)
	}
	if d.RetryAfter < time.Second || d.RetryAfter > 10*time.Second || d.RetryAfter%time.Second != 0 {
		t.Fatalf("RetryAfter = %s, want whole seconds from 1 to 10", d.RetryAfter)
	}
}

// I4: the key has the hash of the input and not the input.
func TestI4_RateLimitKeyName(t *testing.T) {
	vk := containers.Valkey(t, containers.WithValkeyImage(valkeyImage))
	user, password := vk.NewACLUser(t, "identity")
	c, err := valkeygo.NewClient(valkeygo.ClientOption{
		InitAddress: []string{vk.Address()}, Username: user, Password: string(password), DisableCache: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	l := NewRateLimiter(c, testKeys{})
	rule := ratelimit.Rule{Name: "api_token_create", Limit: 5, Window: time.Minute}
	ctx := context.Background()
	const input = "user-with-a-recognizable-id"
	if _, err := l.Allow(ctx, rule, input); err != nil {
		t.Fatal(err)
	}
	admin := vk.Admin(t)
	keys, err := admin.Do(ctx, admin.B().Keys().Pattern("*").Build()).AsStrSlice()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || !regexp.MustCompile(`^identity:rl:api_token_create:[0-9a-f]{64}$`).MatchString(keys[0]) || strings.Contains(keys[0], input) {
		t.Fatalf("keys = %v", keys)
	}
}

// deployACL is the ACL rule of constellation-deploy/provision/valkey.sh.
const deployACL = "reset on >pw ~identity:* +@all -@admin -@dangerous -@scripting -function -scan -randomkey -dbsize -memory"

// I5: the adapter works with the ACL of the deploy, which denies scripts.
func TestI5_RateLimitWithDeployACL(t *testing.T) {
	vk := containers.Valkey(t, containers.WithValkeyImage(valkeyImage))
	admin := vk.Admin(t)
	args := append([]string{"identity5"}, strings.Fields(deployACL)...)
	if err := admin.Do(context.Background(), admin.B().Arbitrary("ACL", "SETUSER").Args(args...).Build()).Error(); err != nil {
		t.Fatal(err)
	}
	c, err := valkeygo.NewClient(valkeygo.ClientOption{
		InitAddress: []string{vk.Address()}, Username: "identity5", Password: "pw", DisableCache: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	if err := c.Do(context.Background(), c.B().Eval().Script("return 1").Numkeys(0).Build()).Error(); err == nil {
		t.Fatal("the deploy ACL must deny scripts")
	}
	l := NewRateLimiter(c, testKeys{})
	for i := range 3 {
		d, err := l.Allow(context.Background(), ratelimit.Rule{Name: "token_ip", Limit: 2, Window: time.Minute}, "k")
		if err != nil {
			t.Fatalf("call %d: %v", i+1, err)
		}
		if d.Allowed != (i < 2) {
			t.Fatalf("call %d: allowed = %v", i+1, d.Allowed)
		}
	}
}
