package argon2

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/passwordhasher"
)

var ctx = context.Background()

func newHasher(t *testing.T, max int, queue time.Duration) *Hasher {
	t.Helper()
	h, err := New(Config{MaxConcurrent: max, QueueTimeout: queue, MemoryKiB: 64, Time: 1})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// U1: the hasher uses the NFC form, so a decomposed string has the same length
// as the composed string.
func TestU1_Normalize(t *testing.T) {
	h := newHasher(t, 1, time.Second)
	decomposed := strings.Repeat("é", 6) // 12 code points, 6 after NFC
	n := h.Normalize(decomposed)
	if n != strings.Repeat("é", 6) {
		t.Fatalf("normalized = %q", n)
	}
	if err := domain.CheckPassword(n); !errors.Is(err, domain.ErrPasswordTooShort) {
		t.Fatalf("the policy must use the NFC form: %v", err)
	}
}

// U2: hash and verify.
func TestU2_HashVerify(t *testing.T) {
	h := newHasher(t, 1, time.Second)
	enc, err := h.Hash(ctx, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Fatalf("encoded = %q", enc)
	}
	ok, rehash, err := h.Verify(ctx, "correct horse battery", enc)
	if err != nil || !ok || rehash {
		t.Fatalf("right password: %v %v %v", ok, rehash, err)
	}
	ok, _, err = h.Verify(ctx, "wrong horse battery", enc)
	if err != nil || ok {
		t.Fatalf("wrong password: %v %v", ok, err)
	}
	other, _ := h.Hash(ctx, "correct horse battery")
	if other == enc {
		t.Fatal("two hashes of one password must differ (random salt)")
	}
	for _, bad := range []string{"", "plain", "$argon2id$v=19$m=1,t=1,p=1$AAAA$AAAA", "$argon2i$v=19$m=64,t=1,p=1$AAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA"} {
		if ok, _, err := h.Verify(ctx, "x", bad); ok || err != nil {
			t.Fatalf("a bad stored hash %q must not match: %v %v", bad, ok, err)
		}
	}
}

// U3: a hash with old parameters passes and asks for a new hash.
func TestU3_OldParameters(t *testing.T) {
	old := newHasher(t, 1, time.Second)
	enc, err := old.Hash(ctx, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	current, err := New(Config{MaxConcurrent: 1, QueueTimeout: time.Second, MemoryKiB: 128, Time: 2})
	if err != nil {
		t.Fatal(err)
	}
	ok, rehash, err := current.Verify(ctx, "correct horse battery", enc)
	if err != nil || !ok || !rehash {
		t.Fatalf("old hash: ok=%v rehash=%v err=%v", ok, rehash, err)
	}
}

// U4: with one slot, the second call waits.
func TestU4_SecondCallWaits(t *testing.T) {
	h := newHasher(t, 1, 2*time.Second)
	release, err := h.acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan time.Duration)
	start := time.Now()
	go func() {
		_, err := h.Hash(ctx, "correct horse battery")
		if err != nil {
			t.Error(err)
		}
		done <- time.Since(start)
	}()
	select {
	case <-done:
		t.Fatal("the second call must wait for the slot")
	case <-time.After(100 * time.Millisecond):
	}
	release()
	if elapsed := <-done; elapsed < 100*time.Millisecond {
		t.Fatalf("elapsed = %v", elapsed)
	}
}

// U4a: a call that waits longer than the queue timeout returns the busy error.
func TestU4a_QueueTimeout(t *testing.T) {
	h := newHasher(t, 1, 50*time.Millisecond)
	release, err := h.acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	time.AfterFunc(200*time.Millisecond, release)
	start := time.Now()
	_, err = h.Hash(ctx, "correct horse battery")
	elapsed := time.Since(start)
	if !errors.Is(err, passwordhasher.ErrBusy) {
		t.Fatalf("err = %v, want ErrBusy", err)
	}
	if elapsed < 40*time.Millisecond || elapsed > 150*time.Millisecond {
		t.Fatalf("elapsed = %v, want about 50 ms", elapsed)
	}
	// The slot is free again after the first call ends.
	time.Sleep(200 * time.Millisecond)
	if _, err := h.Hash(ctx, "correct horse battery"); err != nil {
		t.Fatal(err)
	}
}

func TestContextEndsTheWait(t *testing.T) {
	h := newHasher(t, 1, 5*time.Second)
	release, _ := h.acquire(ctx)
	defer release()
	c, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	if _, err := h.Hash(c, "x"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestNewChecksConfig(t *testing.T) {
	if _, err := New(Config{MaxConcurrent: 0, QueueTimeout: time.Second}); err == nil {
		t.Fatal("MaxConcurrent 0 must fail")
	}
	if _, err := New(Config{MaxConcurrent: 1}); err == nil {
		t.Fatal("no QueueTimeout must fail")
	}
}
