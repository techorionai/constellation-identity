package fallback_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/common/fallback"
)

func TestFallbackLimiter(t *testing.T) {
	now := time.Unix(1000, 0)
	l := fallback.New(2, time.Minute, 2, fallback.WithClock(func() time.Time { return now }))
	for i := 0; i < 2; i++ {
		if !l.Allow("a") {
			t.Fatalf("call %d must pass", i+1)
		}
	}
	if l.Allow("a") {
		t.Fatal("the third call must not pass")
	}
	if !l.Allow("b") {
		t.Fatal("a second key must pass")
	}
	if l.Allow("c") {
		t.Fatal("a new key must not pass when the table is full")
	}
	now = now.Add(time.Minute)
	if !l.Allow("c") || !l.Allow("a") {
		t.Fatal("the keys must pass after the window")
	}
	if l.Keys() > 2 {
		t.Fatalf("keys = %d", l.Keys())
	}
}

// U4: the total limit holds over many keys.
func TestU4_TotalLimit(t *testing.T) {
	now := time.Unix(1000, 0)
	l := fallback.New(2, time.Minute, 100, fallback.WithTotal(3, time.Minute), fallback.WithClock(func() time.Time { return now }))
	allowed, refused := 0, 0
	for _, k := range []string{"a", "b", "c"} {
		for range 2 {
			if l.Allow(k) {
				allowed++
			} else {
				refused++
			}
		}
	}
	if allowed != 3 || refused != 3 {
		t.Fatalf("allowed = %d, refused = %d, want 3 and 3", allowed, refused)
	}
}

// U5: a full table refuses a new key.
func TestU5_FullTable(t *testing.T) {
	l := fallback.New(1, time.Minute, 10000)
	for i := range 10000 {
		if !l.Allow(fmt.Sprintf("k%d", i)) {
			t.Fatalf("key %d must pass", i)
		}
	}
	if l.Allow("new") {
		t.Fatal("a new key must not pass when the table is full")
	}
}

// U12: two total limits with a fake clock.
func TestU12_TwoTotals(t *testing.T) {
	now := time.Unix(1000, 0)
	l := fallback.New(10, time.Hour, 1000, fallback.WithTotal(100, time.Minute), fallback.WithTotal(150, 24*time.Hour),
		fallback.WithClock(func() time.Time { return now }))
	allowed, refused := 0, 0
	run := func(prefix string) {
		for i := range 100 {
			if l.Allow(fmt.Sprintf("%s%d", prefix, i)) {
				allowed++
			} else {
				refused++
			}
		}
	}
	run("a")
	now = now.Add(time.Minute)
	run("b")
	if allowed != 150 || refused != 50 {
		t.Fatalf("allowed = %d, refused = %d, want 150 and 50", allowed, refused)
	}
}
