package httpapi

import (
	"testing"
	"time"
)

func TestFallbackLimiter(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newFallbackLimiter(2, time.Minute, 2)
	l.now = func() time.Time { return now }
	for i := 0; i < 2; i++ {
		if !l.allow("a") {
			t.Fatalf("call %d must pass", i+1)
		}
	}
	if l.allow("a") {
		t.Fatal("the third call must not pass")
	}
	if !l.allow("b") {
		t.Fatal("a second key must pass")
	}
	if l.allow("c") {
		t.Fatal("a new key must not pass when the table is full")
	}
	now = now.Add(time.Minute)
	if !l.allow("c") || !l.allow("a") {
		t.Fatal("the keys must pass after the window")
	}
	if len(l.keys) > 2 {
		t.Fatalf("keys = %d", len(l.keys))
	}
}
