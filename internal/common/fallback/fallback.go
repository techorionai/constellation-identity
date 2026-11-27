// Package fallback has a small fixed-window limiter in the memory of one
// process. A gate uses it while the shared limiter does not answer.
package fallback

import (
	"sync"
	"time"
)

// Total is a limit on all keys together.
type Total struct {
	Limit  int
	Window time.Duration
}

// Option changes a Limiter.
type Option func(*Limiter)

// WithTotal adds a limit on all keys together. A limiter can have many.
func WithTotal(limit int, window time.Duration) Option {
	return func(l *Limiter) {
		l.totals = append(l.totals, &totalWindow{Total: Total{Limit: limit, Window: window}})
	}
}

// WithClock sets the clock. It is for tests.
func WithClock(now func() time.Time) Option {
	return func(l *Limiter) { l.now = now }
}

// Limiter keeps at most maxKeys keys. If the table is full of live keys, a new
// key is not allowed.
type Limiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	maxKeys int
	now     func() time.Time
	keys    map[string]window
	totals  []*totalWindow
}

type window struct {
	start time.Time
	count int
}

type totalWindow struct {
	Total
	w window
}

// New makes a limiter. Each key has limit entries in each window.
func New(limit int, win time.Duration, maxKeys int, opts ...Option) *Limiter {
	l := &Limiter{limit: limit, window: win, maxKeys: maxKeys, now: time.Now, keys: map[string]window{}}
	for _, o := range opts {
		o(l)
	}
	return l
}

// Allow counts one entry for key. It returns false when the entry is over a
// limit. A refused entry does not count.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for _, t := range l.totals {
		if now.Sub(t.w.start) >= t.Window {
			t.w = window{start: now}
		}
		if t.w.count >= t.Limit {
			return false
		}
	}
	w, ok := l.keys[key]
	switch {
	case ok && now.Sub(w.start) < l.window:
		if w.count >= l.limit {
			return false
		}
		w.count++
	default:
		if !ok && len(l.keys) >= l.maxKeys {
			for k, v := range l.keys {
				if now.Sub(v.start) >= l.window {
					delete(l.keys, k)
				}
			}
			if len(l.keys) >= l.maxKeys {
				return false
			}
		}
		w = window{start: now, count: 1}
	}
	l.keys[key] = w
	for _, t := range l.totals {
		t.w.count++
	}
	return true
}

// Keys returns the number of keys in the table.
func (l *Limiter) Keys() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.keys)
}
