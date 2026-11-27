package httpapi

import (
	"sync"
	"time"
)

// The limits of the in-process fallback of the denied step. The fallback runs
// only while the shared limiter does not answer.
const (
	deniedFallbackLimit  = 10
	deniedFallbackWindow = time.Minute
	deniedFallbackKeys   = 10000
)

// fallbackLimiter is a small fixed-window limiter in the memory of one
// process. It keeps at most maxKeys keys. If the table is full of live keys,
// a new key is not allowed.
type fallbackLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	maxKeys int
	now     func() time.Time
	keys    map[string]fallbackWindow
}

type fallbackWindow struct {
	start time.Time
	count int
}

func newFallbackLimiter(limit int, window time.Duration, maxKeys int) *fallbackLimiter {
	return &fallbackLimiter{limit: limit, window: window, maxKeys: maxKeys, now: time.Now, keys: map[string]fallbackWindow{}}
}

// allow counts one entry for key. It returns false when the entry is over the
// limit.
func (l *fallbackLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	w, ok := l.keys[key]
	if ok && now.Sub(w.start) < l.window {
		if w.count >= l.limit {
			return false
		}
		w.count++
		l.keys[key] = w
		return true
	}
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
	l.keys[key] = fallbackWindow{start: now, count: 1}
	return true
}
