package shim

import (
	"sync"
	"time"
)

type limiter struct {
	mu           sync.Mutex
	rate, tokens float64
	last         time.Time
}

func newLimiter(rate float64) *limiter { return &limiter{rate: rate, tokens: 5, last: time.Now()} }
func (l *limiter) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.After(l.last) {
		l.tokens = min(5, l.tokens+now.Sub(l.last).Seconds()*l.rate)
		l.last = now
	}
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}
