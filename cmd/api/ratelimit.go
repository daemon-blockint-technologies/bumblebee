package main

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// rateLimiter is a simple in-memory token-bucket rate limiter
// keyed by client IP. Each client gets maxRequests per window.
type rateLimiter struct {
	mu        sync.Mutex
	clients   map[string]*clientBucket
	maxPerWin int
	window    time.Duration
}

type clientBucket struct {
	tokens    int
	lastReset time.Time
}

func newRateLimiter(maxPerWin int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		clients:   make(map[string]*clientBucket),
		maxPerWin: maxPerWin,
		window:    window,
	}
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.clients[key]
	if !ok || now.Sub(b.lastReset) >= rl.window {
		b = &clientBucket{tokens: rl.maxPerWin, lastReset: now}
		rl.clients[key] = b
	}

	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

// cleanup removes stale entries older than 2x window.
func (rl *rateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-2 * rl.window)
	for k, b := range rl.clients {
		if b.lastReset.Before(cutoff) {
			delete(rl.clients, k)
		}
	}
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	host := r.RemoteAddr
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}
	return host
}

func rateLimitMiddleware(rl *rateLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if rl == nil {
			next(w, r)
			return
		}
		ip := clientIP(r)
		if !rl.allow(ip) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, `{"error":"rate_limit_exceeded","message":"too many requests"}`, http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}
