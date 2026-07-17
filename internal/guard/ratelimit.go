package guard

import (
	"sync"
	"time"
)

// RateLimiter is a per-IP token bucket. Each IP refills at Rate tokens/second up
// to Burst tokens; a request costs one token. It catches volumetric abuse
// (scanners, brute force, scraping) that no single-request signature would.
type RateLimiter struct {
	rate  float64 // tokens per second
	burst float64

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewRateLimiter returns a limiter allowing rate requests/sec with the given
// burst. A background janitor drops idle buckets so memory stays bounded.
func NewRateLimiter(rate, burst float64) *RateLimiter {
	if burst < 1 {
		burst = 1
	}
	r := &RateLimiter{rate: rate, burst: burst, buckets: map[string]*bucket{}}
	go r.janitor()
	return r
}

// Allow consumes a token for ip and reports whether the request is within the
// limit. A rate of 0 disables limiting.
func (r *RateLimiter) Allow(ip string) bool {
	if r.rate <= 0 {
		return true
	}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()

	b := r.buckets[ip]
	if b == nil {
		b = &bucket{tokens: r.burst, last: now}
		r.buckets[ip] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	b.last = now
	b.tokens += elapsed * r.rate
	if b.tokens > r.burst {
		b.tokens = r.burst
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

func (r *RateLimiter) janitor() {
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().Add(-5 * time.Minute)
		r.mu.Lock()
		for ip, b := range r.buckets {
			// Idle and fully refilled -> nothing to remember.
			if b.last.Before(cutoff) && b.tokens >= r.burst {
				delete(r.buckets, ip)
			}
		}
		r.mu.Unlock()
	}
}
