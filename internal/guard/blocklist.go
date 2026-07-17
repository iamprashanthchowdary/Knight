// Package guard holds Knight's enforcement primitives: the IP blocklist and the
// per-IP rate limiter. These are the "become very defensive" side of the design
// -- once the engine or the observer decides an IP is hostile, it lands here and
// every later request from that IP is refused on the fast path.
package guard

import (
	"sort"
	"sync"
	"time"
)

// Entry is a single active ban.
type Entry struct {
	IP      string    `json:"ip"`
	Reason  string    `json:"reason"`
	Expires time.Time `json:"expires"`
}

// Blocklist is an in-memory, TTL-based IP ban store, safe for concurrent use.
type Blocklist struct {
	mu      sync.RWMutex
	entries map[string]Entry
	hook    *BanHook // optional; mirrors bans into the kernel firewall
}

// SetHook attaches a BanHook. Call before traffic starts.
func (b *Blocklist) SetHook(h *BanHook) { b.hook = h }

// NewBlocklist returns an empty blocklist and starts a background janitor that
// evicts expired entries.
func NewBlocklist() *Blocklist {
	b := &Blocklist{entries: map[string]Entry{}}
	go b.janitor()
	return b
}

// Block bans ip for d with a human-readable reason. A longer existing ban is
// preserved rather than shortened.
func (b *Blocklist) Block(ip, reason string, d time.Duration) {
	if ip == "" || d <= 0 {
		return
	}
	exp := time.Now().Add(d)
	b.mu.Lock()
	cur, existed := b.entries[ip]
	if existed && cur.Expires.After(exp) {
		b.mu.Unlock()
		return
	}
	b.entries[ip] = Entry{IP: ip, Reason: reason, Expires: exp}
	b.mu.Unlock()
	if !existed && b.hook != nil {
		b.hook.OnBlock(ip)
	}
}

// Blocked reports whether ip is currently banned.
func (b *Blocklist) Blocked(ip string) bool {
	b.mu.RLock()
	e, ok := b.entries[ip]
	b.mu.RUnlock()
	return ok && time.Now().Before(e.Expires)
}

// Unblock removes a ban immediately.
func (b *Blocklist) Unblock(ip string) {
	b.mu.Lock()
	_, existed := b.entries[ip]
	delete(b.entries, ip)
	b.mu.Unlock()
	if existed && b.hook != nil {
		b.hook.OnUnblock(ip)
	}
}

// List returns the currently active bans, soonest-to-expire first.
func (b *Blocklist) List() []Entry {
	now := time.Now()
	b.mu.RLock()
	out := make([]Entry, 0, len(b.entries))
	for _, e := range b.entries {
		if now.Before(e.Expires) {
			out = append(out, e)
		}
	}
	b.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Expires.Before(out[j].Expires) })
	return out
}

func (b *Blocklist) janitor() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		var expired []string
		b.mu.Lock()
		for ip, e := range b.entries {
			if now.After(e.Expires) {
				delete(b.entries, ip)
				expired = append(expired, ip)
			}
		}
		b.mu.Unlock()
		if b.hook != nil {
			for _, ip := range expired {
				b.hook.OnUnblock(ip) // lift the kernel drop too
			}
		}
	}
}
