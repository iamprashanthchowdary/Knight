// Package server exposes Knight's decision API. Its most important endpoint is
// /inspect, designed to be called by nginx's auth_request directive: for every
// incoming request nginx asks Knight "allow or block?" and Knight answers with
// an HTTP status. If Knight is unreachable, nginx is configured to fail OPEN,
// so a Knight crash never takes the site down -- the hybrid guarantee the design
// calls for.
package server

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"knight/internal/config"
	"knight/internal/engine"
	"knight/internal/guard"
	"knight/internal/request"
)

// Server wires the engine and enforcement primitives to the HTTP API.
type Server struct {
	cfg *config.Config
	eng *engine.Engine
	bl  *guard.Blocklist
	rl  *guard.RateLimiter
	log *slog.Logger

	// counters (atomic) for /metrics
	total   atomic.Uint64
	blocked atomic.Uint64
	flagged atomic.Uint64 // would-block in observe mode
}

// New constructs a Server.
func New(cfg *config.Config, eng *engine.Engine, bl *guard.Blocklist, rl *guard.RateLimiter, log *slog.Logger) *Server {
	return &Server{cfg: cfg, eng: eng, bl: bl, rl: rl, log: log}
}

// Handler returns the configured HTTP mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/inspect", s.handleInspect)
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/blocklist", s.handleBlocklist)
	return mux
}

// handleInspect is the nginx auth_request target.
//
// nginx forwards the original request's metadata via headers (see the deploy
// example). We answer 204 to allow and 403 to block. In observe mode we always
// allow but still record and log what we would have done.
func (s *Server) handleInspect(w http.ResponseWriter, r *http.Request) {
	s.total.Add(1)

	ip := clientIP(r)

	// Fast path: already-banned IPs never reach the engine.
	if s.bl.Blocked(ip) {
		s.deny(w, ip, "ip-banned", 0)
		return
	}

	// Volumetric abuse -> ban, then deny.
	if !s.rl.Allow(ip) {
		s.bl.Block(ip, "rate-limit exceeded", s.cfg.BanDuration())
		s.deny(w, ip, "rate-limit", 0)
		return
	}

	ctx := request.New(
		ip,
		hdr(r, "X-Original-Method"),
		hdr(r, "X-Original-URI"),
		hdr(r, "X-Original-UA", "User-Agent"),
		hdr(r, "X-Original-Referer", "Referer"),
		hdr(r, "X-Original-Cookie"),
		"", // body not available via auth_request; inspected out-of-band
	)

	v := s.eng.Evaluate(ctx)
	if !v.Block {
		s.allow(w)
		return
	}

	// A blocking verdict.
	ruleIDs := matchIDs(v.Matches)
	if s.cfg.Mode == config.ModeObserve {
		s.flagged.Add(1)
		s.log.Warn("would block (observe mode)",
			"ip", ip, "uri", ctx.Target("uri"), "score", v.Score, "rules", ruleIDs)
		s.allow(w)
		return
	}

	s.bl.Block(ip, "waf: "+strings.Join(ruleIDs, ","), s.cfg.BanDuration())
	s.deny(w, ip, "waf-match", v.Score)
	s.log.Warn("blocked",
		"ip", ip, "uri", ctx.Target("uri"), "score", v.Score, "rules", ruleIDs)
}

func (s *Server) allow(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent) // 204 -> nginx allows
}

func (s *Server) deny(w http.ResponseWriter, ip, reason string, score int) {
	s.blocked.Add(1)
	w.Header().Set("X-Knight-Block", reason)
	w.WriteHeader(http.StatusForbidden) // 403 -> nginx blocks
	_ = score
	_ = ip
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "ok",
		"mode":   s.cfg.Mode,
		"rules":  s.eng.RuleCount(),
		"time":   time.Now().UTC(),
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"requests_total": s.total.Load(),
		"blocked_total":  s.blocked.Load(),
		"flagged_total":  s.flagged.Load(),
		"active_bans":    len(s.bl.List()),
		"mode":           s.cfg.Mode,
	})
}

func (s *Server) handleBlocklist(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.bl.List())
}

func matchIDs(ms []engine.Match) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.RuleID)
	}
	return out
}

// hdr returns the first non-empty value among the given header names.
func hdr(r *http.Request, names ...string) string {
	for _, n := range names {
		if v := r.Header.Get(n); v != "" {
			return v
		}
	}
	return ""
}

// clientIP resolves the real client address, trusting the headers nginx sets.
func clientIP(r *http.Request) string {
	if v := r.Header.Get("X-Real-IP"); v != "" {
		return strings.TrimSpace(v)
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		// Left-most entry is the original client.
		if i := strings.IndexByte(v, ','); i >= 0 {
			return strings.TrimSpace(v[:i])
		}
		return strings.TrimSpace(v)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
