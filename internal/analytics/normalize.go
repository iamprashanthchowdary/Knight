package analytics

import (
	"regexp"
	"strings"
)

// Normalizer collapses concrete request paths into stable endpoint templates so
// that /api/users/12345 and /api/users/98 both count as ONE endpoint,
// /api/users/{id}. Without this, every dynamic id/uuid/api-key explodes into a
// distinct path and the dashboard drowns.
//
// Two layers, config wins:
//  1. Config route patterns (exact, e.g. "/api/users/:id/orders/:orderId").
//     The first pattern whose shape matches is used.
//  2. Heuristic fallback (no config needed): each path segment that "looks
//     dynamic" (all-digits, uuid, hash, long mixed token) is replaced with a
//     placeholder; ordinary words are kept literally.
type Normalizer struct {
	patterns []routePattern
	// ignore holds path prefixes whose requests are dropped entirely at ingest
	// time (never counted, never stored) -- e.g. Knight's own dashboard API
	// path, so the agent doesn't count its own polling as site traffic. Stored
	// trimmed of any trailing slash; matched by Ignore.
	ignore []string
}

type routePattern struct {
	segs []patternSeg
}

type patternSeg struct {
	param bool
	// value is the literal text (param == false) or the placeholder name to
	// render, e.g. "id" -> "{id}" (param == true).
	value string
}

// NewNormalizer compiles config route patterns and ignore prefixes. Patterns
// use ":name" for a dynamic segment, e.g. "/api/users/:id/orders/:orderId".
// ignorePaths are absolute path prefixes to drop from ingestion entirely (see
// Ignore). Invalid/empty entries in either list are skipped. Passing nil for
// both is fine -- pure heuristic mode, nothing ignored.
func NewNormalizer(patterns, ignorePaths []string) *Normalizer {
	n := &Normalizer{}
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" || !strings.HasPrefix(p, "/") {
			continue
		}
		var rp routePattern
		for _, seg := range splitPath(p) {
			if strings.HasPrefix(seg, ":") {
				rp.segs = append(rp.segs, patternSeg{param: true, value: strings.TrimPrefix(seg, ":")})
			} else {
				rp.segs = append(rp.segs, patternSeg{value: seg})
			}
		}
		n.patterns = append(n.patterns, rp)
	}
	for _, p := range ignorePaths {
		p = strings.TrimSpace(p)
		if p == "" || !strings.HasPrefix(p, "/") {
			continue
		}
		// Trim a trailing slash so "/api/knight/" and "/api/knight" behave the
		// same; the bare root "/" collapses to "" then back to "/" so it only
		// ever ignores the literal root path, never everything.
		p = strings.TrimRight(p, "/")
		if p == "" {
			p = "/"
		}
		n.ignore = append(n.ignore, p)
	}
	return n
}

// Ignore reports whether a request path should be dropped from ingestion. A
// path matches an ignore prefix when it equals the prefix exactly or sits
// beneath it as a full path segment -- so "/api/knight" ignores "/api/knight"
// and "/api/knight/v1/overview" but NOT "/api/knightfoo".
func (n *Normalizer) Ignore(path string) bool {
	for _, p := range n.ignore {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// Normalize returns the endpoint template for a path.
func (n *Normalizer) Normalize(path string) string {
	if path == "" || path == "/" {
		return "/"
	}
	segs := splitPath(path)

	// Layer 1: first matching config pattern wins.
	for _, rp := range n.patterns {
		if out, ok := rp.match(segs); ok {
			return out
		}
	}

	// Layer 2: heuristic templating.
	out := make([]string, len(segs))
	for i, s := range segs {
		out[i] = classifySegment(s)
	}
	return "/" + strings.Join(out, "/")
}

func (rp routePattern) match(segs []string) (string, bool) {
	if len(rp.segs) != len(segs) {
		return "", false
	}
	out := make([]string, len(segs))
	for i, ps := range rp.segs {
		if ps.param {
			out[i] = "{" + ps.value + "}"
			continue
		}
		if !strings.EqualFold(ps.value, segs[i]) {
			return "", false
		}
		out[i] = ps.value
	}
	return "/" + strings.Join(out, "/"), true
}

func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

var (
	reAllDigits = regexp.MustCompile(`^\d+$`)
	reUUID      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reHex       = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	reHasDigit  = regexp.MustCompile(`\d`)
	reHasLetter = regexp.MustCompile(`[a-zA-Z]`)
)

// classifySegment decides whether one path segment is dynamic and, if so, what
// placeholder to substitute. The bias is CONSERVATIVE: short human-readable
// words (v1, users, orders, my-blog-post) stay literal; only clearly generated
// values become placeholders, so we don't over-collapse distinct real routes.
func classifySegment(s string) string {
	switch {
	case s == "":
		return s
	case reUUID.MatchString(s):
		return "{uuid}"
	case reAllDigits.MatchString(s):
		return "{id}"
	case reHex.MatchString(s):
		return "{hash}"
	// Mixed letters+digits, long enough to be a generated key/token rather than
	// a slug (api keys, session ids, base62 ids). e.g. "aGVsbG9rZXkx9zQ".
	case len(s) >= 12 && reHasDigit.MatchString(s) && reHasLetter.MatchString(s) && !strings.Contains(s, "-"):
		return "{token}"
	default:
		return s
	}
}
