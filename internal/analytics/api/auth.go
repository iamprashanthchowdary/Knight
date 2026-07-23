package api

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"sync/atomic"
)

// tokens is the pair Auth hot-swaps as one unit, so a reader never observes a
// half-updated pair (e.g. a new admin token paired with a stale viewer token).
type tokens struct {
	Viewer string
	Admin  string
}

// Auth checks bearer tokens against the two configured tiers. See
// config.AuthConfig for the read/write split this enforces. Held behind an
// atomic pointer (same pattern as analytics.NormalizerHolder) so a token
// rotation (ConfigService.RotateToken) takes effect for the very next
// request -- no restart required.
type Auth struct {
	p atomic.Pointer[tokens]
}

// NewAuth builds an Auth with the given starting tokens.
func NewAuth(viewer, admin string) *Auth {
	a := &Auth{}
	a.p.Store(&tokens{Viewer: viewer, Admin: admin})
	return a
}

// SetAdmin hot-swaps the admin token, leaving the viewer token untouched.
// Load-then-store, not a single atomic read-modify-write -- safe only because
// ConfigService.RotateToken serializes every rotation through its own mutex.
// Do not call this from anywhere else without the same discipline.
func (a *Auth) SetAdmin(token string) {
	cur := a.p.Load()
	a.p.Store(&tokens{Viewer: cur.Viewer, Admin: token})
}

// SetViewer hot-swaps the viewer token, leaving the admin token untouched.
// Same load-then-store caveat as SetAdmin.
func (a *Auth) SetViewer(token string) {
	cur := a.p.Load()
	a.p.Store(&tokens{Viewer: token, Admin: cur.Admin})
}

// requireViewer allows either token (an admin can do everything a viewer can).
func (a *Auth) requireViewer(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.isAdmin(r) && !a.isViewer(r) {
			unauthorized(w)
			return
		}
		next(w, r)
	}
}

// requireAdmin allows only the admin token.
func (a *Auth) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.isAdmin(r) {
			unauthorized(w)
			return
		}
		next(w, r)
	}
}

func (a *Auth) isAdmin(r *http.Request) bool {
	t := a.p.Load()
	return t.Admin != "" && constantTimeEqual(bearerToken(r), t.Admin)
}

func (a *Auth) isViewer(r *http.Request) bool {
	t := a.p.Load()
	return t.Viewer != "" && constantTimeEqual(bearerToken(r), t.Viewer)
}

// bearerToken extracts the token from "Authorization: Bearer <token>". Tokens
// are deliberately never accepted via query string: request URLs commonly end
// up in access logs (including nginx's own), which would leak the token right
// back into the logs Knight exists to read.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimPrefix(h, prefix)
}

// constantTimeEqual compares two tokens without leaking timing information
// about how many leading bytes matched.
func constantTimeEqual(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="knight"`)
	http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
}
