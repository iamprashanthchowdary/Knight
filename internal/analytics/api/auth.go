package api

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// Auth checks bearer tokens against the two configured tiers. See
// config.AuthConfig for the read/write split this enforces.
type Auth struct {
	ViewerToken string
	AdminToken  string
}

// requireViewer allows either token (an admin can do everything a viewer can).
func (a Auth) requireViewer(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.isAdmin(r) && !a.isViewer(r) {
			unauthorized(w)
			return
		}
		next(w, r)
	}
}

// requireAdmin allows only the admin token.
func (a Auth) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.isAdmin(r) {
			unauthorized(w)
			return
		}
		next(w, r)
	}
}

func (a Auth) isAdmin(r *http.Request) bool {
	return a.AdminToken != "" && constantTimeEqual(bearerToken(r), a.AdminToken)
}

func (a Auth) isViewer(r *http.Request) bool {
	return a.ViewerToken != "" && constantTimeEqual(bearerToken(r), a.ViewerToken)
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
