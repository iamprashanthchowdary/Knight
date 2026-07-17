package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func handlerOK(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }

func request(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func TestRequireViewer(t *testing.T) {
	a := Auth{ViewerToken: "view-tok", AdminToken: "admin-tok"}
	h := a.requireViewer(handlerOK)

	cases := []struct {
		name  string
		token string
		want  int
	}{
		{"no token", "", http.StatusUnauthorized},
		{"wrong token", "garbage", http.StatusUnauthorized},
		{"viewer token", "view-tok", http.StatusOK},
		{"admin token also works", "admin-tok", http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h(w, request(c.token))
			if w.Code != c.want {
				t.Errorf("got status %d, want %d", w.Code, c.want)
			}
		})
	}
}

func TestRequireAdmin(t *testing.T) {
	a := Auth{ViewerToken: "view-tok", AdminToken: "admin-tok"}
	h := a.requireAdmin(handlerOK)

	cases := []struct {
		name  string
		token string
		want  int
	}{
		{"no token", "", http.StatusUnauthorized},
		{"viewer token rejected", "view-tok", http.StatusUnauthorized},
		{"admin token", "admin-tok", http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h(w, request(c.token))
			if w.Code != c.want {
				t.Errorf("got status %d, want %d", w.Code, c.want)
			}
		})
	}
}

func TestUnauthorizedResponseIsWellFormed(t *testing.T) {
	a := Auth{ViewerToken: "v", AdminToken: "ad"}
	w := httptest.NewRecorder()
	a.requireAdmin(handlerOK)(w, request(""))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if got := w.Header().Get("WWW-Authenticate"); got == "" {
		t.Error("expected a WWW-Authenticate header on 401")
	}
}

func TestNoTokensConfiguredMeansEverythingRejected(t *testing.T) {
	// Empty Auth (e.g. a bug that skipped Load's auto-generation) must fail
	// closed, never open -- an empty configured token must never match an
	// empty/missing request token.
	a := Auth{}
	w := httptest.NewRecorder()
	a.requireViewer(handlerOK)(w, request(""))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("empty tokens must fail closed, got status %d", w.Code)
	}
}
