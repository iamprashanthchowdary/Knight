package analytics

import "testing"

func TestNormalizeHeuristic(t *testing.T) {
	n := NewNormalizer(nil)
	cases := map[string]string{
		"/":                                        "/",
		"/api/products/12345":                      "/api/products/{id}",
		"/v1/users/550e8400-e29b-41d4-a716-446655440000": "/v1/users/{uuid}",
		"/files/deadbeefdeadbeef0123":              "/files/{hash}",
		"/download/aGVsbG9rZXkx9zQ/file":           "/download/{token}/file",
		"/v1/products/list":                        "/v1/products/list",
		"/blog/my-post-title":                      "/blog/my-post-title",
	}
	for in, want := range cases {
		if got := n.Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeConfigPatternWins(t *testing.T) {
	n := NewNormalizer([]string{"/api/users/:id/orders/:orderId"})
	got := n.Normalize("/api/users/42/orders/99")
	want := "/api/users/{id}/orders/{orderId}"
	if got != want {
		t.Errorf("Normalize = %q, want %q", got, want)
	}
	// Non-matching length falls through to heuristic.
	if got := n.Normalize("/api/users/42"); got != "/api/users/{id}" {
		t.Errorf("fallthrough Normalize = %q, want /api/users/{id}", got)
	}
}

func TestParseCombined(t *testing.T) {
	line := `203.0.113.7 - - [15/Jul/2026:13:04:05 +0000] "GET /api/products/12345?ref=x HTTP/1.1" 200 512 "-" "curl/8.0"`
	r, ok := ParseCombined(line, "shop")
	if !ok {
		t.Fatal("expected parse to succeed")
	}
	if r.IP != "203.0.113.7" || r.Method != "GET" || r.Status != 200 {
		t.Errorf("bad parse: %+v", r)
	}
	if r.Path != "/api/products/12345" || r.Query != "ref=x" {
		t.Errorf("path/query split wrong: path=%q query=%q", r.Path, r.Query)
	}
	if r.Site != "shop" || r.Bytes != 512 {
		t.Errorf("site/bytes wrong: %+v", r)
	}
}

func TestParseCombinedRejectsGarbage(t *testing.T) {
	if _, ok := ParseCombined("not a log line", "x"); ok {
		t.Error("expected garbage line to be rejected")
	}
}

func TestStoreAggregatesRatesAndGrouping(t *testing.T) {
	s := NewStore(0)
	n := NewNormalizer(nil)
	add := func(ip, path string, status int) {
		r, _ := ParseCombined(
			`X - - [15/Jul/2026:13:04:05 +0000] "GET `+path+` HTTP/1.1" `+itoa(status)+` 10 "-" "ua"`, "s")
		r.IP = ip
		s.Add(r, n.Normalize(r.Path))
	}
	// One IP hits the same templated endpoint with mixed outcomes.
	add("1.1.1.1", "/api/products/1", 200)
	add("1.1.1.1", "/api/products/2", 200)
	add("1.1.1.1", "/api/products/3", 404)
	add("1.1.1.1", "/api/products/4", 500)

	ov := s.Overview()
	if ov.Total != 4 {
		t.Fatalf("total = %d, want 4", ov.Total)
	}
	if ov.DistinctRoutes != 1 {
		t.Errorf("distinct endpoints = %d, want 1 (all collapse to /api/products/{id})", ov.DistinctRoutes)
	}

	d, ok := s.IPDetail("1.1.1.1")
	if !ok {
		t.Fatal("expected ip detail")
	}
	if d.SuccessRate != 0.5 || d.FailureRate != 0.25 || d.ErrorRate != 0.25 {
		t.Errorf("rates wrong: succ=%v fail=%v err=%v", d.SuccessRate, d.FailureRate, d.ErrorRate)
	}
	if len(d.CalledEndpoints) != 1 || d.CalledEndpoints[0].Endpoint != "/api/products/{id}" {
		t.Errorf("endpoint grouping wrong: %+v", d.CalledEndpoints)
	}
	if d.CalledEndpoints[0].Hits != 4 {
		t.Errorf("hits = %d, want 4", d.CalledEndpoints[0].Hits)
	}
}

// itoa avoids importing strconv just for the test helper.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
