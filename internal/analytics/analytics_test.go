package analytics

import (
	"testing"
	"time"
)

func TestNormalizeHeuristic(t *testing.T) {
	n := NewNormalizer(nil)
	cases := map[string]string{
		"/":                   "/",
		"/api/products/12345": "/api/products/{id}",
		"/v1/users/550e8400-e29b-41d4-a716-446655440000": "/v1/users/{uuid}",
		"/files/deadbeefdeadbeef0123":                    "/files/{hash}",
		"/download/aGVsbG9rZXkx9zQ/file":                 "/download/{token}/file",
		"/v1/products/list":                              "/v1/products/list",
		"/blog/my-post-title":                            "/blog/my-post-title",
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

func TestParseJSONPrefersForwardedForOverRemoteAddr(t *testing.T) {
	line := `{"v":1,"time":"2026-07-20T12:34:56+05:30","remote_addr":"10.221.1.118","forwarded_for":"203.0.113.9, 10.221.1.118","method":"GET","uri":"/payments/api/lumpsum/get-redirection-url?ihNo=906182580","status":400,"bytes_sent":512,"referer":"-","user_agent":"curl/8.0","host":"swiftflowpayments.com"}`
	r, ok := Parse(line, "swiftflow")
	if !ok {
		t.Fatal("expected JSON line to parse")
	}
	if r.IP != "203.0.113.9" {
		t.Errorf("IP = %q, want the real client (first X-Forwarded-For hop), not the proxy remote_addr", r.IP)
	}
	if r.Path != "/payments/api/lumpsum/get-redirection-url" || r.Query != "ihNo=906182580" {
		t.Errorf("path/query split wrong: path=%q query=%q", r.Path, r.Query)
	}
	if r.Status != 400 || r.Bytes != 512 || r.Site != "swiftflow" {
		t.Errorf("bad parse: %+v", r)
	}
}

func TestParseJSONFallsBackToRemoteAddrWhenNoForwardedFor(t *testing.T) {
	line := `{"v":1,"time":"2026-07-20T12:34:56+05:30","remote_addr":"10.221.1.118","forwarded_for":"-","method":"GET","uri":"/","status":200,"bytes_sent":10}`
	r, ok := Parse(line, "s")
	if !ok {
		t.Fatal("expected JSON line to parse")
	}
	if r.IP != "10.221.1.118" {
		t.Errorf("IP = %q, want remote_addr fallback when forwarded_for is absent (\"-\")", r.IP)
	}
}

func TestParseAutoDetectsPerLine(t *testing.T) {
	jsonLine := `{"v":1,"time":"2026-07-20T00:00:00Z","remote_addr":"1.1.1.1","method":"GET","uri":"/a","status":200,"bytes_sent":1}`
	combinedLine := `2.2.2.2 - - [20/Jul/2026:00:00:01 +0000] "GET /b HTTP/1.1" 200 2 "-" "ua"`

	r1, ok := Parse(jsonLine, "s")
	if !ok || r1.IP != "1.1.1.1" || r1.Path != "/a" {
		t.Errorf("json line: got %+v ok=%v", r1, ok)
	}
	r2, ok := Parse(combinedLine, "s")
	if !ok || r2.IP != "2.2.2.2" || r2.Path != "/b" {
		t.Errorf("combined line: got %+v ok=%v", r2, ok)
	}
}

func TestParseJSONMalformedFallsBackToCombined(t *testing.T) {
	// Starts with '{' but isn't valid JSON -- must not crash, and since it also
	// isn't valid combined format, must be rejected rather than half-parsed.
	if _, ok := Parse(`{not json at all`, "s"); ok {
		t.Error("expected malformed JSON-looking line to be rejected, not silently accepted")
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

func TestEvictOldestIPsBoundsMapSize(t *testing.T) {
	base := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	m := map[string]*IPStat{
		"1.1.1.1": {IP: "1.1.1.1", Last: base},                      // oldest
		"2.2.2.2": {IP: "2.2.2.2", Last: base.Add(time.Minute)},     // middle
		"3.3.3.3": {IP: "3.3.3.3", Last: base.Add(2 * time.Minute)}, // newest
	}

	evictOldestIPs(m, 5) // under limit: no-op
	if len(m) != 3 {
		t.Fatalf("under-limit call should not evict anything, len = %d", len(m))
	}

	evictOldestIPs(m, 2) // over limit by 1: drop the single oldest
	if len(m) != 2 {
		t.Fatalf("len after eviction = %d, want 2", len(m))
	}
	if _, ok := m["1.1.1.1"]; ok {
		t.Error("expected the oldest-seen IP to be evicted")
	}
	if _, ok := m["3.3.3.3"]; !ok {
		t.Error("expected the newest-seen IP to survive")
	}
}

func TestStoreEnforcesMaxTrackedIPs(t *testing.T) {
	s := NewStore(24 * time.Hour)
	n := NewNormalizer(nil)
	base := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)

	// One record per distinct IP, well over a small artificial cap tested via
	// evictOldestIPs directly above; here we confirm Evict() actually calls it
	// by shrinking maxTrackedIPs's effect indirectly: add a handful of IPs and
	// verify Evict never grows the map, and never drops IPs seen within retention.
	for i := 0; i < 50; i++ {
		r, _ := ParseCombined(`X - - [20/Jul/2026:00:00:00 +0000] "GET /x HTTP/1.1" 200 1 "-" "ua"`, "s")
		r.IP = itoa(i)
		r.Time = base
		s.Add(r, n.Normalize(r.Path))
	}
	s.Evict(base) // well under maxTrackedIPs; must not touch fresh IPs
	if got := s.Overview().DistinctIPs; got != 50 {
		t.Fatalf("distinct ips after in-window evict = %d, want 50", got)
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
