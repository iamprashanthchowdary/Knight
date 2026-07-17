package analytics

import (
	"testing"
	"time"
)

func TestReportFlow(t *testing.T) {
	s := NewStore(time.Hour)
	base := time.Date(2026, 7, 15, 22, 0, 0, 0, time.UTC)

	add := func(status int, query string, min int) {
		s.Add(Record{
			Time: base.Add(time.Duration(min) * time.Minute), Site: "swiftflow",
			IP: "10.0.0.1", Method: "GET",
			Path: "/payments/api/lumpsum/get-redirection-url", Query: query, Status: status,
		}, "/payments/api/lumpsum/get-redirection-url")
	}
	// Failing requests with query params (percent-encoded, like nginx logs them).
	add(400, "ihNo=483422527&fundCode=116&apiKey=abc-123", 1)
	add(400, "ihNo=1359367&fundCode=185&apiKey=def-456", 2)
	add(500, "ihNo=99&fundCode=200", 3) // no apiKey
	// A success on the same endpoint must NOT be retained as an event.
	add(200, "ihNo=7&fundCode=1&apiKey=zzz", 4)
	// A failure on a different endpoint, to prove endpoint filtering.
	s.Add(Record{Time: base, Site: "swiftflow", IP: "10.0.0.2", Method: "GET",
		Path: "/other", Query: "foo=bar", Status: 404}, "/other")

	ep := "/payments/api/lumpsum/get-redirection-url"
	f := ReportFilter{Endpoint: ep, Classes: []int{4, 5}}

	// Step 3/4: distinct endpoints (unfiltered by endpoint).
	eps := s.ReportEndpoints(ReportFilter{Classes: []int{4, 5}})
	if len(eps) != 2 {
		t.Fatalf("expected 2 failing endpoints, got %d", len(eps))
	}
	if eps[0].Endpoint != ep || eps[0].Count != 3 {
		t.Errorf("busiest endpoint wrong: %+v", eps[0])
	}
	if eps[0].C4xx != 2 || eps[0].C5xx != 1 {
		t.Errorf("class split wrong: %+v", eps[0])
	}

	// Step 5: key discovery + coverage (3 events on this endpoint).
	keys := s.ReportKeys(f)
	cov := map[string]float64{}
	for _, k := range keys {
		cov[k.Key] = k.Coverage
	}
	if cov["ihNo"] != 1.0 || cov["fundCode"] != 1.0 {
		t.Errorf("ihNo/fundCode should be 100%% coverage: %+v", cov)
	}
	if cov["apiKey"] <= 0.66 || cov["apiKey"] >= 0.67 { // 2 of 3
		t.Errorf("apiKey coverage should be ~0.667, got %v", cov["apiKey"])
	}

	// Step 6: the report, newest first, missing key = empty cell.
	table := s.ReportRows(f, []string{"ihNo", "fundCode", "apiKey"}, 100)
	if table.Total != 3 {
		t.Fatalf("expected 3 rows, got %d", table.Total)
	}
	// Columns: date, ip, status, method, endpoint, ihNo, fundCode, apiKey
	if got := table.Columns[len(table.Columns)-1]; got != "apiKey" {
		t.Errorf("last column = %q, want apiKey", got)
	}
	// Newest row (min=3) is the 500 with no apiKey.
	newest := table.Rows[0]
	if newest[2] != "500" {
		t.Errorf("newest row status = %q, want 500", newest[2])
	}
	if newest[len(newest)-1] != "" {
		t.Errorf("missing apiKey should render empty, got %q", newest[len(newest)-1])
	}
	// A populated row must have the decoded value.
	if table.Rows[1][5] != "1359367" { // ihNo of the min=2 event
		t.Errorf("ihNo value wrong: %q", table.Rows[1][5])
	}
}
