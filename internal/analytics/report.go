package analytics

import (
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// ReportFilter selects which retained failing events a report covers. Zero
// values mean "no constraint": empty Site/Endpoint/Method match all, zero
// From/To are unbounded, and an empty Classes matches every retained event
// (which is already only status >= 400, i.e. "4xx and 5xx").
type ReportFilter struct {
	Site     string
	Endpoint string // endpoint template
	Method   string
	From     time.Time
	To       time.Time
	Classes  []int // e.g. [4], [5], or [4,5]
}

func (f ReportFilter) match(e Event) bool {
	if f.Site != "" && e.Site != f.Site {
		return false
	}
	if f.Endpoint != "" && e.Template != f.Endpoint {
		return false
	}
	if f.Method != "" && e.Method != f.Method {
		return false
	}
	if !f.From.IsZero() && e.Time.Before(f.From) {
		return false
	}
	if !f.To.IsZero() && !e.Time.Before(f.To) {
		return false
	}
	if len(f.Classes) > 0 {
		c := e.Status / 100
		ok := false
		for _, want := range f.Classes {
			if want == c {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// matchingEvents snapshots events passing the filter under the read lock, so
// the (potentially slow) URL parsing happens outside the lock.
func (s *Store) matchingEvents(f ReportFilter) []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Event, 0, len(s.events)/4)
	for _, e := range s.events {
		if f.match(e) {
			out = append(out, e)
		}
	}
	return out
}

// ReportEndpoint is one distinct failing endpoint (step 3/4 of the report flow).
type ReportEndpoint struct {
	Site     string `json:"site"`
	Method   string `json:"method"`
	Endpoint string `json:"endpoint"`
	Count    int    `json:"count"`
	C4xx     int    `json:"c4xx"`
	C5xx     int    `json:"c5xx"`
}

// ReportEndpoints aggregates failing events into distinct endpoints, busiest
// first, so the user can pick which to drill into.
func (s *Store) ReportEndpoints(f ReportFilter) []ReportEndpoint {
	evs := s.matchingEvents(f)
	m := make(map[string]*ReportEndpoint)
	for _, e := range evs {
		key := e.Site + "\x00" + e.Method + "\x00" + e.Template
		r := m[key]
		if r == nil {
			r = &ReportEndpoint{Site: e.Site, Method: e.Method, Endpoint: e.Template}
			m[key] = r
		}
		r.Count++
		switch e.Status / 100 {
		case 4:
			r.C4xx++
		case 5:
			r.C5xx++
		}
	}
	out := make([]ReportEndpoint, 0, len(m))
	for _, r := range m {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

// ReportKey is one query-string key discovered across the matching events, with
// how many events contained it (step 5: "destruct the keys").
type ReportKey struct {
	Key      string  `json:"key"`
	Count    int     `json:"count"`
	Coverage float64 `json:"coverage"` // fraction of matching events with this key
}

// ReportKeys discovers the distinct query-param keys present across matching
// events, most common first, so the user can choose which become columns.
func (s *Store) ReportKeys(f ReportFilter) []ReportKey {
	evs := s.matchingEvents(f)
	counts := make(map[string]int)
	for _, e := range evs {
		vals, err := url.ParseQuery(e.Query)
		if err != nil {
			continue
		}
		for k := range vals {
			counts[k]++
		}
	}
	total := len(evs)
	out := make([]ReportKey, 0, len(counts))
	for k, c := range counts {
		cov := 0.0
		if total > 0 {
			cov = float64(c) / float64(total)
		}
		out = append(out, ReportKey{Key: k, Count: c, Coverage: cov})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// ReportTable is the final report (step 6): fixed leading columns plus one
// column per requested query-param key, newest row first.
type ReportTable struct {
	Columns []string   `json:"columns"`
	Rows    [][]string `json:"rows"`
	Total   int        `json:"total"` // matching events before the limit
}

// ReportRows builds the report for the selected keys. Multi-valued query params
// are joined with " | "; missing keys render as an empty cell.
func (s *Store) ReportRows(f ReportFilter, keys []string, limit int) ReportTable {
	evs := s.matchingEvents(f)
	sort.Slice(evs, func(i, j int) bool { return evs[i].Time.After(evs[j].Time) })
	total := len(evs)
	if limit > 0 && len(evs) > limit {
		evs = evs[:limit]
	}

	cols := append([]string{"date", "ip", "status", "method", "endpoint"}, keys...)
	rows := make([][]string, 0, len(evs))
	for _, e := range evs {
		vals, _ := url.ParseQuery(e.Query)
		row := make([]string, 0, len(cols))
		row = append(row,
			e.Time.Format(time.RFC3339),
			e.IP,
			strconv.Itoa(e.Status),
			e.Method,
			e.Template,
		)
		for _, k := range keys {
			v := ""
			if vv, ok := vals[k]; ok && len(vv) > 0 {
				v = joinValues(vv)
				// Some clients send corrupted params (e.g. ihNo containing raw
				// U+FFFD bytes) that decode to unreadable mojibake. Rather than
				// emit garbage, fall back to the honest raw percent-encoded form.
				if !printable(v) {
					if raw := rawQueryValue(e.Query, k); raw != "" {
						v = raw
					}
				}
			}
			row = append(row, v)
		}
		rows = append(rows, row)
	}
	return ReportTable{Columns: cols, Rows: rows, Total: total}
}

// printable reports whether s is valid UTF-8 with no replacement or control
// characters (tab excepted). A decoded query value that fails this is treated
// as corrupt and shown in its raw form instead.
func printable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == utf8.RuneError { // includes literal U+FFFD from %EF%BF%BD
			return false
		}
		if unicode.IsControl(r) && r != '\t' {
			return false
		}
	}
	return true
}

// rawQueryValue returns the still-percent-encoded value for key from the raw
// query string (no decoding), or "" if absent.
func rawQueryValue(query, key string) string {
	for _, pair := range strings.Split(query, "&") {
		eq := strings.IndexByte(pair, '=')
		if eq < 0 {
			if pair == key {
				return ""
			}
			continue
		}
		if pair[:eq] == key {
			return pair[eq+1:]
		}
	}
	return ""
}

func joinValues(vs []string) string {
	if len(vs) == 1 {
		return vs[0]
	}
	out := vs[0]
	for _, v := range vs[1:] {
		out += " | " + v
	}
	return out
}
