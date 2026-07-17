// Package analytics turns a stream of nginx access-log lines into queryable
// traffic statistics: status-code breakdowns over time, per-IP behaviour, and
// per-endpoint health. It is READ-ONLY -- it never blocks, bans, or touches
// traffic. This is the "observe & inform" layer: a Sentry-style eye on the
// network edge, built to feed a dashboard.
package analytics

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Record is one parsed request from the access log.
type Record struct {
	Time    time.Time
	Site    string // which configured log this came from
	IP      string
	Method  string
	Path    string // path only, query stripped off
	Query   string
	Status  int
	Bytes   int64
	Referer string
	UA      string
}

// combinedRE parses the nginx "combined" log format:
//
//	$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$referer" "$ua"
//
// Group 1 ip, 2 time_local, 3 method, 4 request-target, 5 status, 6 bytes,
// 7 referer, 8 user-agent.
var combinedRE = regexp.MustCompile(
	`^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]*?) [^"]*" (\d{3}) (\S+) "([^"]*)" "([^"]*)"`,
)

// nginxTimeLayout matches $time_local, e.g. 15/Jul/2026:13:04:05 +0000.
const nginxTimeLayout = "02/Jan/2006:15:04:05 -0700"

// ParseCombined parses one access-log line. ok is false for lines that don't
// match (health checks in a different format, blank lines, garbage) -- callers
// simply skip those. The site label is attached to the record.
func ParseCombined(line, site string) (Record, bool) {
	m := combinedRE.FindStringSubmatch(line)
	if m == nil {
		return Record{}, false
	}

	status, err := strconv.Atoi(m[5])
	if err != nil {
		return Record{}, false
	}

	ts, err := time.Parse(nginxTimeLayout, m[2])
	if err != nil {
		ts = time.Now() // fall back to ingest time rather than drop the line
	}

	path, query := m[4], ""
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path, query = path[:i], path[i+1:]
	}

	var bytes int64
	if m[6] != "-" {
		bytes, _ = strconv.ParseInt(m[6], 10, 64)
	}

	return Record{
		Time:    ts,
		Site:    site,
		IP:      m[1],
		Method:  m[3],
		Path:    path,
		Query:   query,
		Status:  status,
		Bytes:   bytes,
		Referer: m[7],
		UA:      m[8],
	}, true
}

// Class returns the status class bucket index (1xx..5xx -> 1..5, unknown -> 0).
func Class(status int) int {
	c := status / 100
	if c < 1 || c > 5 {
		return 0
	}
	return c
}
