// Package analytics turns a stream of nginx access-log lines into queryable
// traffic statistics: status-code breakdowns over time, per-IP behaviour, and
// per-endpoint health. It is READ-ONLY -- it never blocks, bans, or touches
// traffic. This is the "observe & inform" layer: a Sentry-style eye on the
// network edge, built to feed a dashboard.
package analytics

import (
	"encoding/json"
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

// jsonLine is Knight's registered structured nginx log format (see
// deploy/nginx-log-format.conf). It's versioned via "v" so a future field
// change can be detected rather than silently mis-parsed. Unknown/missing
// fields are never a parse error -- encoding/json ignores fields it doesn't
// recognize and zero-values ones that are absent, so this format can gain
// fields later without breaking older log lines already on disk.
type jsonLine struct {
	V            int    `json:"v"`
	Time         string `json:"time"`
	RemoteAddr   string `json:"remote_addr"`
	ForwardedFor string `json:"forwarded_for"`
	Method       string `json:"method"`
	URI          string `json:"uri"`
	Status       int    `json:"status"`
	BytesSent    int64  `json:"bytes_sent"`
	Referer      string `json:"referer"`
	UserAgent    string `json:"user_agent"`
}

// Parse is the entrypoint tailers/batch readers should use: it auto-detects
// Knight's structured JSON format (deploy/nginx-log-format.conf) vs. plain
// nginx "combined" format per line, so a site can mix history from before and
// after adopting the JSON format in the same log file with no migration step.
func Parse(line, site string) (Record, bool) {
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "{") {
		if rec, ok := parseJSON(trimmed, site); ok {
			return rec, true
		}
		// Falls through to combined on a malformed JSON line rather than
		// dropping it outright -- cheap insurance, essentially free.
	}
	return ParseCombined(line, site)
}

// parseJSON parses one line of Knight's registered JSON log format. The real
// client IP is preferred from X-Forwarded-For (first hop = original client)
// when present, falling back to remote_addr -- this is what fixes "distinct
// IPs = 1" behind a proxy/load balancer, without needing any Knight-side
// configuration once the nginx log_format is adopted.
func parseJSON(line, site string) (Record, bool) {
	var j jsonLine
	if err := json.Unmarshal([]byte(line), &j); err != nil {
		return Record{}, false
	}
	if j.URI == "" || j.Status == 0 {
		return Record{}, false // not a recognizable request line
	}

	ts, err := time.Parse(time.RFC3339, j.Time)
	if err != nil {
		ts = time.Now()
	}

	path, query := j.URI, ""
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path, query = path[:i], path[i+1:]
	}

	ip := j.RemoteAddr
	if fwd := strings.TrimSpace(firstForwardedFor(j.ForwardedFor)); fwd != "" {
		ip = fwd
	}

	return Record{
		Time:    ts,
		Site:    site,
		IP:      ip,
		Method:  j.Method,
		Path:    path,
		Query:   query,
		Status:  j.Status,
		Bytes:   j.BytesSent,
		Referer: j.Referer,
		UA:      j.UserAgent,
	}, true
}

// firstForwardedFor returns the first (left-most / original client) address in
// a possibly comma-separated X-Forwarded-For value, or "" for an empty/absent
// header. nginx logs "-" for an absent header, which this treats as empty.
func firstForwardedFor(v string) string {
	if v == "" || v == "-" {
		return ""
	}
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

// Class returns the status class bucket index (1xx..5xx -> 1..5, unknown -> 0).
func Class(status int) int {
	c := status / 100
	if c < 1 || c > 5 {
		return 0
	}
	return c
}
