package analytics

import (
	"net/url"
	"sort"
	"time"
)

// QueryParam is one decomposed query-string key, shown both decoded (the
// readable form -- nested JSON, spaces, etc. all come through legibly) and in
// its original percent-encoded form. Both matter: decoded is what a human
// wants to read, but a raw request only ever sends the percent-encoded
// bytes, so the raw form is what you'd need to reproduce the exact request
// (e.g. in a curl command) or compare byte-for-byte against another log line.
type QueryParam struct {
	Key     string `json:"key"`
	Decoded string `json:"decoded"`
	Raw     string `json:"raw"`
	// Corrupt is true when the decoded value isn't valid printable text (a
	// client sent malformed percent-encoding that decodes to mojibake, e.g.
	// truncated %-escapes or invalid UTF-8) -- Decoded falls back to Raw in
	// that case, matching ReportRows' existing behavior, and the FE uses this
	// to say so explicitly rather than silently showing garbage as if it were
	// the clean value.
	Corrupt bool `json:"corrupt"`
}

// LineBreakdown is one raw log line decomposed into its structured fields
// plus every query-string key, for the FE's "what actually happened" detail
// screen -- reached by clicking a raw log line already surfaced via
// GET /v1/report/rows?include_raw=1.
type LineBreakdown struct {
	OK      bool         `json:"ok"`
	Time    string       `json:"time,omitempty"` // RFC3339
	IP      string       `json:"ip,omitempty"`
	Method  string       `json:"method,omitempty"`
	Path    string       `json:"path,omitempty"`
	Query   []QueryParam `json:"query,omitempty"`
	Status  int          `json:"status,omitempty"`
	Bytes   int64        `json:"bytes,omitempty"`
	Referer string       `json:"referer,omitempty"`
	UA      string       `json:"user_agent,omitempty"`
	Host    string       `json:"host,omitempty"` // only ever set by the JSON log format -- combined format has no such field
	Raw     string       `json:"raw"`
}

// DecodeLine re-parses one raw log line with the SAME Parse used at ingest
// time, so this breakdown can never drift from what Knight itself extracted
// -- there's exactly one place that knows how to read a log line, not one in
// Go and a second reimplemented in the frontend. OK is false if the line
// doesn't match any known format at all; Raw is still populated so the FE can
// show the line even when it can't be broken down further.
func DecodeLine(raw string) LineBreakdown {
	rec, ok := Parse(raw, "")
	if !ok {
		return LineBreakdown{OK: false, Raw: raw}
	}

	vals, _ := url.ParseQuery(rec.Query)
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	params := make([]QueryParam, 0, len(keys))
	for _, k := range keys {
		decoded := joinValues(vals[k])
		rawVal := rawQueryValue(rec.Query, k)
		corrupt := !printable(decoded)
		if corrupt && rawVal != "" {
			decoded = rawVal // same fallback ReportRows already applies
		}
		params = append(params, QueryParam{Key: k, Decoded: decoded, Raw: rawVal, Corrupt: corrupt})
	}

	return LineBreakdown{
		OK:      true,
		Time:    rec.Time.Format(time.RFC3339),
		IP:      rec.IP,
		Method:  rec.Method,
		Path:    rec.Path,
		Query:   params,
		Status:  rec.Status,
		Bytes:   rec.Bytes,
		Referer: rec.Referer,
		UA:      rec.UA,
		Host:    rec.Host,
		Raw:     rec.Raw,
	}
}
