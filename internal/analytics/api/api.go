// Package api exposes the analytics Store as a JSON HTTP API for a web
// frontend. Routes are gated by two bearer-token tiers (see Auth): viewer
// (read-only: overview, endpoints, ips, reports) and admin (viewer routes
// plus config read/write and alert testing -- GET /v1/config is admin-only
// since the config itself holds secrets). CORS is open so a separately hosted
// FE can call it; tighten AllowOrigin before exposing beyond localhost.
package api

import (
	"encoding/csv"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"knight/internal/analytics"
	"knight/internal/config"
)

// Server bundles the store, config service, auth, and logger behind an
// http.Handler.
type Server struct {
	store *analytics.Store
	cfg   *ConfigService
	auth  Auth
	log   *slog.Logger
}

// New builds the API server. cfg may be nil to run read-only (no config routes).
func New(store *analytics.Store, cfg *ConfigService, auth Auth, log *slog.Logger) *Server {
	return &Server{store: store, cfg: cfg, auth: auth, log: log}
}

// Handler returns the routed, CORS-wrapped handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Index: hitting the root in a browser shows what's available instead of a
	// bare "404 page not found".
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"service": "knight observe agent",
			"endpoints": []string{
				"/v1/overview",
				"/v1/timeseries?window=24h&codes=1",
				"/v1/ips?limit=50",
				"/v1/ips/{ip}",
				"/v1/endpoints?limit=50",
				"/v1/report/endpoints?classes=4,5",
				"/v1/report/keys?endpoint=...",
				"/v1/report/rows?endpoint=...&keys=...",
				"/v1/config",
				"/v1/alerts/test",
				"/healthz",
			},
		})
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /v1/overview", s.auth.requireViewer(s.overview))
	mux.HandleFunc("GET /v1/timeseries", s.auth.requireViewer(s.timeseries))
	mux.HandleFunc("GET /v1/series", s.auth.requireViewer(s.series))
	mux.HandleFunc("GET /v1/ips", s.auth.requireViewer(s.ips))
	mux.HandleFunc("GET /v1/ips/{ip}", s.auth.requireViewer(s.ipDetail))
	mux.HandleFunc("GET /v1/endpoints", s.auth.requireViewer(s.endpoints))

	// Failure drill-down reports (read-only): pick failing endpoints, discover
	// their query-param keys, then produce a per-request table (+ CSV export).
	mux.HandleFunc("GET /v1/report/endpoints", s.auth.requireViewer(s.reportEndpoints))
	mux.HandleFunc("GET /v1/report/keys", s.auth.requireViewer(s.reportKeys))
	mux.HandleFunc("GET /v1/report/rows", s.auth.requireViewer(s.reportRows))

	// Config (write-side) and anything that can leak secrets or reconfigure the
	// agent: admin-only. Only mounted when a ConfigService is present.
	if s.cfg != nil {
		mux.HandleFunc("GET /v1/config", s.auth.requireAdmin(s.getConfig))
		mux.HandleFunc("PUT /v1/config", s.auth.requireAdmin(s.putConfig))
		mux.HandleFunc("POST /v1/config/validate", s.auth.requireAdmin(s.validateConfig))
		mux.HandleFunc("POST /v1/config/test-log", s.auth.requireAdmin(s.testLog))
		mux.HandleFunc("POST /v1/config/preview-route", s.auth.requireAdmin(s.previewRoute))
		mux.HandleFunc("POST /v1/alerts/test", s.auth.requireAdmin(s.testAlert))
	}
	return cors(mux)
}

// testAlert sends a synthetic alert to the requested channels (or every
// enabled channel, if the body is empty/omitted), so the config UI can verify
// webhook/email credentials before relying on them.
func (s *Server) testAlert(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Channels []string `json:"channels"`
	}
	if r.ContentLength > 0 {
		if !readJSON(w, r, &body) {
			return
		}
	}
	ok, errs := s.cfg.SendTestAlert(body.Channels)
	if !ok {
		w.WriteHeader(http.StatusBadGateway)
		writeJSON(w, map[string]any{"ok": false, "errors": errs})
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) getConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.cfg.Get())
}

func (s *Server) putConfig(w http.ResponseWriter, r *http.Request) {
	var e config.Editable
	if !readJSON(w, r, &e) {
		return
	}
	errs, saveErr := s.cfg.Apply(e)
	if saveErr != nil {
		s.log.Error("save config", "err", saveErr)
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]any{"ok": false, "error": saveErr.Error()})
		return
	}
	if len(errs) > 0 {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"ok": false, "errors": errs})
		return
	}
	s.log.Info("config updated via api", "sites", len(e.Sites))
	writeJSON(w, map[string]any{"ok": true, "applied": true})
}

func (s *Server) validateConfig(w http.ResponseWriter, r *http.Request) {
	var e config.Editable
	if !readJSON(w, r, &e) {
		return
	}
	errs := s.cfg.Validate(e)
	writeJSON(w, map[string]any{"ok": len(errs) == 0, "errors": errs})
}

func (s *Server) testLog(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AccessLog string `json:"access_log"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	writeJSON(w, TestLog(body.AccessLog))
}

func (s *Server) previewRoute(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Path     string   `json:"path"`
		Patterns []string `json:"patterns"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	writeJSON(w, map[string]string{"endpoint": PreviewRoute(body.Path, body.Patterns)})
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.store.Overview())
}

func (s *Server) timeseries(w http.ResponseWriter, r *http.Request) {
	window := queryDuration(r, "window", 0) // 0 => all retained buckets
	withCodes := r.URL.Query().Get("codes") == "1"
	writeJSON(w, s.store.TimeSeries(window, withCodes))
}

// series returns a fixed-shape chart: `count` sticks of width `bucket`, anchored
// to the latest data (default) or now. Examples:
//
//	?bucket=4m&count=15    recent hour in 15 sticks
//	?bucket=1h&count=12    recent 12 hours, hourly
//	?bucket=24h&count=7    last 7 days, one stick per day
//	?bucket=24h            all days (count omitted => cover everything)
//	&anchor=now            anchor to wall-clock instead of latest data
func (s *Server) series(w http.ResponseWriter, r *http.Request) {
	bucket := queryDuration(r, "bucket", time.Minute)
	count := queryInt(r, "count", 0) // 0 => cover all data
	anchorLatest := r.URL.Query().Get("anchor") != "now"
	writeJSON(w, s.store.Series(bucket, count, anchorLatest))
}

func (s *Server) ips(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.store.TopIPs(queryInt(r, "limit", 50)))
}

func (s *Server) ipDetail(w http.ResponseWriter, r *http.Request) {
	d, ok := s.store.IPDetail(r.PathValue("ip"))
	if !ok {
		http.Error(w, `{"error":"ip not found"}`, http.StatusNotFound)
		return
	}
	writeJSON(w, d)
}

func (s *Server) endpoints(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.store.TopEndpoints(queryInt(r, "limit", 50)))
}

// reportFilter builds a ReportFilter from shared query params: site, endpoint,
// method, from/to (unix seconds), classes ("4,5"). Missing classes defaults to
// both 4xx and 5xx.
func reportFilter(r *http.Request) analytics.ReportFilter {
	q := r.URL.Query()
	classes := intList(q.Get("classes"))
	if len(classes) == 0 {
		classes = []int{4, 5}
	}
	return analytics.ReportFilter{
		Site:     q.Get("site"),
		Endpoint: q.Get("endpoint"),
		Method:   q.Get("method"),
		From:     unixTime(q.Get("from")),
		To:       unixTime(q.Get("to")),
		Classes:  classes,
	}
}

func (s *Server) reportEndpoints(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.store.ReportEndpoints(reportFilter(r)))
}

func (s *Server) reportKeys(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.store.ReportKeys(reportFilter(r)))
}

func (s *Server) reportRows(w http.ResponseWriter, r *http.Request) {
	keys := splitComma(r.URL.Query().Get("keys"))
	limit := queryInt(r, "limit", 1000)
	table := s.store.ReportRows(reportFilter(r), keys, limit)

	if r.URL.Query().Get("format") == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=\"knight-report.csv\"")
		cw := csv.NewWriter(w)
		_ = cw.Write(table.Columns)
		for _, row := range table.Rows {
			_ = cw.Write(row)
		}
		cw.Flush()
		return
	}
	writeJSON(w, table)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// readJSON decodes a request body, writing a 400 and returning false on failure.
func readJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		http.Error(w, `{"ok":false,"error":"invalid JSON body"}`, http.StatusBadRequest)
		return false
	}
	return true
}

func cors(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func queryInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func queryDuration(r *http.Request, key string, def time.Duration) time.Duration {
	if v := r.URL.Query().Get(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}

// unixTime parses a unix-seconds string into a time.Time; empty or invalid
// yields the zero Time (treated as unbounded by ReportFilter).
func unixTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(n, 0)
}

// intList parses "4,5" into [4,5], skipping non-numeric entries.
func intList(s string) []int {
	if s == "" {
		return nil
	}
	var out []int
	for _, part := range strings.Split(s, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// splitComma splits "a,b, c" into ["a","b","c"], dropping blanks.
func splitComma(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
