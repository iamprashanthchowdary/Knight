package api

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"knight/internal/alerts"
	"knight/internal/analytics"
	"knight/internal/config"
)

// ConfigService is the write-side of the agent: it validates edits, persists
// them to config.json, and hot-reloads the runtime (tailers + normalizer +
// retention + alert rules/channels). It is the single source of truth the FE
// and CLI both drive.
type ConfigService struct {
	mu     sync.Mutex
	path   string
	cfg    *config.Config
	mgr    *analytics.Manager
	store  *analytics.Store
	alerts *alerts.Engine // optional; nil disables alert-related reload
}

// NewConfigService wires the service to the loaded config and running runtime.
// alertsEngine may be nil if alerting isn't wired up.
func NewConfigService(path string, cfg *config.Config, mgr *analytics.Manager, store *analytics.Store, alertsEngine *alerts.Engine) *ConfigService {
	return &ConfigService{path: path, cfg: cfg, mgr: mgr, store: store, alerts: alertsEngine}
}

// FieldError points the UI at exactly which field is wrong.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Get returns the current editable config.
func (s *ConfigService) Get() config.Editable {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg.Editable()
}

// Validate checks an edit without saving.
func (s *ConfigService) Validate(e config.Editable) []FieldError {
	var errs []FieldError
	seen := map[string]bool{}
	for i, site := range e.Sites {
		p := fmt.Sprintf("sites[%d]", i)
		if strings.TrimSpace(site.Name) == "" {
			errs = append(errs, FieldError{p + ".name", "name is required"})
		} else if seen[site.Name] {
			errs = append(errs, FieldError{p + ".name", "duplicate site name"})
		} else {
			seen[site.Name] = true
		}
		switch {
		case strings.TrimSpace(site.AccessLog) == "":
			errs = append(errs, FieldError{p + ".access_log", "access_log is required"})
		case !filepath.IsAbs(site.AccessLog):
			errs = append(errs, FieldError{p + ".access_log", "must be an absolute path"})
		}
	}
	if e.Analytics.APIListen != "" {
		if _, _, err := net.SplitHostPort(e.Analytics.APIListen); err != nil {
			errs = append(errs, FieldError{"analytics.api_listen", "must be host:port, e.g. 127.0.0.1:8090"})
		}
	}
	if e.Analytics.Retention != "" {
		if _, err := time.ParseDuration(e.Analytics.Retention); err != nil {
			errs = append(errs, FieldError{"analytics.retention", "not a valid duration, e.g. 24h or 30m"})
		}
	}
	for i, pat := range e.Analytics.RoutePatterns {
		if !strings.HasPrefix(strings.TrimSpace(pat), "/") {
			errs = append(errs, FieldError{fmt.Sprintf("analytics.route_patterns[%d]", i), "must start with /"})
		}
	}
	if e.Analytics.StateDir != "" && !filepath.IsAbs(e.Analytics.StateDir) {
		errs = append(errs, FieldError{"analytics.state_dir", "must be an absolute path"})
	}
	if e.Analytics.SnapshotInterval != "" {
		if d, err := time.ParseDuration(e.Analytics.SnapshotInterval); err != nil || d <= 0 {
			errs = append(errs, FieldError{"analytics.snapshot_interval", "not a valid duration, e.g. 2m"})
		}
	}
	errs = append(errs, validateAlerts(e.Alerts)...)
	return errs
}

func validateAlerts(a config.AlertsConfig) []FieldError {
	var errs []FieldError
	seenIDs := map[string]bool{}
	for i, r := range a.Rules {
		p := fmt.Sprintf("alerts.rules[%d]", i)
		if strings.TrimSpace(r.ID) == "" {
			errs = append(errs, FieldError{p + ".id", "id is required"})
		} else if seenIDs[r.ID] {
			errs = append(errs, FieldError{p + ".id", "duplicate rule id"})
		} else {
			seenIDs[r.ID] = true
		}
		switch r.Metric {
		case "status_count":
			if len(r.StatusClasses) == 0 {
				errs = append(errs, FieldError{p + ".status_classes", "required for metric status_count, e.g. [5]"})
			}
			for _, c := range r.StatusClasses {
				if c < 1 || c > 5 {
					errs = append(errs, FieldError{p + ".status_classes", "must be 1-5 (status class, e.g. 5 for 5xx)"})
					break
				}
			}
		case "ip_request_count":
			// no extra fields required
		default:
			errs = append(errs, FieldError{p + ".metric", `must be "status_count" or "ip_request_count"`})
		}
		if strings.TrimSpace(r.Window) == "" {
			errs = append(errs, FieldError{p + ".window", "window is required, e.g. \"2m\""})
		} else if _, err := time.ParseDuration(r.Window); err != nil {
			errs = append(errs, FieldError{p + ".window", "not a valid duration, e.g. \"2m\""})
		}
		if r.Cooldown != "" {
			if _, err := time.ParseDuration(r.Cooldown); err != nil {
				errs = append(errs, FieldError{p + ".cooldown", "not a valid duration, e.g. \"10m\""})
			}
		}
		if r.Threshold <= 0 {
			errs = append(errs, FieldError{p + ".threshold", "must be greater than 0"})
		}
		for _, c := range r.Channels {
			if c != "webhook" && c != "email" {
				errs = append(errs, FieldError{p + ".channels", `must be "webhook" or "email"`})
				break
			}
		}
	}

	for _, dur := range []struct{ field, val string }{
		{"alerts.anomaly.baseline_window", a.Anomaly.BaselineWindow},
		{"alerts.anomaly.eval_window", a.Anomaly.EvalWindow},
		{"alerts.anomaly.cooldown", a.Anomaly.Cooldown},
	} {
		if dur.val != "" {
			if _, err := time.ParseDuration(dur.val); err != nil {
				errs = append(errs, FieldError{dur.field, "not a valid duration"})
			}
		}
	}
	if a.Anomaly.Sensitivity < 0 {
		errs = append(errs, FieldError{"alerts.anomaly.sensitivity", "must not be negative"})
	}
	if a.Anomaly.MinRateFloor < 0 || a.Anomaly.MinRateFloor > 1 {
		errs = append(errs, FieldError{"alerts.anomaly.min_rate_floor", "must be between 0 and 1"})
	}

	if a.Webhook.Enabled {
		if strings.TrimSpace(a.Webhook.URL) == "" {
			errs = append(errs, FieldError{"alerts.webhook.url", "url is required when webhook is enabled"})
		} else if u, err := url.Parse(a.Webhook.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			errs = append(errs, FieldError{"alerts.webhook.url", "must be a valid http:// or https:// URL"})
		}
	}
	if a.Email.Enabled {
		if strings.TrimSpace(a.Email.SMTPHost) == "" {
			errs = append(errs, FieldError{"alerts.email.smtp_host", "smtp_host is required when email is enabled"})
		}
		if a.Email.SMTPPort <= 0 || a.Email.SMTPPort > 65535 {
			errs = append(errs, FieldError{"alerts.email.smtp_port", "must be a valid port (1-65535)"})
		}
		if strings.TrimSpace(a.Email.From) == "" {
			errs = append(errs, FieldError{"alerts.email.from", "from is required when email is enabled"})
		}
		if len(a.Email.To) == 0 {
			errs = append(errs, FieldError{"alerts.email.to", "at least one recipient is required when email is enabled"})
		}
	}
	return errs
}

// Apply validates, persists, and hot-reloads. Returns validation errors (config
// unchanged) or a save error. Note: changing analytics.api_listen is saved but
// only takes effect on the next start -- the API socket is already bound.
func (s *ConfigService) Apply(e config.Editable) (errs []FieldError, saveErr error) {
	if v := s.Validate(e); len(v) > 0 {
		return v, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cfg.SetEditable(e)
	if err := s.cfg.Save(s.path); err != nil {
		return nil, err
	}

	specs := make([]analytics.SiteSpec, 0, len(e.Sites))
	for _, site := range e.Sites {
		specs = append(specs, analytics.SiteSpec{Name: site.Name, AccessLog: site.AccessLog})
	}
	s.mgr.Apply(specs, e.Analytics.RoutePatterns)
	s.store.SetRetention(s.cfg.AnalyticsRetention())
	if s.alerts != nil {
		s.alerts.Reload(e.Alerts)
	}
	return nil, nil
}

// SendTestAlert delivers a synthetic alert to the given channels (or every
// enabled channel, if empty) so the UI can verify webhook/email credentials.
// Returns ok=false with per-channel errors if alerting isn't wired up or any
// channel failed.
func (s *ConfigService) SendTestAlert(channels []string) (ok bool, errs map[string]string) {
	if s.alerts == nil {
		return false, map[string]string{"_": "alerts are not enabled on this agent"}
	}
	failed := s.alerts.SendTest(channels)
	if len(failed) == 0 {
		return true, nil
	}
	out := make(map[string]string, len(failed))
	for ch, err := range failed {
		out[ch] = err.Error()
	}
	return false, out
}

// TestLogResult reports whether a candidate log path is usable.
type TestLogResult struct {
	Readable bool       `json:"readable"`
	Error    string     `json:"error,omitempty"`
	Lines    int        `json:"lines"`
	ParseOK  bool       `json:"parse_ok"`
	Earliest *time.Time `json:"earliest,omitempty"`
	Latest   *time.Time `json:"latest,omitempty"`
	Sample   []string   `json:"sample,omitempty"`
}

// TestLog inspects a path so the UI can confirm it before saving: readable?,
// line count, first/last timestamp, and whether lines parse as nginx-combined.
func TestLog(path string) TestLogResult {
	f, err := os.Open(path)
	if err != nil {
		return TestLogResult{Readable: false, Error: friendlyErr(err)}
	}
	defer f.Close()

	res := TestLogResult{Readable: true}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var first, last time.Time
	for sc.Scan() {
		line := sc.Text()
		res.Lines++
		if len(res.Sample) < 3 {
			res.Sample = append(res.Sample, line)
		}
		if rec, ok := analytics.Parse(line, ""); ok {
			res.ParseOK = true
			if first.IsZero() {
				first = rec.Time
			}
			last = rec.Time
		}
	}
	if !first.IsZero() {
		res.Earliest, res.Latest = &first, &last
	}
	return res
}

// PreviewRoute shows how a path would be grouped under the given draft patterns,
// so the UI can make URL templating tangible before saving.
func PreviewRoute(path string, patterns []string) string {
	return analytics.NewNormalizer(patterns).Normalize(path)
}

func friendlyErr(err error) string {
	switch {
	case os.IsNotExist(err):
		return "file not found at that path"
	case os.IsPermission(err):
		return "permission denied — the agent can't read this file (try adding it to the 'adm' group)"
	default:
		return err.Error()
	}
}
