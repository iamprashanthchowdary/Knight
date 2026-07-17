// Package config loads Knight's runtime configuration from a JSON file.
// JSON (not YAML) keeps Knight a zero-dependency, single static binary that
// drops onto a bastion with nothing to install but the binary itself.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Mode controls whether Knight enforces verdicts or only records them.
type Mode string

const (
	// ModeEnforce actually blocks/ bans. Use once you trust the ruleset.
	ModeEnforce Mode = "enforce"
	// ModeObserve logs what WOULD have happened but always allows. Use this to
	// roll out safely and tune away false positives first.
	ModeObserve Mode = "observe"
)

// Config is the top-level configuration.
type Config struct {
	// Listen is the address Knight's decision API binds to, e.g. "127.0.0.1:8088".
	Listen string `json:"listen"`
	// RulesPath is the JSON ruleset file.
	RulesPath string `json:"rules_path"`
	// Mode is "enforce" or "observe".
	Mode Mode `json:"mode"`
	// AnomalyThreshold: total rule score at or above which a request is blocked.
	AnomalyThreshold int `json:"anomaly_threshold"`

	Ban       BanConfig       `json:"ban"`
	RateLimit RateLimitConfig `json:"rate_limit"`
	Observer  ObserverConfig  `json:"observer"`
	Sentinel  SentinelConfig  `json:"sentinel"`

	// Sites are the nginx access logs to observe. Each entry is one server
	// block / vhost with its own log path.
	Sites []SiteConfig `json:"sites"`
	// Analytics is the observe-and-inform traffic layer.
	Analytics AnalyticsConfig `json:"analytics"`
	// Alerts is the outbound notification layer (webhook/email on threshold or
	// automatic anomaly triggers).
	Alerts AlertsConfig `json:"alerts"`
	// Auth controls who can read vs write the API. Not part of Editable: it is
	// never rewritten by a PUT /v1/config from the dashboard, so a stale
	// frontend payload can never accidentally blank out or overwrite tokens.
	Auth AuthConfig `json:"auth"`

	viewerTokenGenerated bool // set by Load if AuthConfig.ViewerToken was empty and freshly generated
	adminTokenGenerated  bool // set by Load if AuthConfig.AdminToken was empty and freshly generated
}

// AuthConfig gates the analytics API with two bearer tokens:
//
//	ViewerToken — read-only: dashboard viewing (overview, endpoints, ips, reports).
//	AdminToken  — read + write: viewer routes, plus GET/PUT /v1/config,
//	              /v1/config/*, and /v1/alerts/test. GET /v1/config is
//	              admin-only because the config itself contains secrets
//	              (webhook secret, SMTP password).
//
// If a token is empty, Load auto-generates and persists a random one on first
// boot -- the API defaults to secured, not open, even if nobody sets a token
// by hand. Send the token as "Authorization: Bearer <token>", never as a query
// parameter (query strings end up in nginx's own access log, which would leak
// the token right back into the very logs Knight reads).
type AuthConfig struct {
	ViewerToken string `json:"viewer_token"`
	AdminToken  string `json:"admin_token"`
}

// TokensGenerated reports whether either token was freshly auto-generated on
// this Load call, so the caller can print them once at startup.
func (c *Config) TokensGenerated() (viewer, admin bool) {
	return c.viewerTokenGenerated, c.adminTokenGenerated
}

// AlertsConfig controls outbound notifications. It is a LIVE-only feature: the
// agent only evaluates rules while tailing real-time traffic, never during a
// historical/-from-start replay (see cmd/knight), so replaying old logs never
// fires alerts about events that happened days ago.
type AlertsConfig struct {
	Enabled bool          `json:"enabled"`
	Rules   []AlertRule   `json:"rules"`
	Anomaly AnomalyConfig `json:"anomaly"`
	Webhook WebhookConfig `json:"webhook"`
	Email   EmailConfig   `json:"email"`
}

// AlertRule is a user-defined threshold: "in <window>, if <metric> crosses
// <threshold>, notify." Two metrics are supported:
//
//	status_count      — count of requests whose status falls in StatusClasses
//	                     (e.g. [5] for 5xx) within Window, optionally scoped to
//	                     one Site ("" = all sites combined).
//	ip_request_count  — fires when ANY single IP makes >= Threshold requests
//	                     within Window (a flood/scanner signal). Site is ignored.
type AlertRule struct {
	ID            string   `json:"id"`
	Metric        string   `json:"metric"` // "status_count" | "ip_request_count"
	StatusClasses []int    `json:"status_classes,omitempty"`
	Site          string   `json:"site,omitempty"` // empty = all sites combined
	Window        string   `json:"window"`         // Go duration, e.g. "2m"
	Threshold     int64    `json:"threshold"`
	Cooldown      string   `json:"cooldown,omitempty"` // default 10m; suppresses repeat-fires
	Channels      []string `json:"channels,omitempty"` // "webhook"/"email"; empty = all enabled
}

// WindowDuration parses Window, defaulting to 1 minute.
func (r AlertRule) WindowDuration() time.Duration { return parseDur(r.Window, time.Minute) }

// CooldownDuration parses Cooldown, defaulting to 10 minutes.
func (r AlertRule) CooldownDuration() time.Duration { return parseDur(r.Cooldown, 10*time.Minute) }

// AnomalyConfig is the automatic 4xx/5xx spike detector: no manual threshold to
// tune. It compares a short recent window against each site's own rolling
// baseline (mean + Sensitivity*stddev), so a site that normally runs 3% 4xx
// doesn't fire at 4%, while a site that normally runs 0.1% fires at 1%.
// MinSamples and MinRateFloor exist specifically to prevent false alarms on
// low-traffic windows, where a handful of errors would otherwise look huge as
// a percentage.
type AnomalyConfig struct {
	Enabled bool `json:"enabled"`
	// BaselineWindow: how much trailing history establishes "normal". Default 60m.
	BaselineWindow string `json:"baseline_window,omitempty"`
	// EvalWindow: the recent window checked against the baseline. Default 2m.
	EvalWindow string `json:"eval_window,omitempty"`
	// MinSamples: eval window must have at least this many requests before the
	// detector will consider firing (guards against tiny-sample noise). Default 20.
	MinSamples int64 `json:"min_samples,omitempty"`
	// Sensitivity: k in mean + k*stddev. Higher = fewer, more confident alerts.
	// Default 3.0 (roughly a 99.7%-confidence outlier under a normal approximation).
	Sensitivity float64 `json:"sensitivity,omitempty"`
	// MinRateFloor: absolute minimum error rate before an alert is worth sending,
	// even if it's statistically an outlier. Default 0.02 (2%).
	MinRateFloor float64 `json:"min_rate_floor,omitempty"`
	// Cooldown: minimum time between repeat fires for the same site+class. Default 15m.
	Cooldown string `json:"cooldown,omitempty"`
}

func (a AnomalyConfig) BaselineDuration() time.Duration { return parseDur(a.BaselineWindow, 60*time.Minute) }
func (a AnomalyConfig) EvalDuration() time.Duration      { return parseDur(a.EvalWindow, 2*time.Minute) }
func (a AnomalyConfig) CooldownDuration() time.Duration  { return parseDur(a.Cooldown, 15*time.Minute) }

func (a AnomalyConfig) MinSamplesOrDefault() int64 {
	if a.MinSamples <= 0 {
		return 20
	}
	return a.MinSamples
}

func (a AnomalyConfig) SensitivityOrDefault() float64 {
	if a.Sensitivity <= 0 {
		return 3.0
	}
	return a.Sensitivity
}

func (a AnomalyConfig) MinRateFloorOrDefault() float64 {
	if a.MinRateFloor <= 0 {
		return 0.02
	}
	return a.MinRateFloor
}

// WebhookConfig sends alerts as an HTTPS POST of JSON. If Secret is set, the
// body is HMAC-SHA256 signed and sent as X-Knight-Signature so the receiver can
// verify the request actually came from this agent.
type WebhookConfig struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`
	Secret  string `json:"secret,omitempty"`
}

// EmailConfig sends alerts via an SMTP relay (your own server, SES SMTP,
// SendGrid SMTP, Gmail app-password, etc).
type EmailConfig struct {
	Enabled  bool     `json:"enabled"`
	SMTPHost string   `json:"smtp_host"`
	SMTPPort int      `json:"smtp_port"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	From     string   `json:"from"`
	To       []string `json:"to"`
}

// SiteConfig is one nginx access log to tail, labelled with a site name that
// tags every event and stat it produces.
type SiteConfig struct {
	Name string `json:"name"`
	// AccessLog is the path to this site's nginx access log.
	AccessLog string `json:"access_log"`
}

// AnalyticsConfig controls the traffic-analytics observe layer.
type AnalyticsConfig struct {
	Enabled bool `json:"enabled"`
	// APIListen is where the read-only JSON API for the frontend binds,
	// e.g. "127.0.0.1:8090".
	APIListen string `json:"api_listen"`
	// Retention is how long time-series buckets and idle IPs are kept, e.g. "24h".
	Retention string `json:"retention"`
	// RoutePatterns are optional endpoint templates that override the automatic
	// URL grouping, e.g. "/api/users/:id/orders/:orderId". First match wins.
	RoutePatterns []string `json:"route_patterns"`
}

// SentinelConfig arms trap ports against port scanners: any completed TCP
// connection to one of these ports bans the source IP (see internal/sentinel).
type SentinelConfig struct {
	Enabled   bool  `json:"enabled"`
	TrapPorts []int `json:"trap_ports"`
	// BanDuration for scan offenders, e.g. "24h". Empty = the global ban duration.
	BanDuration string `json:"ban_duration"`
}

// BanConfig controls how long offenders stay on the blocklist and how bans are
// mirrored into the kernel firewall.
type BanConfig struct {
	// Duration is a Go duration string, e.g. "15m", "1h".
	Duration string `json:"duration"`
	// BanCommand / UnbanCommand are optional external hooks run when an IP is
	// banned/unbanned; the token {ip} is substituted. Point them at an nftables
	// set (deploy/nftables.conf.example) to drop offenders at the kernel.
	BanCommand   []string `json:"ban_command,omitempty"`
	UnbanCommand []string `json:"unban_command,omitempty"`
}

// RateLimitConfig is the per-IP token bucket.
type RateLimitConfig struct {
	RequestsPerSecond float64 `json:"requests_per_second"` // 0 disables
	Burst             float64 `json:"burst"`
}

// ObserverConfig controls the out-of-band nginx log tailer.
type ObserverConfig struct {
	Enabled bool `json:"enabled"`
	// AccessLog is the nginx access log path to tail.
	AccessLog string `json:"access_log"`
	// BlockThreshold: anomaly score seen in a log line that triggers a ban.
	BlockThreshold int `json:"block_threshold"`
}

// BanDuration parses Ban.Duration, defaulting to 15 minutes.
func (c *Config) BanDuration() time.Duration {
	return parseDur(c.Ban.Duration, 15*time.Minute)
}

// SentinelBanDuration parses Sentinel.BanDuration, falling back to the global
// ban duration. Port scanning is unambiguous hostility, so configs typically
// set this much longer (e.g. "24h").
func (c *Config) SentinelBanDuration() time.Duration {
	return parseDur(c.Sentinel.BanDuration, c.BanDuration())
}

// AnalyticsRetention parses Analytics.Retention, defaulting to 24 hours.
func (c *Config) AnalyticsRetention() time.Duration {
	return parseDur(c.Analytics.Retention, 24*time.Hour)
}

func parseDur(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

// Editable is the subset of config the observe agent's UI/CLI can change. The
// rest of Config (parked WAF fields) is preserved untouched on save.
type Editable struct {
	Sites     []SiteConfig    `json:"sites"`
	Analytics AnalyticsConfig `json:"analytics"`
	Alerts    AlertsConfig    `json:"alerts"`
}

// Editable returns the currently editable subset.
func (c *Config) Editable() Editable {
	return Editable{Sites: c.Sites, Analytics: c.Analytics, Alerts: c.Alerts}
}

// SetEditable overwrites the editable subset, leaving all other fields intact.
func (c *Config) SetEditable(e Editable) {
	c.Sites = e.Sites
	c.Analytics = e.Analytics
	c.Alerts = e.Alerts
	normalizeNilSlices(c)
}

// Save writes the full config back to path atomically (temp file + rename) so a
// crash mid-write can never leave a truncated config.
func (c *Config) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Load reads, parses and defaults a config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8088"
	}
	if c.RulesPath == "" {
		c.RulesPath = "rules/signatures.json"
	}
	if c.Mode != ModeEnforce && c.Mode != ModeObserve {
		c.Mode = ModeObserve // safe default
	}
	if c.AnomalyThreshold <= 0 {
		c.AnomalyThreshold = 10
	}
	if c.Analytics.APIListen == "" {
		c.Analytics.APIListen = "127.0.0.1:8090"
	}
	normalizeNilSlices(&c)

	// Secure by default: generate + persist tokens on first boot (or upgrade
	// from a version that predates auth) rather than leaving the API open
	// until someone remembers to configure it.
	changed := false
	if c.Auth.ViewerToken == "" {
		t, err := generateToken()
		if err != nil {
			return nil, fmt.Errorf("generate viewer token: %w", err)
		}
		c.Auth.ViewerToken = t
		c.viewerTokenGenerated = true
		changed = true
	}
	if c.Auth.AdminToken == "" {
		t, err := generateToken()
		if err != nil {
			return nil, fmt.Errorf("generate admin token: %w", err)
		}
		c.Auth.AdminToken = t
		c.adminTokenGenerated = true
		changed = true
	}
	if changed {
		if err := c.Save(path); err != nil {
			return nil, fmt.Errorf("persist generated auth tokens: %w", err)
		}
	}

	return &c, nil
}

// generateToken returns a random 32-byte token, hex-encoded.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// normalizeNilSlices replaces nil slices with empty ones so the JSON API
// always emits [] rather than null for list fields. This keeps the FE's
// TypeScript types (which declare these as plain arrays) safe to .map()/.length
// without defensive null-guards scattered through the UI.
func normalizeNilSlices(c *Config) {
	if c.Sites == nil {
		c.Sites = []SiteConfig{}
	}
	if c.Analytics.RoutePatterns == nil {
		c.Analytics.RoutePatterns = []string{}
	}
	if c.Alerts.Rules == nil {
		c.Alerts.Rules = []AlertRule{}
	}
	for i := range c.Alerts.Rules {
		if c.Alerts.Rules[i].StatusClasses == nil {
			c.Alerts.Rules[i].StatusClasses = []int{}
		}
		if c.Alerts.Rules[i].Channels == nil {
			c.Alerts.Rules[i].Channels = []string{}
		}
	}
	if c.Alerts.Email.To == nil {
		c.Alerts.Email.To = []string{}
	}
}
