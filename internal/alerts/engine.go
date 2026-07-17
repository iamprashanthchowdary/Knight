package alerts

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"knight/internal/analytics"
	"knight/internal/config"
)

// Engine periodically evaluates threshold rules and the anomaly detector
// against the Store, and dispatches any firing Alert to the configured
// notifiers. Evaluation is anchored to the Store's latest ingested data
// timestamp, not wall-clock -- but the caller is responsible for only running
// Engine.Run in live mode (see package doc and cmd/knight).
type Engine struct {
	mu        sync.Mutex
	rules     []config.AlertRule
	notifiers map[string]Notifier // channel name -> notifier
	anomaly   *AnomalyDetector

	store     *analytics.Store
	log       *slog.Logger
	cooldowns map[string]time.Time // rule id + scope key -> last fired (tick-goroutine only)
}

// NewEngine builds an Engine from config. Call Reload to apply config edits
// without restarting.
func NewEngine(cfg config.AlertsConfig, store *analytics.Store, log *slog.Logger) *Engine {
	e := &Engine{
		store:     store,
		log:       log,
		cooldowns: make(map[string]time.Time),
	}
	e.Reload(cfg)
	return e
}

// Reload swaps in a new rule set, notifier configuration, and anomaly
// detector. Safe to call from a different goroutine than Run (e.g. the config
// HTTP handler) while Run's ticker is active.
func (e *Engine) Reload(cfg config.AlertsConfig) {
	notifiers := make(map[string]Notifier)
	if cfg.Webhook.Enabled && cfg.Webhook.URL != "" {
		notifiers["webhook"] = NewWebhookNotifier(cfg.Webhook.URL, cfg.Webhook.Secret)
	}
	if cfg.Email.Enabled && cfg.Email.SMTPHost != "" {
		notifiers["email"] = NewEmailNotifier(cfg.Email.SMTPHost, cfg.Email.SMTPPort,
			cfg.Email.Username, cfg.Email.Password, cfg.Email.From, cfg.Email.To)
	}
	anomaly := NewAnomalyDetector(cfg.Anomaly, e.store)

	e.mu.Lock()
	e.rules = cfg.Rules
	e.notifiers = notifiers
	e.anomaly = anomaly
	e.mu.Unlock()
}

// Run evaluates rules once a minute until ctx is cancelled. sites is called on
// every tick so a hot-reloaded site list is picked up automatically.
func (e *Engine) Run(ctx context.Context, sites func() []string) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.tick(sites())
		}
	}
}

func (e *Engine) tick(sites []string) {
	now := e.store.LatestDataTime()
	if now.IsZero() {
		return
	}

	e.mu.Lock()
	rules := e.rules
	anomaly := e.anomaly
	e.mu.Unlock()

	var firing []Alert
	for _, r := range rules {
		if a, ok := e.evalRule(r, now); ok {
			firing = append(firing, a)
		}
	}
	firing = append(firing, anomaly.Evaluate(sites, now)...)

	for _, a := range firing {
		e.dispatch(a)
	}
}

func (e *Engine) evalRule(r config.AlertRule, now time.Time) (Alert, bool) {
	window := r.WindowDuration()
	cooldown := r.CooldownDuration()

	switch r.Metric {
	case "status_count":
		if len(r.StatusClasses) == 0 {
			return Alert{}, false // validated at config-save time; defensive here
		}
		matched, _ := e.store.WindowStatusCount(r.Site, r.StatusClasses, window, now)
		if matched < r.Threshold {
			return Alert{}, false
		}
		if !e.armed(r.ID+"\x00"+r.Site, cooldown, now) {
			return Alert{}, false
		}
		return Alert{
			ID: r.ID, Kind: "threshold", Site: r.Site, Metric: "status_count",
			Value: float64(matched), Threshold: float64(r.Threshold), Window: r.Window,
			Message: fmt.Sprintf("%s: %d matching requests in %s (threshold %d)%s",
				r.ID, matched, r.Window, r.Threshold, siteSuffix(r.Site)),
			Time: now, Channels: r.Channels,
		}, true

	case "ip_request_count":
		counts := e.store.WindowIPCounts(window, now)
		var worstIP string
		var worst int64
		for ip, c := range counts {
			if c > worst {
				worst, worstIP = c, ip
			}
		}
		if worst < r.Threshold {
			return Alert{}, false
		}
		if !e.armed(r.ID+"\x00"+worstIP, cooldown, now) {
			return Alert{}, false
		}
		return Alert{
			ID: r.ID, Kind: "threshold", Metric: "ip_request_count",
			Value: float64(worst), Threshold: float64(r.Threshold), Window: r.Window,
			Message: fmt.Sprintf("%s: IP %s made %d requests in %s (threshold %d)",
				r.ID, worstIP, worst, r.Window, r.Threshold),
			Time: now, Channels: r.Channels,
		}, true

	default:
		return Alert{}, false
	}
}

// armed reports whether a rule+scope is out of cooldown, and if so starts a new
// cooldown period. Only ever called from the single tick() goroutine, so the
// map needs no separate lock.
func (e *Engine) armed(key string, cooldown time.Duration, now time.Time) bool {
	if last, ok := e.cooldowns[key]; ok && now.Sub(last) < cooldown {
		return false
	}
	e.cooldowns[key] = now
	return true
}

func (e *Engine) dispatch(a Alert) {
	e.mu.Lock()
	notifiers := e.notifiers
	e.mu.Unlock()

	targets := notifiers
	if len(a.Channels) > 0 {
		targets = make(map[string]Notifier, len(a.Channels))
		for _, c := range a.Channels {
			if n, ok := notifiers[c]; ok {
				targets[c] = n
			}
		}
	}
	for name, n := range targets {
		if err := n.Notify(a); err != nil {
			e.log.Error("alert delivery failed", "channel", name, "alert", a.ID, "err", err)
			continue
		}
		e.log.Info("alert delivered", "channel", name, "alert", a.ID, "site", a.Site, "message", a.Message)
	}
}

// SendTest delivers a synthetic alert to the given channels (or every enabled
// channel, if empty), so a user can verify webhook/email credentials before
// relying on them. Returns one error per channel that failed.
func (e *Engine) SendTest(channels []string) map[string]error {
	e.mu.Lock()
	notifiers := e.notifiers
	e.mu.Unlock()

	targets := notifiers
	if len(channels) > 0 {
		targets = make(map[string]Notifier, len(channels))
		for _, c := range channels {
			if n, ok := notifiers[c]; ok {
				targets[c] = n
			}
		}
	}
	a := Alert{
		ID: "test", Kind: "test", Metric: "test",
		Message: "Knight test alert — if you received this, notifications are working.",
		Time:    time.Now(),
	}
	errs := make(map[string]error)
	for name, n := range targets {
		if err := n.Notify(a); err != nil {
			errs[name] = err
		}
	}
	return errs
}

func siteSuffix(site string) string {
	if site == "" {
		return ""
	}
	return " on " + site
}
