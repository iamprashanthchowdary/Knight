// Command knight is the observe-and-inform traffic agent. It tails one or more
// nginx access logs, turns every request into traffic statistics
// (status-code breakdowns, per-IP behaviour, per-endpoint health), and serves
// them as a read-only JSON API for a dashboard. It never blocks or bans -- it
// only watches and reports.
//
// The attack-detection engine (engine/, guard/, sentinel/, server/) is parked
// in the tree for a later layer and is intentionally not wired here.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"knight/internal/alerts"
	"knight/internal/analytics"
	"knight/internal/analytics/api"
	"knight/internal/config"
)

func main() {
	cfgPath := flag.String("config", "config.json", "path to config file")
	fromStart := flag.Bool("from-start", false, "read existing log files from the beginning (for checking a file you already have) instead of only new lines")
	sinceStr := flag.String("since", "", "only ingest requests at/after this time, e.g. \"15/07/2026:00:00:14\" (dd/mm/yyyy:hh:mm:ss); implies -from-start and keeps historical data")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("load config", "err", err)
		os.Exit(1)
	}

	var since time.Time
	if *sinceStr != "" {
		since, err = parseSince(*sinceStr)
		if err != nil {
			log.Error("invalid -since value", "value", *sinceStr, "err", err)
			os.Exit(1)
		}
		*fromStart = true // must read history to reach the start point
		log.Info("replaying from timestamp", "since", since.Format(time.RFC3339))
	}

	store := analytics.NewStore(cfg.AnalyticsRetention())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Manager owns the tailers + normalizer and supports hot reload. The initial
	// Apply starts tailers from the configured sites (using the CLI ingestion
	// flags); later edits via the config API re-Apply live.
	mgr := analytics.NewManager(ctx, store, log, *fromStart, since)
	specs := make([]analytics.SiteSpec, 0, len(cfg.Sites))
	for _, s := range cfg.Sites {
		specs = append(specs, analytics.SiteSpec{Name: s.Name, AccessLog: s.AccessLog})
	}
	mgr.Bootstrap(specs, cfg.Analytics.RoutePatterns)
	if len(cfg.Sites) == 0 {
		log.Warn("no sites configured yet — add one via the config page or config.json")
	}

	// Periodic eviction keeps memory bounded to the retention window in LIVE
	// mode. Skip it entirely during any historical replay (-from-start or
	// -since): that data is intentionally old and would otherwise be evicted for
	// being older than the retention window, leaving only the last window's worth
	// (e.g. just access.log.1).
	historical := *fromStart || !since.IsZero()
	if !historical {
		go func() {
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case now := <-ticker.C:
					store.Evict(now)
				}
			}
		}()
	}

	// Alerts are LIVE-only: evaluating threshold/anomaly rules against a
	// historical replay would fire notifications for events that happened days
	// ago the moment the agent starts. The engine is still constructed (and
	// wired into the config API) during a replay so config edits and test-sends
	// work, but Run() -- the periodic rule evaluator -- is never started.
	alertsEngine := alerts.NewEngine(cfg.Alerts, store, log)
	if !historical {
		go alertsEngine.Run(ctx, func() []string { return store.Overview().Sites })
	} else {
		log.Info("historical replay: alert rule evaluation is disabled")
	}

	cfgSvc := api.NewConfigService(*cfgPath, cfg, mgr, store, alertsEngine)

	apiSrv := &http.Server{
		Addr:              cfg.Analytics.APIListen,
		Handler:           api.New(store, cfgSvc, log).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := apiSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("api server", "err", err)
			stop()
		}
	}()
	log.Info("knight observe agent started",
		"api", cfg.Analytics.APIListen,
		"sites", len(cfg.Sites),
		"retention", cfg.AnalyticsRetention().String())

	<-ctx.Done()
	log.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = apiSrv.Shutdown(shutCtx)
}

// parseSince accepts the nginx access-log timestamp form (with or without a
// timezone), plus common ISO forms. Values without a timezone are interpreted
// in the server's local time.
func parseSince(s string) (time.Time, error) {
	withTZ := []string{
		"02/01/2006:15:04:05 -0700", // dd/mm/yyyy:hh:mm:ss +zone
		"02/Jan/2006:15:04:05 -0700", // nginx log form
		time.RFC3339,
	}
	for _, l := range withTZ {
		if t, err := time.Parse(l, s); err == nil {
			return t, nil
		}
	}
	noTZ := []string{
		"02/01/2006:15:04:05", // dd/mm/yyyy:hh:mm:ss  <- preferred
		"02/01/2006",          // dd/mm/yyyy
		"02/Jan/2006:15:04:05",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, l := range noTZ {
		if t, err := time.ParseInLocation(l, s, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized time format")
}
