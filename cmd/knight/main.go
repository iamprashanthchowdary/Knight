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

// version and commit are overridden at build time via:
//
//	go build -ldflags "-X main.version=1.0.0 -X main.commit=$(git rev-parse --short HEAD)"
//
// Unset (plain `go build`) yields "dev" / "unknown", which is fine for local
// development builds.
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	// A bare `knight version` (or -version/--version) prints and exits BEFORE
	// touching config -- it must work even when no config.json exists yet,
	// e.g. right after copying the binary onto a fresh host.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "-version", "--version":
			fmt.Printf("knight %s (%s)\n", version, commit)
			return
		case "key-gen":
			runKeyGen(os.Args[2:])
			return
		}
	}

	cfgPath := flag.String("config", "config.json", "path to config file")
	fromStart := flag.Bool("from-start", false, "read existing log files from the beginning (for checking a file you already have) instead of only new lines")
	sinceStr := flag.String("since", "", "only ingest requests at/after this time, e.g. \"15/07/2026:00:00:14\" (dd/mm/yyyy:hh:mm:ss); implies -from-start and keeps historical data")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Error("config file not found",
				"path", *cfgPath,
				"hint", "create it, or point at one with -config /path/to/config.json")
		} else {
			log.Error("load config", "err", err)
		}
		os.Exit(1)
	}
	if viewerGen, adminGen := cfg.TokensGenerated(); viewerGen || adminGen {
		log.Warn("generated new API auth token(s) — copy these now, saved to config.json",
			"viewer_token", cfg.Auth.ViewerToken, "admin_token", cfg.Auth.AdminToken)
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
	// historical mode (-from-start/-since) is a deliberate, separate, one-shot
	// ad-hoc replay flow: no persistence, no live tail afterward. Everything
	// below in this block only applies to the default always-on-service path.
	historical := *fromStart || !since.IsZero()

	store := analytics.NewStore(cfg.AnalyticsRetention())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Persistence: on a warm restart, load the last checkpoint instead of
	// reprocessing the whole retention window from disk. Snapshot (the computed
	// Store) and Positions (each tailer's exact resume byte) are trusted only as
	// a matching pair -- see their SavedAt comparison below -- so a crash between
	// the two writes, or an old/missing file, safely falls back to a cold start
	// rather than silently restoring mismatched state.
	stateDir := cfg.StateDir()
	snapPath := analytics.SnapshotPath(stateDir)
	posPath := analytics.PositionsPath(stateDir)
	pos := analytics.Positions{}
	if !historical {
		if err := os.MkdirAll(stateDir, 0o750); err != nil {
			log.Warn("cannot create state dir; persistence disabled this run", "dir", stateDir, "err", err)
		} else if snap, snapErr := analytics.LoadSnapshot(snapPath); snapErr == nil {
			if loadedPos, posErr := analytics.LoadPositions(posPath); posErr == nil && loadedPos.SavedAt.Equal(snap.SavedAt) {
				store.Restore(snap)
				pos = loadedPos
				log.Info("restored analytics state from checkpoint",
					"saved_at", snap.SavedAt.Format(time.RFC3339), "total_requests", store.Overview().Total)
			} else {
				log.Warn("snapshot/positions checkpoint mismatched or incomplete; starting cold",
					"snapshot_saved_at", snap.SavedAt.Format(time.RFC3339))
			}
		}
	}

	// Manager owns the tailers + normalizer and supports hot reload. The initial
	// bootstrap starts tailers from the configured sites; later edits via the
	// config API re-Apply live.
	mgr := analytics.NewManager(ctx, store, log, *fromStart, since)
	specs := make([]analytics.SiteSpec, 0, len(cfg.Sites))
	for _, s := range cfg.Sites {
		specs = append(specs, analytics.SiteSpec{Name: s.Name, AccessLog: s.AccessLog})
	}
	if historical {
		mgr.Bootstrap(specs, cfg.Analytics.RoutePatterns, cfg.Analytics.IgnorePaths)
	} else {
		// Sites with a saved position resume exactly where they left off
		// (cheap); anything else (a true first-ever start, or a site added
		// since the last checkpoint) gets one bounded historical read covering
		// the configured retention window, then hands off to live tailing with
		// no gap -- see Manager.BootstrapWithHistory.
		mgr.BootstrapWithHistory(specs, cfg.Analytics.RoutePatterns, cfg.Analytics.IgnorePaths, time.Now().Add(-cfg.AnalyticsRetention()), pos)
	}
	if len(cfg.Sites) == 0 {
		log.Warn("no sites configured yet — add one via the config page or config.json")
	}

	// Periodic eviction keeps memory bounded to the retention window in LIVE
	// mode. Skip it entirely during any historical replay (-from-start or
	// -since): that data is intentionally old and would otherwise be evicted for
	// being older than the retention window, leaving only the last window's worth
	// (e.g. just access.log.1).
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

	// persistCheckpoint captures the Store BEFORE the tailer positions, every
	// call: Tailer.drain always does its Store.Add calls before updating its
	// own position (same goroutine, program order), so this ordering biases any
	// race toward a tiny, safe undercount on restore (a handful of requests
	// re-read as "new" next boot) rather than a duplicate/inflated count.
	persistCheckpoint := func() {
		now := time.Now()
		snap := store.Snapshot()
		snap.SavedAt = now
		if err := analytics.SaveSnapshot(snapPath, snap); err != nil {
			log.Warn("persist analytics snapshot", "err", err)
			return
		}
		p := mgr.Positions()
		p.SavedAt = now
		if err := analytics.SavePositions(posPath, p); err != nil {
			log.Warn("persist tailer positions", "err", err)
		}
	}
	if !historical {
		go func() {
			ticker := time.NewTicker(cfg.SnapshotInterval())
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					persistCheckpoint()
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

	auth := api.NewAuth(cfg.Auth.ViewerToken, cfg.Auth.AdminToken)
	cfgSvc := api.NewConfigService(*cfgPath, cfg, mgr, store, alertsEngine, auth)

	apiSrv := &http.Server{
		Addr:              cfg.Analytics.APIListen,
		Handler:           api.New(store, cfgSvc, auth, api.AgentInfo{Version: version, Commit: commit}, log).Handler(),
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
	if !historical {
		// Final synchronous checkpoint: a clean stop/restart (systemctl
		// restart, a deploy, SIGTERM) loses ~nothing. Only an unclean kill -9
		// loses up to one snapshot-interval's worth of data.
		persistCheckpoint()
	}
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

// runKeyGen implements `knight key-gen [-config path] admin|viewer`: a
// one-shot maintenance command for when a token is lost and there's no
// running dashboard session to rotate it from (see POST /v1/auth/rotate for
// the live-API equivalent, which additionally updates the already-running
// process without a restart). This command only edits config.json on disk --
// a separately running knight process keeps its old token in memory until
// restarted, which is why the printed reminder below matters.
func runKeyGen(args []string) {
	fs := flag.NewFlagSet("key-gen", flag.ExitOnError)
	cfgPath := fs.String("config", "config.json", "path to config file")
	fs.Parse(args)

	rest := fs.Args()
	if len(rest) != 1 || (rest[0] != "admin" && rest[0] != "viewer") {
		fmt.Fprintln(os.Stderr, "usage: knight key-gen [-config path] admin|viewer")
		os.Exit(2)
	}
	which := rest[0]

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config %s: %v\n", *cfgPath, err)
		os.Exit(1)
	}
	token, err := config.GenerateToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate token: %v\n", err)
		os.Exit(1)
	}
	if which == "admin" {
		cfg.Auth.AdminToken = token
	} else {
		cfg.Auth.ViewerToken = token
	}
	if err := cfg.Save(*cfgPath); err != nil {
		fmt.Fprintf(os.Stderr, "save config %s: %v\n", *cfgPath, err)
		os.Exit(1)
	}

	fmt.Printf("new %s token: %s\n", which, token)
	fmt.Println("Restart knight for this to take effect (a running process keeps its old token in memory until restarted), or rotate it live instead from the dashboard's Profile page.")
}
