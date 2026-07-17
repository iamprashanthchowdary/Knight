package alerts

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"knight/internal/analytics"
	"knight/internal/config"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func addN(store *analytics.Store, site, ip string, status int, t time.Time, n int) {
	for i := 0; i < n; i++ {
		store.Add(analytics.Record{Time: t, Site: site, IP: ip, Method: "GET", Path: "/x", Status: status}, "/x")
	}
}

func TestEngineStatusCountRule(t *testing.T) {
	store := analytics.NewStore(time.Hour)
	base := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)

	addN(store, "site", "1.1.1.1", 500, base, 4) // below threshold of 5

	rule := config.AlertRule{ID: "high-5xx", Metric: "status_count", StatusClasses: []int{5}, Window: "2m", Threshold: 5, Cooldown: "1m"}
	e := NewEngine(config.AlertsConfig{Rules: []config.AlertRule{rule}}, store, testLogger())

	if a, ok := e.evalRule(rule, base); ok {
		t.Fatalf("rule should not fire below threshold, got %+v", a)
	}

	addN(store, "site", "1.1.1.1", 500, base, 1) // now 5 total, crosses threshold
	a, ok := e.evalRule(rule, base)
	if !ok {
		t.Fatal("expected rule to fire at threshold")
	}
	if a.Value != 5 {
		t.Errorf("value = %v, want 5", a.Value)
	}

	if _, ok := e.evalRule(rule, base); ok {
		t.Fatal("expected cooldown to suppress an immediate re-fire")
	}
}

func TestEngineIPFloodRule(t *testing.T) {
	store := analytics.NewStore(time.Hour)
	base := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	addN(store, "site", "9.9.9.9", 200, base, 150)

	rule := config.AlertRule{ID: "flood", Metric: "ip_request_count", Window: "1m", Threshold: 100, Cooldown: "1m"}
	e := NewEngine(config.AlertsConfig{Rules: []config.AlertRule{rule}}, store, testLogger())

	a, ok := e.evalRule(rule, base)
	if !ok {
		t.Fatal("expected flood rule to fire")
	}
	if a.Value != 150 {
		t.Errorf("value = %v, want 150", a.Value)
	}
}

func TestAnomalyDetectorNoFalseAlarmOnStableTraffic(t *testing.T) {
	store := analytics.NewStore(3 * time.Hour)
	base := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)

	// 60 minutes of stable ~2% error rate baseline.
	for m := 0; m < 60; m++ {
		ts := base.Add(-time.Duration(60-m) * time.Minute)
		addN(store, "site", "1.1.1.1", 200, ts, 98)
		addN(store, "site", "1.1.1.1", 500, ts, 2)
	}
	// Eval window: same ~2% rate -- must NOT fire.
	addN(store, "site", "1.1.1.1", 200, base, 98)
	addN(store, "site", "1.1.1.1", 500, base, 2)

	d := NewAnomalyDetector(config.AnomalyConfig{Enabled: true, MinSamples: 20, Sensitivity: 3, MinRateFloor: 0.01}, store)
	for _, a := range d.Evaluate([]string{"site"}, base) {
		if a.Site == "site" && a.Metric == "5xx_rate" {
			t.Fatalf("expected no false alarm on stable traffic, got %+v", a)
		}
	}
}

func TestAnomalyDetectorFiresOnRealSpike(t *testing.T) {
	store := analytics.NewStore(3 * time.Hour)
	base := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)

	// 60 minutes of stable ~1% error rate baseline.
	for m := 0; m < 60; m++ {
		ts := base.Add(-time.Duration(60-m) * time.Minute)
		addN(store, "site", "1.1.1.1", 200, ts, 99)
		addN(store, "site", "1.1.1.1", 500, ts, 1)
	}
	// Eval window: sudden jump to 40% 5xx -- must fire.
	addN(store, "site", "1.1.1.1", 200, base, 60)
	addN(store, "site", "1.1.1.1", 500, base, 40)

	d := NewAnomalyDetector(config.AnomalyConfig{Enabled: true, MinSamples: 20, Sensitivity: 3, MinRateFloor: 0.01}, store)
	found := false
	for _, a := range d.Evaluate([]string{"site"}, base) {
		if a.Site == "site" && a.Metric == "5xx_rate" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected the anomaly detector to fire on a real spike")
	}
}

func TestAnomalyDetectorIgnoresLowSampleBlip(t *testing.T) {
	store := analytics.NewStore(3 * time.Hour)
	base := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)

	for m := 0; m < 60; m++ {
		ts := base.Add(-time.Duration(60-m) * time.Minute)
		addN(store, "site", "1.1.1.1", 200, ts, 99)
		addN(store, "site", "1.1.1.1", 500, ts, 1)
	}
	// Eval window: only 3 total requests, 1 of them a 500 (33%!) -- classic
	// low-sample false-alarm trap. MinSamples=20 must suppress this. EvalWindow
	// is pinned to 1m so this minute doesn't overlap the last baseline minute.
	addN(store, "site", "1.1.1.1", 200, base, 2)
	addN(store, "site", "1.1.1.1", 500, base, 1)

	d := NewAnomalyDetector(config.AnomalyConfig{Enabled: true, EvalWindow: "1m", MinSamples: 20, Sensitivity: 3, MinRateFloor: 0.01}, store)
	for _, a := range d.Evaluate([]string{"site"}, base) {
		if a.Site == "site" && a.Metric == "5xx_rate" {
			t.Fatalf("expected MinSamples to suppress a low-sample blip, got %+v", a)
		}
	}
}
