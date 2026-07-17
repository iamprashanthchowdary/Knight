package alerts

import (
	"fmt"
	"math"
	"time"

	"knight/internal/analytics"
	"knight/internal/config"
)

// AnomalyDetector flags sudden 4xx/5xx spikes with NO manually-tuned threshold.
//
// Algorithm: an adaptive control chart (Z-score test against a rolling
// per-site baseline), the standard statistical-process-control technique for
// "is this recent value unusual given this metric's own normal variance" --
// deliberately not a fixed percentage, because a fixed threshold is either too
// sensitive on a noisy site or too blind on a very stable one.
//
//  1. Baseline: mean and standard deviation of the per-minute error rate over
//     the trailing baseline window (default 60m), EXCLUDING the evaluation
//     window itself -- so a live spike can never pollute its own baseline.
//     Near-empty minutes (<5 requests) are dropped from the baseline; a
//     handful of requests produces wildly noisy rates that would widen the
//     baseline into uselessness.
//  2. Evaluation: the error rate over the trailing eval window (default 2m).
//  3. Fires ONLY if every one of these holds -- each is specifically there to
//     kill a class of false alarm:
//       - eval window has >= MinSamples requests (default 20). Without this, 1
//         error out of 3 requests is "33%" and fires constantly on quiet sites.
//       - eval rate >= MinRateFloor (default 2%). Without this, a site that's
//         normally 0.01% error and blips to 0.05% is a real statistical
//         outlier but not worth waking anyone up for.
//       - eval rate > baseline_mean + Sensitivity * baseline_stddev (default
//         Sensitivity=3, i.e. ~3 standard deviations above normal).
//  4. Cooldown suppresses repeat fires for the same site+class while the
//     elevated rate persists, instead of re-notifying every single minute.
//
// This adapts per site automatically: a site that normally runs 3% 4xx (lots
// of expected "not found" traffic) won't fire at 4%, while a site that
// normally runs 0.1% fires at 1% -- both are genuine several-sigma departures
// from THAT site's own normal.
type AnomalyDetector struct {
	enabled     bool
	baseline    time.Duration
	eval        time.Duration
	minSamples  int64
	sensitivity float64
	minFloor    float64
	cooldown    time.Duration

	store *analytics.Store
	state map[string]time.Time // "site\x00class" -> last fired
}

// NewAnomalyDetector builds a detector from config, applying defaults for any
// unset tuning fields.
func NewAnomalyDetector(cfg config.AnomalyConfig, store *analytics.Store) *AnomalyDetector {
	return &AnomalyDetector{
		enabled:     cfg.Enabled,
		baseline:    cfg.BaselineDuration(),
		eval:        cfg.EvalDuration(),
		minSamples:  cfg.MinSamplesOrDefault(),
		sensitivity: cfg.SensitivityOrDefault(),
		minFloor:    cfg.MinRateFloorOrDefault(),
		cooldown:    cfg.CooldownDuration(),
		store:       store,
		state:       make(map[string]time.Time),
	}
}

var watchedClasses = []struct {
	class int
	label string
}{
	{5, "5xx"},
	{4, "4xx"},
}

// Evaluate checks every given site (plus the global/all-sites scope) for a
// 4xx/5xx anomaly and returns any alerts that should fire, respecting cooldown.
func (d *AnomalyDetector) Evaluate(sites []string, now time.Time) []Alert {
	if !d.enabled {
		return nil
	}
	var out []Alert
	scopes := append([]string{""}, sites...) // "" = all sites combined
	for _, site := range scopes {
		for _, wc := range watchedClasses {
			if a, ok := d.evalOne(site, wc.class, wc.label, now); ok {
				out = append(out, a)
			}
		}
	}
	return out
}

func (d *AnomalyDetector) evalOne(site string, class int, label string, now time.Time) (Alert, bool) {
	// Baseline covers [now-baseline-eval, now-eval), i.e. it excludes the
	// window currently being evaluated.
	baseEnd := now.Add(-d.eval)
	baseMinutes := int(d.baseline / time.Minute)
	if baseMinutes < 5 {
		baseMinutes = 5
	}
	series := d.store.SiteMinuteSeries(site, baseMinutes, baseEnd)

	var rates []float64
	for _, m := range series {
		if m.Total < 5 {
			continue // near-empty minute; would distort the baseline
		}
		rates = append(rates, float64(m.Class[class])/float64(m.Total))
	}
	if len(rates) < 5 {
		return Alert{}, false // not enough history yet to have an opinion
	}
	mean, stddev := meanStddev(rates)

	matched, total := d.store.WindowStatusCount(site, []int{class}, d.eval, now)
	if total < d.minSamples {
		return Alert{}, false
	}
	rate := float64(matched) / float64(total)
	if rate < d.minFloor {
		return Alert{}, false
	}
	upperBound := mean + d.sensitivity*stddev
	if rate <= upperBound {
		return Alert{}, false
	}

	key := site + "\x00" + label
	if last, ok := d.state[key]; ok && now.Sub(last) < d.cooldown {
		return Alert{}, false
	}
	d.state[key] = now

	return Alert{
		ID:        "anomaly_" + label,
		Kind:      "anomaly",
		Site:      site,
		Metric:    label + "_rate",
		Value:     rate,
		Threshold: upperBound,
		Window:    d.eval.String(),
		Message: fmt.Sprintf("%s spike on %s: %.2f%% (baseline %.2f%% ± %.2f%%)",
			label, siteLabel(site), rate*100, mean*100, stddev*100),
		Time: now,
	}, true
}

func meanStddev(xs []float64) (mean, stddev float64) {
	n := float64(len(xs))
	for _, x := range xs {
		mean += x
	}
	mean /= n
	var sumSq float64
	for _, x := range xs {
		diff := x - mean
		sumSq += diff * diff
	}
	stddev = math.Sqrt(sumSq / n)
	return mean, stddev
}

func siteLabel(site string) string {
	if site == "" {
		return "all sites"
	}
	return site
}
