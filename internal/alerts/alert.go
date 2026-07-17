// Package alerts is Knight's outbound notification layer: it evaluates
// user-defined threshold rules and an automatic anomaly detector against the
// analytics Store, and delivers firing alerts via webhook and/or email.
//
// This is a LIVE-only feature. The caller (cmd/knight) must only run the
// Engine while tailing real-time traffic, never during a historical/-from-start
// replay -- otherwise replaying a week-old log would fire a week's worth of
// stale notifications the moment the agent starts.
package alerts

import "time"

// Alert is one notification event, delivered to every channel in Channels (or
// every enabled channel, if Channels is empty).
type Alert struct {
	ID        string    `json:"id"`   // rule id, or "anomaly_5xx" / "anomaly_4xx" / "test"
	Kind      string    `json:"kind"` // "threshold" | "anomaly" | "test"
	Site      string    `json:"site,omitempty"`
	Metric    string    `json:"metric"`
	Value     float64   `json:"value"`
	Threshold float64   `json:"threshold"`
	Window    string    `json:"window,omitempty"`
	Message   string    `json:"message"`
	Time      time.Time `json:"time"`
	Channels  []string  `json:"-"`
}
