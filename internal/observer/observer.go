// Package observer is Knight's out-of-band eye. It tails the nginx access log
// and replays each request through the same engine the inline path uses. This
// catches things the per-request decision cannot: an IP that is individually
// benign per request but hostile in aggregate, or attacks visible only in the
// full logged line. When a line scores past the observer threshold, the source
// IP is banned -- so even in pure log mode Knight can "strike back".
package observer

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"os"
	"regexp"
	"time"

	"knight/internal/engine"
	"knight/internal/guard"
	"knight/internal/request"
)

// nginx "combined" log format:
// $remote_addr - $remote_user [$time_local] "$request" $status $bytes "$referer" "$ua"
var combinedRE = regexp.MustCompile(
	`^(\S+) \S+ \S+ \[[^\]]*\] "(\S+) ([^"]*?) [^"]*" \d+ \S+ "([^"]*)" "([^"]*)"`,
)

// Observer tails a log file and feeds parsed requests to the engine.
type Observer struct {
	path      string
	eng       *engine.Engine
	bl        *guard.Blocklist
	log       *slog.Logger
	threshold int
	banFor    time.Duration
}

// New creates an Observer.
func New(path string, eng *engine.Engine, bl *guard.Blocklist, log *slog.Logger, threshold int, banFor time.Duration) *Observer {
	if threshold <= 0 {
		threshold = 15
	}
	return &Observer{path: path, eng: eng, bl: bl, log: log, threshold: threshold, banFor: banFor}
}

// Run tails the file until ctx is cancelled. It starts at end-of-file (only new
// traffic) and re-opens the file if it is rotated or briefly missing.
func (o *Observer) Run(ctx context.Context) {
	var offset int64 = -1 // -1 means "seek to end on first open"
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			offset = o.drain(offset)
		}
	}
}

// drain reads any bytes appended since offset and returns the new offset.
func (o *Observer) drain(offset int64) int64 {
	f, err := os.Open(o.path)
	if err != nil {
		return offset // file gone for now; try again next tick
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return offset
	}
	size := fi.Size()

	switch {
	case offset < 0:
		return size // first run: skip existing history
	case size < offset:
		offset = 0 // file was truncated/rotated
	}

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return offset
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		o.process(sc.Text())
	}
	return size
}

func (o *Observer) process(line string) {
	m := combinedRE.FindStringSubmatch(line)
	if m == nil {
		return
	}
	ip, method, uri, referer, ua := m[1], m[2], m[3], m[4], m[5]
	if o.bl.Blocked(ip) {
		return
	}
	ctx := request.New(ip, method, uri, ua, referer, "", "")
	v := o.eng.Evaluate(ctx)
	if v.Score >= o.threshold {
		o.bl.Block(ip, "observer", o.banFor)
		o.log.Warn("observer banned ip",
			"ip", ip, "uri", uri, "score", v.Score)
	}
}
