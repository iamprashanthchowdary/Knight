package analytics

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"os"
	"time"
)

// Tailer follows one access-log file and feeds parsed records into the Store.
// It starts at end-of-file (only new traffic), polls for appended bytes, and
// survives log rotation/truncation by reopening from the top.
type Tailer struct {
	path      string
	site      string
	norm      *NormalizerHolder
	sink      *Store
	log       *slog.Logger
	fromStart bool
	since     time.Time // if non-zero, skip records older than this
}

// NewTailer wires a tailer for one site's log. The normalizer is passed as a
// holder so route-pattern changes take effect live. If fromStart is true it
// reads the file from the beginning (useful for checking an existing log);
// otherwise it begins at end-of-file and only sees new traffic. If since is
// non-zero, records timestamped before it are skipped.
func NewTailer(path, site string, norm *NormalizerHolder, sink *Store, log *slog.Logger, fromStart bool, since time.Time) *Tailer {
	return &Tailer{path: path, site: site, norm: norm, sink: sink, log: log, fromStart: fromStart, since: since}
}

// Run tails until ctx is cancelled.
func (t *Tailer) Run(ctx context.Context) {
	var offset int64 = -1 // -1 => seek to end on first open
	if t.fromStart {
		offset = 0 // read existing history from the top
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			offset = t.drain(offset)
		}
	}
}

func (t *Tailer) drain(offset int64) int64 {
	f, err := os.Open(t.path)
	if err != nil {
		return offset // not present yet; retry next tick
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
		offset = 0 // rotated/truncated
	}

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return offset
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		rec, ok := ParseCombined(sc.Text(), t.site)
		if !ok {
			continue
		}
		if !t.since.IsZero() && rec.Time.Before(t.since) {
			continue // older than the requested start point
		}
		t.sink.Add(rec, t.norm.Normalize(rec.Path))
	}
	return size
}
