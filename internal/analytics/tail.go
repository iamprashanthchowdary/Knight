package analytics

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"os"
	"sync/atomic"
	"time"
)

// Tailer follows one access-log file and feeds parsed records into the Store.
// It polls for appended bytes and survives log rotation/truncation by
// reopening from the top. Its starting point is controlled by startOffset (see
// NewTailer), and its current position is exposed via Position() so a
// supervisor can persist it across restarts (see internal/analytics/positions.go).
type Tailer struct {
	path        string
	site        string
	norm        *NormalizerHolder
	sink        *Store
	log         *slog.Logger
	startOffset int64
	since       time.Time // if non-zero, skip records older than this

	pos atomic.Pointer[FilePosition] // last-recorded resume point; read concurrently by the snapshot writer
}

// NewTailer wires a tailer for one site's log. The normalizer is passed as a
// holder so route-pattern changes take effect live. startOffset controls where
// reading begins:
//
//	-1  seek to end-of-file on first open (only new traffic from this point)
//	 0  read the whole file from the top
//	 N  resume at exactly byte N (used to restore a saved position, or to hand
//	    off seamlessly from a just-completed historical batch read -- see
//	    ingestFile in sources.go)
//
// If since is non-zero, records timestamped before it are skipped regardless
// of startOffset.
func NewTailer(path, site string, norm *NormalizerHolder, sink *Store, log *slog.Logger, startOffset int64, since time.Time) *Tailer {
	return &Tailer{path: path, site: site, norm: norm, sink: sink, log: log, startOffset: startOffset, since: since}
}

// Run tails until ctx is cancelled.
func (t *Tailer) Run(ctx context.Context) {
	offset := t.startOffset
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

// Position returns the tailer's last-recorded resume point (zero value if it
// hasn't opened the file yet). Safe to call concurrently with Run.
func (t *Tailer) Position() FilePosition {
	if p := t.pos.Load(); p != nil {
		return *p
	}
	return FilePosition{}
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
		t.pos.Store(&FilePosition{Offset: size, Size: size, ModTime: fi.ModTime()})
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
		rec, ok := Parse(sc.Text(), t.site)
		if !ok {
			continue
		}
		if t.norm.Ignore(rec.Path) {
			continue // e.g. Knight's own dashboard API polling -- not site traffic
		}
		if !t.since.IsZero() && rec.Time.Before(t.since) {
			continue // older than the requested start point
		}
		t.sink.Add(rec, t.norm.Normalize(rec.Path))
	}
	t.pos.Store(&FilePosition{Offset: size, Size: size, ModTime: fi.ModTime()})
	return size
}
