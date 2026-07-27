package analytics

import (
	"compress/gzip"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestIngestFileFreezesReadBoundary proves the core gap/duplicate-free
// guarantee the historical-to-live handoff depends on: ingestFile's returned
// offset always matches the file's size at the moment it started reading, even
// when the file is actively appended to WHILE the scan is in progress. If this
// ever regressed to measuring size at scanner-EOF instead, this test would
// observe the returned offset include the concurrently-appended bytes.
func TestIngestFileFreezesReadBoundary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")

	var initial []byte
	ts := "20/Jul/2026:00:00:00 +0000"
	for i := 0; i < 20000; i++ {
		initial = append(initial, []byte(fmt.Sprintf(
			`10.0.0.1 - - [%s] "GET /x HTTP/1.1" 200 1 "-" "ua-%d"`+"\n", ts, i))...)
	}
	if err := os.WriteFile(path, initial, 0o644); err != nil {
		t.Fatal(err)
	}
	sizeBefore := int64(len(initial))

	appended := make(chan struct{})
	go func() {
		defer close(appended)
		time.Sleep(20 * time.Millisecond) // give ingestFile's Stat() a head start
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return
		}
		defer f.Close()
		_, _ = f.WriteString(fmt.Sprintf(`10.0.0.2 - - [%s] "GET /appended-after HTTP/1.1" 200 1 "-" "late"`+"\n", ts))
	}()

	store := NewStore(time.Hour)
	offset, err := ingestFile(path, "site", NewNormalizerHolder(), store, time.Time{}, testLogger())
	if err != nil {
		t.Fatalf("ingestFile: %v", err)
	}
	<-appended // ensure the append has definitely landed before we assert

	if offset != sizeBefore {
		t.Errorf("offset = %d, want %d (the pre-scan size) -- the append during scan must not be included", offset, sizeBefore)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() <= sizeBefore {
		t.Fatal("test setup broken: the concurrent append didn't actually grow the file")
	}

	// A second ingestFile call on the now-larger file must pick up the
	// appended line and return the new, larger size -- proving the freeze is
	// per-call, not a stale global assumption.
	offset2, err := ingestFile(path, "site", NewNormalizerHolder(), store, time.Time{}, testLogger())
	if err != nil {
		t.Fatalf("second ingestFile: %v", err)
	}
	if offset2 != fi.Size() {
		t.Errorf("second call offset = %d, want %d (current file size)", offset2, fi.Size())
	}
}

// TestIngestFileRecoversFromOversizedLine reproduces the real production bug
// found 2026-07-27: two nginx workers writing large log lines (long request
// URLs carrying embedded tokens) to the same file can have their writes
// interleave into one garbled "line" far longer than any real request line --
// bufio.Scanner's old 4MB cap turned that into a fatal, whole-file read
// failure (records_before_error logged, but ingestFile returned an error and
// 0 offset, and -- more seriously in Tailer.drain's case -- a PERMANENT silent
// stall). readLines has no such cap: the garbled line is read in full, fails
// Parse, and is harmlessly skipped -- every other line, including ones AFTER
// the garbled one, must still be ingested.
func TestIngestFileRecoversFromOversizedLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")

	ts := "27/Jul/2026:10:00:00 +0000"
	good := func(i int) string {
		return fmt.Sprintf(`10.0.0.1 - - [%s] "GET /x HTTP/1.1" 200 1 "-" "ua-%d"`+"\n", ts, i)
	}
	// A single "line" (no embedded newline) well past the old 4MB scanner cap
	// AND structurally unparseable -- simulating two concurrent writes torn
	// and glued together mid-line, with none of the combined-format anchors
	// (brackets/quotes) surviving intact.
	garbled := strings.Repeat("A", 5*1024*1024) + "\n"

	var content string
	content += good(1)
	content += garbled
	content += good(2)
	content += good(3)

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	store := NewStore(time.Hour)
	offset, err := ingestFile(path, "site", NewNormalizerHolder(), store, time.Time{}, testLogger())
	if err != nil {
		t.Fatalf("ingestFile: %v", err)
	}
	if offset != int64(len(content)) {
		t.Errorf("offset = %d, want %d (the whole file, garbled line included)", offset, len(content))
	}
	// 3 good records: the garbled one must fail Parse and be silently skipped,
	// not abort the read and lose the two good lines that follow it.
	if got := store.Overview("").Total; got != 3 {
		t.Errorf("total = %d, want 3 (garbled line skipped, everything else ingested)", got)
	}
}

// TestIngestFileGzipReturnsZeroOffset confirms .gz archives -- read once, never
// live-tailed -- report offset 0 rather than a meaningless decompressed size.
func TestIngestFileGzipReturnsZeroOffset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log.2.gz")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	if _, err := gz.Write([]byte("10.0.0.1 - - [20/Jul/2026:00:00:00 +0000] \"GET /x HTTP/1.1\" 200 1 \"-\" \"ua\"\n")); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	store := NewStore(time.Hour)
	offset, err := ingestFile(path, "site", NewNormalizerHolder(), store, time.Time{}, testLogger())
	if err != nil {
		t.Fatalf("ingestFile: %v", err)
	}
	if offset != 0 {
		t.Errorf("offset = %d, want 0 for a .gz archive", offset)
	}
	if store.Overview("").Total != 1 {
		t.Errorf("total = %d, want 1 (the gz content should still be ingested)", store.Overview("").Total)
	}
}
