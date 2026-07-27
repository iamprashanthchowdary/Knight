package analytics

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestTailerRecoversFromOversizedLine reproduces the real production incident
// found 2026-07-27: a garbled/oversized line (see
// TestIngestFileRecoversFromOversizedLine for how this arises on a real nginx
// box) used to make Tailer.drain silently stall FOREVER -- bufio.Scanner
// aborted on the oversized token, drain didn't check the error, and
// unconditionally stored the file's then-current size as "fully consumed",
// discarding every subsequent line for good with no warning ever logged.
// This proves the fix: a tick containing a garbled line still ingests every
// good line in that same tick (before AND after the garbled one), and
// ingestion continues normally on the NEXT tick.
func TestTailerRecoversFromOversizedLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	store := NewStore(time.Hour)
	tailer := NewTailer(path, "site", NewNormalizerHolder(), store, testLogger(), 0, time.Time{})

	ts := "27/Jul/2026:10:00:00 +0000"
	good := func(i int) string {
		return fmt.Sprintf(`10.0.0.1 - - [%s] "GET /x HTTP/1.1" 200 1 "-" "ua-%d"`+"\n", ts, i)
	}
	// Structurally unparseable, not just long -- see sources_test.go's
	// TestIngestFileRecoversFromOversizedLine for why a merely-long-but-valid
	// line isn't actually a useful reproduction of a torn concurrent write.
	garbled := strings.Repeat("A", 2*1024*1024) + "\n"

	appendLine := func(s string) {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.WriteString(s); err != nil {
			t.Fatal(err)
		}
	}

	// Tick 1: a good line, a garbled line, then another good line -- all in
	// the same poll.
	appendLine(good(1) + garbled + good(2))
	offset := tailer.drain(0)
	if got := store.Overview("").Total; got != 2 {
		t.Fatalf("after tick 1: total = %d, want 2 (both good lines, garbled one skipped)", got)
	}

	// Tick 2: ingestion must continue normally -- proving no permanent stall.
	appendLine(good(3))
	offset = tailer.drain(offset)
	if got := store.Overview("").Total; got != 3 {
		t.Fatalf("after tick 2: total = %d, want 3 (ingestion must resume, not stay stuck)", got)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if offset != fi.Size() {
		t.Errorf("final offset = %d, want %d (fully caught up to the file's end)", offset, fi.Size())
	}
}

// TestTailerResumesFromExactUnterminatedFragment proves a partially-written
// final line (nginx mid-write at the moment of a poll) is neither lost nor
// double-counted: drain must not advance its offset past it, and the NEXT
// tick -- once the line is completed -- must ingest it exactly once.
func TestTailerResumesFromExactUnterminatedFragment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	ts := "27/Jul/2026:10:00:00 +0000"
	full := fmt.Sprintf(`10.0.0.1 - - [%s] "GET /x HTTP/1.1" 200 1 "-" "ua"`+"\n", ts)
	partial := strings.TrimSuffix(full, "\n") // no trailing newline yet -- "mid write"

	if err := os.WriteFile(path, []byte(partial), 0o644); err != nil {
		t.Fatal(err)
	}

	store := NewStore(time.Hour)
	tailer := NewTailer(path, "site", NewNormalizerHolder(), store, testLogger(), 0, time.Time{})

	offset := tailer.drain(0)
	if offset != 0 {
		t.Errorf("offset = %d, want 0 (unterminated line must not be counted as consumed)", offset)
	}
	if got := store.Overview("").Total; got != 0 {
		t.Errorf("total = %d, want 0 (unterminated line must not be ingested yet)", got)
	}

	// Complete the line (append the trailing newline the "write" was missing).
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	offset = tailer.drain(offset)
	if got := store.Overview("").Total; got != 1 {
		t.Errorf("total = %d, want 1 (now-complete line must be ingested exactly once)", got)
	}
	if offset != int64(len(full)) {
		t.Errorf("offset = %d, want %d", offset, len(full))
	}
}

// TestTailerContextCancel is a smoke test that Run exits promptly on context
// cancellation -- unrelated to the bug above, but cheap coverage for a
// function with no prior test at all.
func TestTailerContextCancel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	store := NewStore(time.Hour)
	tailer := NewTailer(path, "site", NewNormalizerHolder(), store, testLogger(), -1, time.Time{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		tailer.Run(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after context cancellation")
	}
}
