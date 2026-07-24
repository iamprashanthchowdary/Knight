package analytics

import (
	"bufio"
	"compress/gzip"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// expandSources turns a site's access_log setting into a concrete list of
// files. It accepts a single file, a directory (all files inside), or a glob
// pattern (e.g. ".../swiftflow-access.log*"). This is what lets one site cover
// a whole nginx logrotate set (access.log + access.log.1 + access.log.*.gz).
func expandSources(pattern string) []string {
	if fi, err := os.Stat(pattern); err == nil && fi.IsDir() {
		pattern = filepath.Join(pattern, "*")
	}
	if !strings.ContainsAny(pattern, "*?[") {
		return []string{pattern} // plain single file
	}
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil
	}
	sort.Strings(matches)
	return matches
}

// resolveLiveFile picks the single file to LIVE-tail from an expanded source:
// the most recently modified plain-text (non-.gz) file. Compressed archives are
// immutable, so they're never tailed.
func resolveLiveFile(pattern string) string {
	files := expandSources(pattern)
	if len(files) == 1 {
		return files[0]
	}
	var newest string
	var newestMod time.Time
	for _, f := range files {
		if strings.HasSuffix(f, ".gz") {
			continue
		}
		fi, err := os.Stat(f)
		if err != nil {
			continue
		}
		if newest == "" || fi.ModTime().After(newestMod) {
			newest, newestMod = f, fi.ModTime()
		}
	}
	if newest == "" {
		return pattern
	}
	return newest
}

// ingestFile reads one file fully, once, feeding parsed records to the store.
// It transparently decompresses .gz archives and honours the since cutoff. Used
// for historical/batch reads (not live tailing).
//
// Returns the byte offset immediately after the last byte scanned, for a plain
// (non-.gz) file -- always 0 for .gz archives, which are read once and never
// live-tailed. The read boundary is frozen at the file's size BEFORE scanning
// starts (via io.LimitReader), not at scanner-EOF: this is what makes handing
// off to a live Tailer seeded with this offset provably gap/duplicate-free even
// if nginx is actively appending to the file during this read. ingestFile owns
// bytes [0, offset); a Tailer started with startOffset=offset owns everything
// from there on -- disjoint ranges, so no duplicate is possible, and the only
// gap that can occur is a single line straddling the exact cut (the same class
// of edge case Tailer.drain already tolerates at every ordinary poll boundary).
func ingestFile(path, site string, norm *NormalizerHolder, sink *Store, since time.Time, log *slog.Logger) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		log.Warn("batch: cannot open log", "path", path, "err", err)
		return 0, err
	}
	defer f.Close()

	isGz := strings.HasSuffix(path, ".gz")
	var r io.Reader = f
	var limit int64
	if isGz {
		gz, err := gzip.NewReader(f)
		if err != nil {
			log.Warn("batch: not a valid gzip file", "path", path, "err", err)
			return 0, err
		}
		defer gz.Close()
		r = gz
	} else {
		fi, err := f.Stat()
		if err != nil {
			log.Warn("batch: cannot stat log", "path", path, "err", err)
			return 0, err
		}
		limit = fi.Size() // frozen before a single line is scanned
		r = io.LimitReader(f, limit)
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // long UA lines
	var n int
	for sc.Scan() {
		rec, ok := Parse(sc.Text(), site)
		if !ok {
			continue
		}
		if norm.Ignore(rec.Path) {
			continue // e.g. Knight's own dashboard API polling -- not site traffic
		}
		if !since.IsZero() && rec.Time.Before(since) {
			continue
		}
		sink.Add(rec, norm.Normalize(rec.Path))
		n++
	}
	// Scan() returns false on a clean EOF AND on a real read error (e.g. a
	// truncated/corrupt gzip body) -- without this check, a genuinely broken
	// file silently reports "0 records, all fine" instead of a warning.
	if err := sc.Err(); err != nil {
		log.Warn("batch: error reading log (partial read)", "path", path, "records_before_error", n, "err", err)
		return 0, err
	}
	log.Info("batch: ingested archive", "path", path, "records", n)

	if isGz {
		return 0, nil
	}
	return limit, nil
}
