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
func ingestFile(path, site string, norm *NormalizerHolder, sink *Store, since time.Time, log *slog.Logger) {
	f, err := os.Open(path)
	if err != nil {
		log.Warn("batch: cannot open log", "path", path, "err", err)
		return
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			log.Warn("batch: not a valid gzip file", "path", path, "err", err)
			return
		}
		defer gz.Close()
		r = gz
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // long UA lines
	var n int
	for sc.Scan() {
		rec, ok := ParseCombined(sc.Text(), site)
		if !ok {
			continue
		}
		if !since.IsZero() && rec.Time.Before(since) {
			continue
		}
		sink.Add(rec, norm.Normalize(rec.Path))
		n++
	}
	log.Info("batch: ingested archive", "path", path, "records", n)
}
