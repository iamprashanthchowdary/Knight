package analytics

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// SiteSpec is one log source to observe. AccessLog may be a single file, a
// directory, or a glob (e.g. ".../access.log*") covering a whole rotation set.
type SiteSpec struct {
	Name      string
	AccessLog string
}

// Manager owns the running tailers and the shared normalizer. It supports
// three entrypoints:
//   - Bootstrap: the `-from-start`/`-since` CLI ad-hoc replay path. BATCH-reads
//     every matched file, including .gz archives, then returns -- a one-shot
//     snapshot, no live tailer started. Unchanged, deliberately separate from
//     the persistence flow below.
//   - BootstrapWithHistory: the default (no CLI flags) startup path. Resumes
//     each site's active file from a saved Positions entry if present (warm
//     restart), otherwise does one bounded historical read before handing off
//     to a live tailer -- see startActiveSite.
//   - Apply: called on config edits (hot reload). Always live-reconciles
//     tailers and swaps the normalizer, preserving accumulated stats.
type Manager struct {
	mu      sync.Mutex
	parent  context.Context
	store   *Store
	holder  *NormalizerHolder
	log     *slog.Logger
	running map[string]*tailerHandle // site name -> live tailer

	fromStart bool
	since     time.Time
}

type tailerHandle struct {
	path   string
	cancel context.CancelFunc
	tailer *Tailer // so Positions() can read back its current offset
}

// NewManager creates a Manager. fromStart/since select historical batch mode in
// Bootstrap.
func NewManager(parent context.Context, store *Store, log *slog.Logger, fromStart bool, since time.Time) *Manager {
	return &Manager{
		parent:    parent,
		store:     store,
		holder:    NewNormalizerHolder(),
		log:       log,
		running:   make(map[string]*tailerHandle),
		fromStart: fromStart,
		since:     since,
	}
}

// Holder exposes the shared normalizer holder.
func (m *Manager) Holder() *NormalizerHolder { return m.holder }

func (m *Manager) historical() bool { return m.fromStart || !m.since.IsZero() }

// Bootstrap performs the initial ingest from the configured sites. This is the
// `-from-start`/`-since` CLI path only -- see cmd/knight/main.go, which calls
// this instead of BootstrapWithHistory exactly when historical() would be true.
func (m *Manager) Bootstrap(sites []SiteSpec, patterns, ignorePaths []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.holder.Store(NewNormalizer(patterns, ignorePaths))

	if m.historical() {
		// Read every matched file once (gzip-aware), across all sites.
		for _, s := range sites {
			if s.AccessLog == "" {
				continue
			}
			name := siteName(s)
			files := expandSources(s.AccessLog)
			m.log.Info("batch: reading rotation set", "site", name, "files", len(files))
			for _, f := range files {
				go ingestFile(f, name, m.holder, m.store, m.since, m.log)
			}
		}
		return
	}
	m.reconcileLocked(sites)
}

// BootstrapWithHistory is the default (non -from-start/-since) startup
// entrypoint. For each site: the active (newest, live-tailed) file either
// resumes from pos (warm restart -- its history is already in the Store via
// Store.Restore, called by main.go before this) or is read once, bounded to
// since, before handing off to a live tailer seeded at exactly the byte offset
// that read reached (cold start -- no gap, no duplicate; see ingestFile).
// Rotated/.gz archives are read once, ONLY on the cold-start path -- on a warm
// restart their content is already durably contained in the restored Store, so
// re-reading them would double-count every request in them on every single
// restart (the exact "recalculating the whole log again and again" cost this
// feature exists to eliminate). A site with no entry in pos (new since the
// last snapshot, or a true first-ever start) falls through to the cold-start
// path -- rotated archives included -- on its own, so warm and cold sites are
// handled correctly in one call without the caller needing to know which is
// which.
func (m *Manager) BootstrapWithHistory(sites []SiteSpec, patterns, ignorePaths []string, since time.Time, pos Positions) {
	m.mu.Lock()
	m.holder.Store(NewNormalizer(patterns, ignorePaths))
	m.mu.Unlock()

	for _, s := range sites {
		if s.AccessLog == "" {
			continue
		}
		name := siteName(s)
		active := resolveLiveFile(s.AccessLog)
		_, warmSite := pos.Files[active]

		if !warmSite {
			files := expandSources(s.AccessLog)
			m.log.Info("batch: reading rotation set", "site", name, "files", len(files), "active", active)
			for _, f := range files {
				if f == active {
					continue // handled by startActiveSite below, possibly live-tailed afterward
				}
				go func(f string) {
					n, err := ingestFile(f, name, m.holder, m.store, since, m.log)
					if err != nil {
						m.log.Warn("batch: ingest failed", "site", name, "path", f, "err", err)
						return
					}
					_ = n
				}(f)
			}
		} else {
			m.log.Info("batch: warm restart, skipping rotation set", "site", name, "active", active)
		}
		go m.startActiveSite(name, active, since, pos)
	}
}

// startActiveSite brings up the live tailer for one site's active file, warm
// (resume from a saved position) or cold (bounded historical read, then resume
// exactly where it left off). Runs in its own goroutine so multiple sites'
// cold-start reads proceed concurrently, same as Bootstrap.
//
// Note: if a config edit (Apply) races this and registers the same site name
// first, startTailerLocked's dedup silently keeps whichever tailer won the
// race and drops the other -- in the rare case that's the EOF-start one, that
// site simply skips this run's historical backfill (no data corruption, just a
// missed catch-up) and self-heals on the next periodic snapshot/restart.
func (m *Manager) startActiveSite(name, active string, since time.Time, pos Positions) {
	startOffset := int64(-1)
	if fp, ok := pos.Files[active]; ok {
		startOffset = fp.Offset // warm restart: history already in the restored Store
	} else if off, err := ingestFile(active, name, m.holder, m.store, since, m.log); err == nil {
		startOffset = off // cold start: bounded historical read, then resume exactly here
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startTailerLocked(name, active, startOffset, time.Time{})
}

// Positions returns every running tailer's current resume point, for periodic
// persistence by the caller (SavedAt is left zero; the caller stamps it so it
// can be correlated with a matching Snapshot -- see cmd/knight/main.go).
func (m *Manager) Positions() Positions {
	m.mu.Lock()
	defer m.mu.Unlock()
	files := make(map[string]FilePosition, len(m.running))
	for _, h := range m.running {
		files[h.path] = h.tailer.Position()
	}
	return Positions{Files: files}
}

// Apply live-reconciles tailers and swaps the normalizer (hot reload).
func (m *Manager) Apply(sites []SiteSpec, patterns, ignorePaths []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.holder.Store(NewNormalizer(patterns, ignorePaths))
	m.reconcileLocked(sites)
}

// reconcileLocked starts/stops live tailers to match the desired sites. Must be
// called with m.mu held. Newly-started tailers always begin from m.fromStart/
// m.since (the CLI flags) -- a site added here (via hot config reload) gets no
// historical catch-up, only BootstrapWithHistory's cold-start path does that.
func (m *Manager) reconcileLocked(sites []SiteSpec) {
	desired := make(map[string]string, len(sites)) // name -> file to tail
	for _, s := range sites {
		if s.AccessLog == "" {
			continue
		}
		desired[siteName(s)] = resolveLiveFile(s.AccessLog)
	}

	for name, h := range m.running {
		if path, ok := desired[name]; !ok || path != h.path {
			h.cancel()
			delete(m.running, name)
			m.log.Info("stopped observing site", "site", name)
		}
	}

	startOffset := int64(-1)
	if m.fromStart {
		startOffset = 0
	}
	for name, path := range desired {
		m.startTailerLocked(name, path, startOffset, m.since)
	}
}

// startTailerLocked starts a tailer for name/path at startOffset and records
// it in m.running. Must be called with m.mu held. No-op if name is already
// running (first writer wins -- see the race note on startActiveSite).
func (m *Manager) startTailerLocked(name, path string, startOffset int64, since time.Time) {
	if _, ok := m.running[name]; ok {
		return
	}
	ctx, cancel := context.WithCancel(m.parent)
	t := NewTailer(path, name, m.holder, m.store, m.log, startOffset, since)
	go t.Run(ctx)
	m.running[name] = &tailerHandle{path: path, cancel: cancel, tailer: t}
	m.log.Info("observing site", "site", name, "access_log", path)
}

func siteName(s SiteSpec) string {
	if s.Name != "" {
		return s.Name
	}
	return s.AccessLog
}
