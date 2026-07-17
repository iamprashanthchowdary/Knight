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

// Manager owns the running tailers and the shared normalizer. It supports two
// ingestion styles:
//   - Bootstrap: called once at startup. In historical mode (-from-start/-since)
//     it BATCH-reads every matched file, including .gz archives, so a folder of
//     rotated logs is fully analyzed. Otherwise it live-tails the active file.
//   - Apply: called on config edits (hot reload). Always live-reconciles tailers
//     and swaps the normalizer, preserving accumulated stats.
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

// Bootstrap performs the initial ingest from the configured sites.
func (m *Manager) Bootstrap(sites []SiteSpec, patterns []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.holder.Store(NewNormalizer(patterns))

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

// Apply live-reconciles tailers and swaps the normalizer (hot reload).
func (m *Manager) Apply(sites []SiteSpec, patterns []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.holder.Store(NewNormalizer(patterns))
	m.reconcileLocked(sites)
}

// reconcileLocked starts/stops live tailers to match the desired sites. Must be
// called with m.mu held.
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

	for name, path := range desired {
		if _, ok := m.running[name]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(m.parent)
		t := NewTailer(path, name, m.holder, m.store, m.log, m.fromStart, m.since)
		go t.Run(ctx)
		m.running[name] = &tailerHandle{path: path, cancel: cancel}
		m.log.Info("observing site", "site", name, "access_log", path)
	}
}

func siteName(s SiteSpec) string {
	if s.Name != "" {
		return s.Name
	}
	return s.AccessLog
}
