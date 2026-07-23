package analytics

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// snapshotVersion guards the on-disk layout. A version mismatch on load is
// treated as "no usable snapshot" (full rebuild from logs) rather than
// attempting a migration -- gob tolerates ADDED fields across versions
// gracefully, but not renamed/retyped/removed ones, so bumping this is the
// escape hatch whenever the Snapshot shape changes incompatibly.
const snapshotVersion = 1

// ClassCountsSnapshot mirrors the private classCounts for serialization.
type ClassCountsSnapshot struct {
	Total int64
	Class [6]int64
}

// MinuteSnapshot mirrors the private bucket type.
type MinuteSnapshot struct {
	ClassCountsSnapshot
	Codes map[int]int64
}

// IPSnapshot mirrors IPStat. Sites/Endpoints use map[string]bool rather than
// map[string]struct{} -- gob has a documented rough edge encoding zero-field
// struct values, and a bool costs one byte per entry, irrelevant at the scale
// involved (each IP's Endpoints is already capped at maxEndpointsPerIP).
type IPSnapshot struct {
	IP        string
	First     time.Time
	Last      time.Time
	Sites     map[string]bool
	Endpoints map[string]int64
	ClassCountsSnapshot
}

// EndpointSnapshot mirrors EndpointStat.
type EndpointSnapshot struct {
	Site     string
	Method   string
	Template string
	Last     time.Time
	IPs      map[string]bool
	ClassCountsSnapshot
}

// Snapshot is the durable, on-disk form of a Store, produced by Store.Snapshot
// and consumed by Store.Restore. Deliberately excludes the alert-rule windowed
// data (siteMinutes/ipMinutes) and alert cooldown state -- both are cheap to
// rebuild live within minutes to an hour of a restart, so persisting them
// isn't worth the extra surface.
type Snapshot struct {
	Version   int
	SavedAt   time.Time
	Retention time.Duration
	Minutes   map[int64]MinuteSnapshot
	Sites     map[string]ClassCountsSnapshot
	IPs       map[string]IPSnapshot
	Endpoints map[string]EndpointSnapshot
	Events    []Event // already fully exported; reused directly
}

// SnapshotPath returns the snapshot file path under a state directory.
func SnapshotPath(stateDir string) string { return filepath.Join(stateDir, "store.gob") }

// SaveSnapshot gob-encodes snap and writes it atomically (temp file + rename,
// same idiom config.Config.Save uses) so a crash mid-write never leaves a
// truncated snapshot that LoadSnapshot could partially decode.
func SaveSnapshot(path string, snap Snapshot) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(snap); err != nil {
		return fmt.Errorf("encode snapshot: %w", err)
	}
	return writeFileAtomic(path, buf.Bytes())
}

// LoadSnapshot reads and decodes a snapshot. Returns the underlying os error
// unwrapped (checkable with os.IsNotExist) when the file is simply absent --
// the normal case on a true first-ever start.
func LoadSnapshot(path string) (Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, err
	}
	var snap Snapshot
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&snap); err != nil {
		return Snapshot{}, fmt.Errorf("decode snapshot %s: %w", path, err)
	}
	if snap.Version != snapshotVersion {
		return Snapshot{}, fmt.Errorf("snapshot %s: version %d, want %d", path, snap.Version, snapshotVersion)
	}
	return snap, nil
}

// writeFileAtomic writes data to path via a temp file + rename, so a reader
// (or a crash) never observes a partially-written file.
func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
