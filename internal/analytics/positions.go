package analytics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// FilePosition is one tailed file's resume point. Size/ModTime are diagnostic
// only (so a human -- or a future health check -- can compare a saved offset
// against the live file's current state during an incident); they are NOT
// load-bearing for correctness. Tailer.drain() already self-heals rotation and
// truncation live, by comparing a saved Offset against the CURRENT file's
// actual size at resume time, so nothing here needs its own fingerprint logic.
type FilePosition struct {
	Offset  int64
	Size    int64
	ModTime time.Time
}

// Positions is the durable, on-disk form of every running tailer's resume
// point, keyed by absolute file path. Paired with a Snapshot via matching
// SavedAt timestamps -- see cmd/knight/main.go for why they must be loaded
// and trusted together, never independently.
type Positions struct {
	SavedAt time.Time
	Files   map[string]FilePosition
}

// PositionsPath returns the positions file path under a state directory.
func PositionsPath(stateDir string) string { return filepath.Join(stateDir, "positions.json") }

// SavePositions writes p as indented JSON, atomically. JSON (not gob) here is
// deliberate: this file is small (one entry per tailed file) and worth being
// human-readable (`cat positions.json`) during an incident, unlike the much
// larger analytics Snapshot.
func SavePositions(path string, p Positions) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data)
}

// LoadPositions reads and decodes a positions file. Returns the underlying os
// error unwrapped (checkable with os.IsNotExist) when the file is absent.
func LoadPositions(path string) (Positions, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Positions{}, err
	}
	var p Positions
	if err := json.Unmarshal(data, &p); err != nil {
		return Positions{}, err
	}
	return p, nil
}
