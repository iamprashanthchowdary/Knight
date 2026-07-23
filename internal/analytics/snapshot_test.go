package analytics

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func buildTestStore(t *testing.T) *Store {
	t.Helper()
	s := NewStore(24 * time.Hour)
	n := NewNormalizer(nil)
	base := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	add := func(ip, path string, status int, at time.Time) {
		r, ok := ParseCombined(
			`X - - [`+at.Format("02/Jan/2006:15:04:05 -0700")+`] "GET `+path+` HTTP/1.1" `+itoa(status)+` 10 "ref" "ua"`, "site-a")
		if !ok {
			t.Fatalf("failed to build synthetic record for %s %s", ip, path)
		}
		r.IP = ip
		s.Add(r, n.Normalize(r.Path))
	}
	// Distinct totals per IP (3 vs 2) so TopIPs' sort has no tie to break --
	// a tie order depends on Go's randomized map iteration and would make this
	// fixture flaky across independent Overview()/TopIPs() calls, unrelated to
	// Snapshot/Restore correctness.
	add("1.1.1.1", "/api/products/1", 200, base)
	add("1.1.1.1", "/api/products/2", 404, base.Add(time.Minute))
	add("1.1.1.1", "/api/products/3", 200, base.Add(90*time.Second))
	add("2.2.2.2", "/api/products/3", 500, base.Add(2*time.Minute))
	add("2.2.2.2", "/health", 200, base.Add(3*time.Minute))
	return s
}

func TestStoreSnapshotRestoreRoundTrip(t *testing.T) {
	s := buildTestStore(t)

	wantOverview := s.Overview()
	wantIPs := s.TopIPs(50)
	wantEndpoints := s.TopEndpoints(50)
	wantIPDetail, ok := s.IPDetail("1.1.1.1")
	if !ok {
		t.Fatal("expected IP detail for 1.1.1.1")
	}

	snap := s.Snapshot()

	restored := NewStore(24 * time.Hour)
	restored.Restore(snap)

	if got := restored.Overview(); !reflect.DeepEqual(got, wantOverview) {
		t.Errorf("Overview mismatch after restore:\n got=%+v\nwant=%+v", got, wantOverview)
	}
	if got := restored.TopIPs(50); !reflect.DeepEqual(got, wantIPs) {
		t.Errorf("TopIPs mismatch after restore:\n got=%+v\nwant=%+v", got, wantIPs)
	}
	if got := restored.TopEndpoints(50); !reflect.DeepEqual(got, wantEndpoints) {
		t.Errorf("TopEndpoints mismatch after restore:\n got=%+v\nwant=%+v", got, wantEndpoints)
	}
	gotIPDetail, ok := restored.IPDetail("1.1.1.1")
	if !ok {
		t.Fatal("expected IP detail for 1.1.1.1 after restore")
	}
	if !reflect.DeepEqual(gotIPDetail, wantIPDetail) {
		t.Errorf("IPDetail mismatch after restore:\n got=%+v\nwant=%+v", gotIPDetail, wantIPDetail)
	}
}

func TestSaveLoadSnapshotGobRoundTrip(t *testing.T) {
	s := buildTestStore(t)
	snap := s.Snapshot()
	snap.SavedAt = time.Date(2026, 7, 20, 13, 0, 0, 0, time.UTC)

	path := filepath.Join(t.TempDir(), "store.gob")
	if err := SaveSnapshot(path, snap); err != nil {
		t.Fatalf("SaveSnapshot: %v", err)
	}

	loaded, err := LoadSnapshot(path)
	if err != nil {
		t.Fatalf("LoadSnapshot: %v", err)
	}
	if !loaded.SavedAt.Equal(snap.SavedAt) {
		t.Errorf("SavedAt = %v, want %v", loaded.SavedAt, snap.SavedAt)
	}

	restored := NewStore(24 * time.Hour)
	restored.Restore(loaded)
	if got, want := restored.Overview().Total, s.Overview().Total; got != want {
		t.Errorf("total after disk round-trip = %d, want %d", got, want)
	}
}

func TestLoadSnapshotMissingFile(t *testing.T) {
	_, err := LoadSnapshot(filepath.Join(t.TempDir(), "does-not-exist.gob"))
	if err == nil {
		t.Fatal("expected an error for a missing snapshot file")
	}
}

func TestSavePositionsRoundTrip(t *testing.T) {
	p := Positions{
		SavedAt: time.Date(2026, 7, 20, 13, 0, 0, 0, time.UTC),
		Files: map[string]FilePosition{
			"/var/log/nginx/access.log": {Offset: 12345, Size: 999999, ModTime: time.Now()},
		},
	}
	path := filepath.Join(t.TempDir(), "positions.json")
	if err := SavePositions(path, p); err != nil {
		t.Fatalf("SavePositions: %v", err)
	}
	loaded, err := LoadPositions(path)
	if err != nil {
		t.Fatalf("LoadPositions: %v", err)
	}
	if loaded.Files["/var/log/nginx/access.log"].Offset != 12345 {
		t.Errorf("offset = %d, want 12345", loaded.Files["/var/log/nginx/access.log"].Offset)
	}
}
