package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"knight/internal/config"
)

func TestConfigServiceRotateTokenPersistsAndSwapsLive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfg := &config.Config{Auth: config.AuthConfig{ViewerToken: "view-orig", AdminToken: "admin-orig"}}
	auth := NewAuth(cfg.Auth.ViewerToken, cfg.Auth.AdminToken)
	svc := NewConfigService(path, cfg, nil, nil, nil, auth)

	newAdmin, err := svc.RotateToken("admin")
	if err != nil {
		t.Fatalf("RotateToken(admin): %v", err)
	}
	if newAdmin == "" || newAdmin == "admin-orig" {
		t.Fatalf("expected a fresh admin token, got %q", newAdmin)
	}

	// Live Auth must enforce the new token immediately, and reject the old one.
	w := httptest.NewRecorder()
	auth.requireAdmin(handlerOK)(w, request("admin-orig"))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("old admin token should be rejected live, got status %d", w.Code)
	}
	w = httptest.NewRecorder()
	auth.requireAdmin(handlerOK)(w, request(newAdmin))
	if w.Code != http.StatusOK {
		t.Errorf("new admin token should be accepted live, got status %d", w.Code)
	}

	// Viewer token must be untouched.
	w = httptest.NewRecorder()
	auth.requireViewer(handlerOK)(w, request("view-orig"))
	if w.Code != http.StatusOK {
		t.Errorf("viewer token should survive an admin rotation, got status %d", w.Code)
	}

	// Disk must reflect the rotation, so a restart loads the same token.
	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if reloaded.Auth.AdminToken != newAdmin {
		t.Errorf("persisted admin token = %q, want %q", reloaded.Auth.AdminToken, newAdmin)
	}
	if reloaded.Auth.ViewerToken != "view-orig" {
		t.Errorf("persisted viewer token changed unexpectedly: %q", reloaded.Auth.ViewerToken)
	}
}

func TestConfigServiceRotateTokenRejectsUnknownTier(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfg := &config.Config{Auth: config.AuthConfig{ViewerToken: "v", AdminToken: "a"}}
	auth := NewAuth(cfg.Auth.ViewerToken, cfg.Auth.AdminToken)
	svc := NewConfigService(path, cfg, nil, nil, nil, auth)

	if _, err := svc.RotateToken("superadmin"); err == nil {
		t.Fatal("expected an error for an unknown token tier, got nil")
	}
}

func TestConfigServiceRotateTokenSaveFailureLeavesLiveStateUntouched(t *testing.T) {
	// A path inside a nonexistent directory makes Save fail (no such
	// directory to rename into), simulating a disk/permission problem.
	path := filepath.Join(t.TempDir(), "missing-dir", "config.json")
	cfg := &config.Config{Auth: config.AuthConfig{ViewerToken: "view-orig", AdminToken: "admin-orig"}}
	auth := NewAuth(cfg.Auth.ViewerToken, cfg.Auth.AdminToken)
	svc := NewConfigService(path, cfg, nil, nil, nil, auth)

	if _, err := svc.RotateToken("admin"); err == nil {
		t.Fatal("expected RotateToken to fail when Save cannot write to disk")
	}

	// In-memory cfg AND the live Auth must both still be the original token --
	// never partially swapped just because the persist step failed.
	if cfg.Auth.AdminToken != "admin-orig" {
		t.Errorf("cfg.Auth.AdminToken changed despite failed save: %q", cfg.Auth.AdminToken)
	}
	w := httptest.NewRecorder()
	auth.requireAdmin(handlerOK)(w, request("admin-orig"))
	if w.Code != http.StatusOK {
		t.Errorf("original admin token should still work after a failed rotation, got status %d", w.Code)
	}

	if _, err := os.Stat(path); err == nil {
		t.Error("config file should not have been created by a failed save")
	}
}
