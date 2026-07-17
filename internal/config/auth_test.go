package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadGeneratesTokensOnFirstBoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"sites":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Auth.ViewerToken == "" || c.Auth.AdminToken == "" {
		t.Fatalf("expected both tokens to be generated, got %+v", c.Auth)
	}
	if c.Auth.ViewerToken == c.Auth.AdminToken {
		t.Error("viewer and admin tokens must not be identical")
	}
	viewerGen, adminGen := c.TokensGenerated()
	if !viewerGen || !adminGen {
		t.Errorf("expected TokensGenerated to report both as generated, got viewer=%v admin=%v", viewerGen, adminGen)
	}

	// The generated tokens must have been persisted to disk, not just held in memory.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk Config
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatal(err)
	}
	if onDisk.Auth.ViewerToken != c.Auth.ViewerToken || onDisk.Auth.AdminToken != c.Auth.AdminToken {
		t.Error("generated tokens were not persisted to the config file")
	}
}

func TestLoadDoesNotRegenerateExistingTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"sites":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	first, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	second, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if viewerGen, adminGen := second.TokensGenerated(); viewerGen || adminGen {
		t.Error("second Load of an already-tokened config must not regenerate")
	}
	if second.Auth.ViewerToken != first.Auth.ViewerToken || second.Auth.AdminToken != first.Auth.AdminToken {
		t.Error("tokens must stay stable across restarts (a rotating token would break every existing client)")
	}
}

func TestLoadPreservesManuallySetTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := `{"sites":[],"auth":{"viewer_token":"my-viewer","admin_token":"my-admin"}}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Auth.ViewerToken != "my-viewer" || c.Auth.AdminToken != "my-admin" {
		t.Errorf("expected manually-set tokens to be preserved, got %+v", c.Auth)
	}
	if viewerGen, adminGen := c.TokensGenerated(); viewerGen || adminGen {
		t.Error("must not report generation when tokens were already set")
	}
}
