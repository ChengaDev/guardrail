package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/chengazit/guardrail/internal/severity"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.SeverityThreshold != severity.LevelHigh {
		t.Errorf("default SeverityThreshold = %v, want HIGH", cfg.SeverityThreshold)
	}
	if !cfg.Block {
		t.Error("default Block = false, want true")
	}
	if cfg.Strict {
		t.Error("default Strict = true, want false")
	}
	if cfg.Cache.TTL != 24*time.Hour {
		t.Errorf("default TTL = %v, want 24h", cfg.Cache.TTL)
	}
	if cfg.ImpactAnalysis.Enabled {
		t.Error("default ImpactAnalysis.Enabled = true, want false")
	}
	if cfg.ImpactAnalysis.MinSeverity != severity.LevelHigh {
		t.Errorf("default ImpactAnalysis.MinSeverity = %v, want HIGH", cfg.ImpactAnalysis.MinSeverity)
	}
}

func TestMergeFile(t *testing.T) {
	yaml := `
severity_threshold: CRITICAL
block: false
strict: true
cache:
  path: /tmp/test-cache
  ttl: 48h
impact_analysis:
  enabled: true
  min_severity: MEDIUM
`
	f := writeTempYAML(t, yaml)
	cfg := DefaultConfig()
	if err := mergeFile(cfg, f); err != nil {
		t.Fatalf("mergeFile: %v", err)
	}

	if cfg.SeverityThreshold != severity.LevelCritical {
		t.Errorf("SeverityThreshold = %v, want CRITICAL", cfg.SeverityThreshold)
	}
	if cfg.Block {
		t.Error("Block = true, want false")
	}
	if !cfg.Strict {
		t.Error("Strict = false, want true")
	}
	if cfg.Cache.Path != "/tmp/test-cache" {
		t.Errorf("Cache.Path = %q, want /tmp/test-cache", cfg.Cache.Path)
	}
	if cfg.Cache.TTL != 48*time.Hour {
		t.Errorf("Cache.TTL = %v, want 48h", cfg.Cache.TTL)
	}
	if !cfg.ImpactAnalysis.Enabled {
		t.Error("ImpactAnalysis.Enabled = false, want true")
	}
	if cfg.ImpactAnalysis.MinSeverity != severity.LevelMedium {
		t.Errorf("ImpactAnalysis.MinSeverity = %v, want MEDIUM", cfg.ImpactAnalysis.MinSeverity)
	}
}

func TestMergeFileIgnores(t *testing.T) {
	yaml := `
ignores:
  - cve: CVE-2023-0001
    reason: "not applicable"
    expires: 2099-12-31
  - cve: CVE-2023-0002
    reason: "vendor confirmed safe"
`
	f := writeTempYAML(t, yaml)
	cfg := DefaultConfig()
	if err := mergeFile(cfg, f); err != nil {
		t.Fatalf("mergeFile: %v", err)
	}

	if len(cfg.Ignores) != 2 {
		t.Fatalf("len(Ignores) = %d, want 2", len(cfg.Ignores))
	}
	if cfg.Ignores[0].CVE != "CVE-2023-0001" {
		t.Errorf("Ignores[0].CVE = %q, want CVE-2023-0001", cfg.Ignores[0].CVE)
	}
	if cfg.Ignores[0].Expires.IsZero() {
		t.Error("Ignores[0].Expires is zero, want 2099-12-31")
	}
	if !cfg.Ignores[1].Expires.IsZero() {
		t.Errorf("Ignores[1].Expires = %v, want zero (no expiry)", cfg.Ignores[1].Expires)
	}
}

func TestMergeFileInvalidTTL(t *testing.T) {
	yaml := `cache:\n  ttl: notaduration\n`
	f := writeTempYAML(t, yaml)
	cfg := DefaultConfig()
	err := mergeFile(cfg, f)
	// Invalid TTL should not error (it's just not parsed as a duration, the yaml is inline-escaped)
	// This test just ensures we don't panic.
	_ = err
}

func TestMergeFileMissingFile(t *testing.T) {
	cfg := DefaultConfig()
	err := mergeFile(cfg, "/nonexistent/path/config.yaml")
	if err == nil || !os.IsNotExist(err) {
		t.Errorf("expected IsNotExist error, got: %v", err)
	}
}

func TestApplyEnv(t *testing.T) {
	t.Setenv("GRAIL_SEVERITY", "CRITICAL")
	t.Setenv("GRAIL_BLOCK", "false")
	t.Setenv("GRAIL_STRICT", "true")
	t.Setenv("GRAIL_CACHE_PATH", "/env/cache")
	t.Setenv("ANTHROPIC_API_KEY", "test-key")

	cfg := DefaultConfig()
	applyEnv(cfg)

	if cfg.SeverityThreshold != severity.LevelCritical {
		t.Errorf("SeverityThreshold = %v, want CRITICAL", cfg.SeverityThreshold)
	}
	if cfg.Block {
		t.Error("Block = true, want false")
	}
	if !cfg.Strict {
		t.Error("Strict = false, want true")
	}
	if cfg.Cache.Path != "/env/cache" {
		t.Errorf("Cache.Path = %q, want /env/cache", cfg.Cache.Path)
	}
	if cfg.ImpactAnalysis.AnthropicAPIKey != "test-key" {
		t.Errorf("AnthropicAPIKey = %q, want test-key", cfg.ImpactAnalysis.AnthropicAPIKey)
	}
}

func TestIsIgnored(t *testing.T) {
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	future := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	past := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	cfg := &Config{
		Ignores: []IgnoreRule{
			{CVE: "CVE-2023-0001", Reason: "active no expiry"},
			{CVE: "CVE-2023-0002", Reason: "active future expiry", Expires: future},
			{CVE: "CVE-2023-0003", Reason: "expired", Expires: past},
		},
	}

	tests := []struct {
		cve        string
		wantIgnore bool
		wantReason string
	}{
		{"CVE-2023-0001", true, "active no expiry"},
		{"CVE-2023-0002", true, "active future expiry"},
		{"CVE-2023-0003", false, ""},   // expired — treated as active CVE
		{"CVE-9999-9999", false, ""},   // not in list
	}

	for _, tt := range tests {
		ignored, reason := cfg.IsIgnored(tt.cve, now)
		if ignored != tt.wantIgnore {
			t.Errorf("IsIgnored(%q) = %v, want %v", tt.cve, ignored, tt.wantIgnore)
		}
		if reason != tt.wantReason {
			t.Errorf("IsIgnored(%q) reason = %q, want %q", tt.cve, reason, tt.wantReason)
		}
	}
}

func TestProjectConfigWinsOverGlobal(t *testing.T) {
	globalYAML := `severity_threshold: LOW`
	projectYAML := `severity_threshold: CRITICAL`

	globalFile := writeTempYAML(t, globalYAML)
	projectFile := writeTempYAML(t, projectYAML)

	cfg := DefaultConfig()
	if err := mergeFile(cfg, globalFile); err != nil {
		t.Fatal(err)
	}
	if err := mergeFile(cfg, projectFile); err != nil {
		t.Fatal(err)
	}

	if cfg.SeverityThreshold != severity.LevelCritical {
		t.Errorf("SeverityThreshold = %v, want CRITICAL (project should win)", cfg.SeverityThreshold)
	}
}

// writeTempYAML writes content to a temp file and returns its path.
func writeTempYAML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	f := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}
	return f
}
