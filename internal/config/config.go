// Package config handles loading, merging, and validating guirdrail configuration.
// Config files are YAML; project-level (.guirdrail.yaml) wins over global (~/.guirdrail/config.yaml).
// Environment variables override both.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ChengaDev/guardrail/internal/severity"
)

// Config is the fully-resolved configuration used at runtime.
type Config struct {
	SeverityThreshold severity.Level
	Block             bool
	Strict            bool
	Cache             CacheConfig
	ImpactAnalysis    ImpactAnalysisConfig
	Ignores           []IgnoreRule
	PackageManagers   map[string]PMConfig
}

// CacheConfig holds cache-related settings.
type CacheConfig struct {
	Path string
	TTL  time.Duration
}

// ImpactAnalysisConfig holds LLM analysis settings.
type ImpactAnalysisConfig struct {
	Enabled         bool
	AnthropicAPIKey string
	MinSeverity     severity.Level
}

// IgnoreRule represents a single CVE ignore entry.
type IgnoreRule struct {
	CVE     string
	Reason  string
	Expires time.Time // zero value = never expires
}

// PMConfig holds per-package-manager settings.
type PMConfig struct {
	Enabled bool
	Binary  string
}

// rawConfig mirrors the YAML structure for unmarshalling.
type rawConfig struct {
	SeverityThreshold string `yaml:"severity_threshold"`
	Block             *bool  `yaml:"block"`
	Strict            *bool  `yaml:"strict"`
	Cache             struct {
		Path string `yaml:"path"`
		TTL  string `yaml:"ttl"`
	} `yaml:"cache"`
	ImpactAnalysis struct {
		Enabled         *bool  `yaml:"enabled"`
		AnthropicAPIKey string `yaml:"anthropic_api_key"`
		MinSeverity     string `yaml:"min_severity"`
	} `yaml:"impact_analysis"`
	Ignores []struct {
		CVE     string `yaml:"cve"`
		Reason  string `yaml:"reason"`
		Expires string `yaml:"expires"`
	} `yaml:"ignores"`
	PackageManagers map[string]struct {
		Enabled *bool  `yaml:"enabled"`
		Binary  string `yaml:"binary"`
	} `yaml:"package_managers"`
}

// DefaultConfig returns the built-in defaults.
func DefaultConfig() *Config {
	home, _ := os.UserHomeDir()
	return &Config{
		SeverityThreshold: severity.LevelHigh,
		Block:             true,
		Strict:            false,
		Cache: CacheConfig{
			Path: filepath.Join(home, ".guirdrail", "cache"),
			TTL:  24 * time.Hour,
		},
		ImpactAnalysis: ImpactAnalysisConfig{
			Enabled:     false,
			MinSeverity: severity.LevelHigh,
		},
		Ignores: nil,
		PackageManagers: map[string]PMConfig{
			"npm":   {Enabled: true, Binary: "npm"},
			"yarn":  {Enabled: true, Binary: "yarn"},
			"pnpm":  {Enabled: true, Binary: "pnpm"},
			"pip":   {Enabled: true, Binary: "pip"},
			"poetry": {Enabled: true, Binary: "poetry"},
			"uv":    {Enabled: true, Binary: "uv"},
			"cargo": {Enabled: true, Binary: "cargo"},
			"go":    {Enabled: true, Binary: "go"},
		},
	}
}

// Load reads, merges, and resolves the final configuration.
// Lookup order:
//  1. Built-in defaults
//  2. Global config (~/.guirdrail/config.yaml)
//  3. Project config (.guirdrail.yaml in cwd)
//  4. Environment variable overrides
func Load() (*Config, error) {
	cfg := DefaultConfig()

	// Allow GRAIL_CONFIG to point to a specific file
	if p := os.Getenv("GRAIL_CONFIG"); p != "" {
		if err := mergeFile(cfg, p); err != nil {
			return nil, fmt.Errorf("loading config from GRAIL_CONFIG=%s: %w", p, err)
		}
		applyEnv(cfg)
		return cfg, nil
	}

	// Global config
	home, _ := os.UserHomeDir()
	if err := mergeFile(cfg, filepath.Join(home, ".guirdrail", "config.yaml")); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("loading global config: %w", err)
	}

	// Project-level config
	if err := mergeFile(cfg, ".guirdrail.yaml"); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("loading project config: %w", err)
	}

	applyEnv(cfg)
	return cfg, nil
}

// mergeFile reads a YAML file and merges its values into cfg.
// Missing file returns os.IsNotExist error so callers can decide to ignore it.
func mergeFile(cfg *Config, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var raw rawConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	return mergeRaw(cfg, &raw)
}

func mergeRaw(cfg *Config, raw *rawConfig) error {
	if raw.SeverityThreshold != "" {
		cfg.SeverityThreshold = severity.Parse(raw.SeverityThreshold)
	}
	if raw.Block != nil {
		cfg.Block = *raw.Block
	}
	if raw.Strict != nil {
		cfg.Strict = *raw.Strict
	}
	if raw.Cache.Path != "" {
		cfg.Cache.Path = raw.Cache.Path
	}
	if raw.Cache.TTL != "" {
		d, err := time.ParseDuration(raw.Cache.TTL)
		if err != nil {
			return fmt.Errorf("invalid cache.ttl %q: %w", raw.Cache.TTL, err)
		}
		cfg.Cache.TTL = d
	}
	if raw.ImpactAnalysis.Enabled != nil {
		cfg.ImpactAnalysis.Enabled = *raw.ImpactAnalysis.Enabled
	}
	if raw.ImpactAnalysis.AnthropicAPIKey != "" {
		cfg.ImpactAnalysis.AnthropicAPIKey = raw.ImpactAnalysis.AnthropicAPIKey
	}
	if raw.ImpactAnalysis.MinSeverity != "" {
		cfg.ImpactAnalysis.MinSeverity = severity.Parse(raw.ImpactAnalysis.MinSeverity)
	}
	for _, ig := range raw.Ignores {
		rule := IgnoreRule{CVE: ig.CVE, Reason: ig.Reason}
		if ig.Expires != "" {
			t, err := time.Parse("2006-01-02", ig.Expires)
			if err != nil {
				return fmt.Errorf("invalid expires date %q: %w", ig.Expires, err)
			}
			rule.Expires = t
		}
		cfg.Ignores = append(cfg.Ignores, rule)
	}
	for pm, rawPM := range raw.PackageManagers {
		existing := cfg.PackageManagers[pm]
		if rawPM.Enabled != nil {
			existing.Enabled = *rawPM.Enabled
		}
		if rawPM.Binary != "" {
			existing.Binary = rawPM.Binary
		}
		cfg.PackageManagers[pm] = existing
	}
	return nil
}

// applyEnv applies environment variable overrides to cfg.
func applyEnv(cfg *Config) {
	if v := os.Getenv("GRAIL_SEVERITY"); v != "" {
		cfg.SeverityThreshold = severity.Parse(v)
	}
	if v := os.Getenv("GRAIL_BLOCK"); v != "" {
		cfg.Block = parseBoolEnv(v, cfg.Block)
	}
	if v := os.Getenv("GRAIL_STRICT"); v != "" {
		cfg.Strict = parseBoolEnv(v, cfg.Strict)
	}
	if v := os.Getenv("GRAIL_CACHE_PATH"); v != "" {
		cfg.Cache.Path = v
	}
	if v := os.Getenv("ANTHROPIC_API_KEY"); v != "" {
		cfg.ImpactAnalysis.AnthropicAPIKey = v
	}
}

func parseBoolEnv(s string, fallback bool) bool {
	switch strings.ToLower(s) {
	case "1", "true", "yes":
		return true
	case "0", "false", "no":
		return false
	}
	return fallback
}

// IsIgnored checks if a CVE ID is in the active ignore list (not expired).
func (c *Config) IsIgnored(cveID string, now time.Time) (bool, string) {
	for _, rule := range c.Ignores {
		if rule.CVE == cveID {
			if rule.Expires.IsZero() || now.Before(rule.Expires) {
				return true, rule.Reason
			}
		}
	}
	return false, ""
}

// Expand expands ~ in cache path.
func (c *Config) ExpandCachePath() {
	if strings.HasPrefix(c.Cache.Path, "~/") {
		home, _ := os.UserHomeDir()
		c.Cache.Path = filepath.Join(home, c.Cache.Path[2:])
	}
}
