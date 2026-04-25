// Package cache provides a local file-based CVE result cache.
// Keys are SHA-256 of the PURL; values are JSON-encoded OSV results + timestamp.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/chengazit/guardrail/internal/osv"
)

// Entry is a single cache record stored on disk.
type Entry struct {
	PURL      string     `json:"purl"`
	FetchedAt time.Time  `json:"fetched_at"`
	Vulns     []osv.Vuln `json:"vulns"`
}

// Cache manages a directory of cached OSV query results.
type Cache struct {
	dir string
	ttl time.Duration
}

// New creates a Cache backed by dir with the given TTL.
// The directory is created if it does not exist.
func New(dir string, ttl time.Duration) (*Cache, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating cache dir %s: %w", dir, err)
	}
	return &Cache{dir: dir, ttl: ttl}, nil
}

// key returns the file path for a PURL.
func (c *Cache) key(purl string) string {
	sum := sha256.Sum256([]byte(purl))
	return filepath.Join(c.dir, hex.EncodeToString(sum[:]))
}

// Get returns the cached entry for purl, or (nil, nil) if not found / expired.
func (c *Cache) Get(purl string) (*Entry, error) {
	data, err := os.ReadFile(c.key(purl))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading cache entry: %w", err)
	}
	var entry Entry
	if err := json.Unmarshal(data, &entry); err != nil {
		// Corrupt entry — treat as miss
		return nil, nil
	}
	if time.Since(entry.FetchedAt) > c.ttl {
		return nil, nil // expired
	}
	return &entry, nil
}

// Set writes an entry to the cache.
func (c *Cache) Set(purl string, vulns []osv.Vuln) error {
	entry := Entry{
		PURL:      purl,
		FetchedAt: time.Now().UTC(),
		Vulns:     vulns,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshalling cache entry: %w", err)
	}
	path := c.key(purl)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing cache entry: %w", err)
	}
	return nil
}

// AllEntries reads every entry in the cache directory and returns them.
// Expired or corrupt entries are silently skipped.
func (c *Cache) AllEntries() ([]*Entry, error) {
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading cache dir: %w", err)
	}

	var result []*Entry
	for _, de := range entries {
		if de.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(c.dir, de.Name()))
		if err != nil {
			continue
		}
		var entry Entry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}
		result = append(result, &entry)
	}
	return result, nil
}

// Delete removes the cache entry for purl (used when refreshing).
func (c *Cache) Delete(purl string) error {
	err := os.Remove(c.key(purl))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
