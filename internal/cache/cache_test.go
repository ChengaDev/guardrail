package cache

import (
	"testing"
	"time"

	"github.com/chengazit/guardrail/internal/osv"
)

func newTestCache(t *testing.T, ttl time.Duration) *Cache {
	t.Helper()
	c, err := New(t.TempDir(), ttl)
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	return c
}

func TestSetAndGet(t *testing.T) {
	c := newTestCache(t, time.Hour)

	purl := "pkg:npm/express@4.18.2"
	vulns := []osv.Vuln{
		{ID: "GHSA-abc-def", Summary: "test vuln"},
	}

	if err := c.Set(purl, vulns); err != nil {
		t.Fatalf("Set: %v", err)
	}

	entry, err := c.Get(purl)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if entry == nil {
		t.Fatal("Get returned nil, want entry")
	}
	if entry.PURL != purl {
		t.Errorf("entry.PURL = %q, want %q", entry.PURL, purl)
	}
	if len(entry.Vulns) != 1 || entry.Vulns[0].ID != "GHSA-abc-def" {
		t.Errorf("unexpected vulns: %+v", entry.Vulns)
	}
}

func TestGetMiss(t *testing.T) {
	c := newTestCache(t, time.Hour)

	entry, err := c.Get("pkg:npm/nonexistent@1.0.0")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if entry != nil {
		t.Errorf("Get on missing key returned non-nil entry: %+v", entry)
	}
}

func TestGetExpired(t *testing.T) {
	c := newTestCache(t, time.Millisecond) // very short TTL

	purl := "pkg:npm/express@4.18.2"
	if err := c.Set(purl, nil); err != nil {
		t.Fatalf("Set: %v", err)
	}

	time.Sleep(5 * time.Millisecond) // let TTL expire

	entry, err := c.Get(purl)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if entry != nil {
		t.Error("expected nil (expired), got entry")
	}
}

func TestSetOverwrite(t *testing.T) {
	c := newTestCache(t, time.Hour)

	purl := "pkg:pypi/django@4.2.0"
	if err := c.Set(purl, []osv.Vuln{{ID: "first"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.Set(purl, []osv.Vuln{{ID: "second"}}); err != nil {
		t.Fatal(err)
	}

	entry, err := c.Get(purl)
	if err != nil || entry == nil {
		t.Fatalf("Get: err=%v entry=%v", err, entry)
	}
	if len(entry.Vulns) != 1 || entry.Vulns[0].ID != "second" {
		t.Errorf("expected overwritten entry, got: %+v", entry.Vulns)
	}
}

func TestDelete(t *testing.T) {
	c := newTestCache(t, time.Hour)

	purl := "pkg:cargo/serde@1.0.0"
	if err := c.Set(purl, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(purl); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	entry, err := c.Get(purl)
	if err != nil {
		t.Fatalf("Get after delete: %v", err)
	}
	if entry != nil {
		t.Error("entry still present after Delete")
	}
}

func TestDeleteNonExistent(t *testing.T) {
	c := newTestCache(t, time.Hour)
	// Should not error
	if err := c.Delete("pkg:npm/ghost@9.9.9"); err != nil {
		t.Errorf("Delete of non-existent key returned error: %v", err)
	}
}

func TestAllEntries(t *testing.T) {
	c := newTestCache(t, time.Hour)

	purls := []string{
		"pkg:npm/express@4.18.2",
		"pkg:pypi/django@4.2.0",
		"pkg:cargo/serde@1.0.0",
	}
	for _, p := range purls {
		if err := c.Set(p, nil); err != nil {
			t.Fatalf("Set(%q): %v", p, err)
		}
	}

	entries, err := c.AllEntries()
	if err != nil {
		t.Fatalf("AllEntries: %v", err)
	}
	if len(entries) != len(purls) {
		t.Errorf("AllEntries returned %d entries, want %d", len(entries), len(purls))
	}
}

func TestAllEntriesEmptyDir(t *testing.T) {
	c := newTestCache(t, time.Hour)
	entries, err := c.AllEntries()
	if err != nil {
		t.Fatalf("AllEntries on empty cache: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestAllEntriesSkipsExpired(t *testing.T) {
	// AllEntries currently returns all entries including expired ones —
	// the sync command uses AllEntries to get PURLs for re-fetching.
	// This test documents that behavior.
	c := newTestCache(t, time.Millisecond)

	purl := "pkg:npm/stale@1.0.0"
	if err := c.Set(purl, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)

	entries, err := c.AllEntries()
	if err != nil {
		t.Fatal(err)
	}
	// AllEntries does NOT filter by TTL — it returns everything in the dir.
	if len(entries) != 1 {
		t.Errorf("AllEntries returned %d entries, want 1 (expired entries included)", len(entries))
	}
}
