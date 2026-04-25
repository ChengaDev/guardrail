package remediation

import (
	"context"
	"errors"
	"testing"

	"github.com/ChengaDev/guardrail/internal/osv"
)

// --- compareVersions ---

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"2.0.0", "1.0.0", 1},
		{"1.0.0", "2.0.0", -1},
		{"1.2.3", "1.2.4", -1},
		{"1.10.0", "1.9.0", 1},  // numeric, not lexicographic
		{"1.0.0", "1.0.0-rc1", 1}, // pre-release < release
		{"1.0.0-rc1", "1.0.0", -1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"v1.2.3", "1.2.3", 0}, // v-prefix stripped
		{"1.0", "1.0.0", 0},    // missing patch treated as 0
		{"0", "0.0.0", 0},
	}

	for _, tt := range tests {
		got := compareVersions(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

// --- maxVersion / minVersion ---

func TestMaxVersion(t *testing.T) {
	tests := []struct {
		versions []string
		want     string
	}{
		{[]string{"1.0.0", "2.0.0", "1.5.0"}, "2.0.0"},
		{[]string{"4.17.21"}, "4.17.21"},
		{[]string{"1.0.0-rc1", "1.0.0"}, "1.0.0"},
		{[]string{}, ""},
	}

	for _, tt := range tests {
		got := maxVersion(tt.versions)
		if got != tt.want {
			t.Errorf("maxVersion(%v) = %q, want %q", tt.versions, got, tt.want)
		}
	}
}

func TestMinVersion(t *testing.T) {
	tests := []struct {
		versions []string
		want     string
	}{
		{[]string{"1.0.0", "2.0.0", "0.5.0"}, "0.5.0"},
		{[]string{"4.17.21"}, "4.17.21"},
		{[]string{"1.0.0", "1.0.0-rc1"}, "1.0.0-rc1"},
		{[]string{}, ""},
	}

	for _, tt := range tests {
		got := minVersion(tt.versions)
		if got != tt.want {
			t.Errorf("minVersion(%v) = %q, want %q", tt.versions, got, tt.want)
		}
	}
}

// --- helpers ---

func makeVuln(ecosystem, name string, introduced, fixed string) osv.Vuln {
	events := []osv.RangeEvent{}
	if introduced != "" {
		events = append(events, osv.RangeEvent{Introduced: introduced})
	}
	if fixed != "" {
		events = append(events, osv.RangeEvent{Fixed: fixed})
	}
	return osv.Vuln{
		ID: "GHSA-test-0001",
		Affected: []osv.Affected{
			{
				Package: osv.AffectedPackage{Ecosystem: ecosystem, Name: name},
				Ranges: []osv.AffectedRange{
					{Type: "SEMVER", Events: events},
				},
			},
		},
	}
}

// --- Suggest ---

func TestSuggest_NoVulns(t *testing.T) {
	sug, err := Suggest(context.Background(), nil, "npm", "express", "4.17.0")
	if err != nil || sug != nil {
		t.Errorf("Suggest with no vulns: got (%v, %v), want (nil, nil)", sug, err)
	}
}

func TestSuggest_KindPatch_SingleFix(t *testing.T) {
	vulns := []osv.Vuln{makeVuln("npm", "express", "0", "4.18.0")}
	sug, err := Suggest(context.Background(), vulns, "npm", "express", "4.17.0")
	if err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	if sug == nil {
		t.Fatal("expected suggestion, got nil")
	}
	if sug.Kind != KindPatch {
		t.Errorf("Kind = %q, want %q", sug.Kind, KindPatch)
	}
	if sug.Version != "4.18.0" {
		t.Errorf("Version = %q, want %q", sug.Version, "4.18.0")
	}
}

func TestSuggest_KindPatch_MaxOfMultipleFixes(t *testing.T) {
	// Two vulns with different fixed versions — should recommend the higher one.
	v1 := makeVuln("npm", "lodash", "0", "4.17.20")
	v2 := makeVuln("npm", "lodash", "0", "4.17.21")
	sug, err := Suggest(context.Background(), []osv.Vuln{v1, v2}, "npm", "lodash", "4.17.19")
	if err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	if sug == nil || sug.Version != "4.17.21" {
		t.Errorf("expected 4.17.21, got %v", sug)
	}
	if sug.Kind != KindPatch {
		t.Errorf("Kind = %q, want KindPatch", sug.Kind)
	}
}

func TestSuggest_KindPatch_EcosystemCaseInsensitive(t *testing.T) {
	// OSV often uses "PyPI" while we use "pypi" internally.
	v := makeVuln("PyPI", "django", "0", "4.2.1")
	sug, err := Suggest(context.Background(), []osv.Vuln{v}, "pypi", "django", "4.2.0")
	if err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	if sug == nil || sug.Version != "4.2.1" {
		t.Errorf("expected 4.2.1 for PyPI/pypi match, got %v", sug)
	}
}

func TestSuggest_KindPatch_EcosystemCratesIO(t *testing.T) {
	// OSV uses "crates.io" while we use "cargo".
	v := makeVuln("crates.io", "serde", "0", "1.0.100")
	sug, err := Suggest(context.Background(), []osv.Vuln{v}, "cargo", "serde", "1.0.0")
	if err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	if sug == nil || sug.Version != "1.0.100" {
		t.Errorf("expected 1.0.100, got %v", sug)
	}
}

func TestSuggest_KindPatch_EcosystemMismatch(t *testing.T) {
	// Affected entry is for npm but we query for pypi — should find no fix.
	// Falls through to KindLastSafe path, which returns nil when no intro version exists either.
	v := makeVuln("npm", "somelib", "0", "2.0.0")
	// Make the introduced version "0" which we skip, so allIntroduced is empty.
	sug, err := Suggest(context.Background(), []osv.Vuln{v}, "pypi", "somelib", "1.0.0")
	if err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	if sug != nil {
		t.Errorf("expected nil for ecosystem mismatch, got %+v", sug)
	}
}

func TestSuggest_KindLastSafe(t *testing.T) {
	// No fixed version; vulnerability introduced in 2.0.0.
	// Registry reports [1.0.0, 1.5.0, 1.9.0, 2.0.0, 2.1.0].
	// Last safe version is 1.9.0 (highest below 2.0.0).
	v := osv.Vuln{
		ID: "GHSA-test-0002",
		Affected: []osv.Affected{
			{
				Package: osv.AffectedPackage{Ecosystem: "npm", Name: "badpkg"},
				Ranges: []osv.AffectedRange{
					{
						Type:   "SEMVER",
						Events: []osv.RangeEvent{{Introduced: "2.0.0"}},
					},
				},
			},
		},
	}

	registryVersions := []string{"1.0.0", "1.5.0", "1.9.0", "2.0.0", "2.1.0"}
	old := fetchAllVersions
	fetchAllVersions = func(_ context.Context, _, _ string) ([]string, error) {
		return registryVersions, nil
	}
	t.Cleanup(func() { fetchAllVersions = old })

	sug, err := Suggest(context.Background(), []osv.Vuln{v}, "npm", "badpkg", "2.1.0")
	if err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	if sug == nil {
		t.Fatal("expected a suggestion, got nil")
	}
	if sug.Kind != KindLastSafe {
		t.Errorf("Kind = %q, want KindLastSafe", sug.Kind)
	}
	if sug.Version != "1.9.0" {
		t.Errorf("Version = %q, want %q", sug.Version, "1.9.0")
	}
}

func TestSuggest_KindLastSafe_NoVersionsBeforeIntro(t *testing.T) {
	// Vulnerability introduced from the very first published version.
	v := osv.Vuln{
		ID: "GHSA-test-0003",
		Affected: []osv.Affected{
			{
				Package: osv.AffectedPackage{Ecosystem: "npm", Name: "badpkg"},
				Ranges: []osv.AffectedRange{
					{
						Type:   "SEMVER",
						Events: []osv.RangeEvent{{Introduced: "1.0.0"}},
					},
				},
			},
		},
	}

	old := fetchAllVersions
	fetchAllVersions = func(_ context.Context, _, _ string) ([]string, error) {
		return []string{"1.0.0", "1.1.0", "2.0.0"}, nil
	}
	t.Cleanup(func() { fetchAllVersions = old })

	sug, err := Suggest(context.Background(), []osv.Vuln{v}, "npm", "badpkg", "2.0.0")
	if err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	if sug != nil {
		t.Errorf("expected nil when no safe version exists, got %+v", sug)
	}
}

func TestSuggest_KindLastSafe_RegistryError(t *testing.T) {
	v := osv.Vuln{
		ID: "GHSA-test-0004",
		Affected: []osv.Affected{
			{
				Package: osv.AffectedPackage{Ecosystem: "npm", Name: "badpkg"},
				Ranges: []osv.AffectedRange{
					{Type: "SEMVER", Events: []osv.RangeEvent{{Introduced: "2.0.0"}}},
				},
			},
		},
	}

	old := fetchAllVersions
	fetchAllVersions = func(_ context.Context, _, _ string) ([]string, error) {
		return nil, errors.New("registry unreachable")
	}
	t.Cleanup(func() { fetchAllVersions = old })

	sug, err := Suggest(context.Background(), []osv.Vuln{v}, "npm", "badpkg", "2.0.0")
	// Should propagate the error and return nil suggestion.
	if err == nil {
		t.Error("expected error from registry failure, got nil")
	}
	if sug != nil {
		t.Errorf("expected nil suggestion on registry error, got %+v", sug)
	}
}

func TestSuggest_IntroducedZeroSkipped(t *testing.T) {
	// "introduced: 0" means "from the beginning" and should not be used as a cutoff
	// for the rollback suggestion. Without other intro events and with no fixed version,
	// Suggest should return nil.
	v := osv.Vuln{
		ID: "GHSA-test-0005",
		Affected: []osv.Affected{
			{
				Package: osv.AffectedPackage{Ecosystem: "npm", Name: "pkg"},
				Ranges: []osv.AffectedRange{
					{Type: "SEMVER", Events: []osv.RangeEvent{{Introduced: "0"}}},
				},
			},
		},
	}

	sug, err := Suggest(context.Background(), []osv.Vuln{v}, "npm", "pkg", "1.0.0")
	if err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	if sug != nil {
		t.Errorf("introduced=0 should not yield a suggestion, got %+v", sug)
	}
}

func TestSuggest_GitRangeIgnored(t *testing.T) {
	// GIT ranges should be ignored; only SEMVER/ECOSYSTEM ranges count.
	v := osv.Vuln{
		ID: "GHSA-test-0006",
		Affected: []osv.Affected{
			{
				Package: osv.AffectedPackage{Ecosystem: "npm", Name: "pkg"},
				Ranges: []osv.AffectedRange{
					{
						Type:   "GIT",
						Events: []osv.RangeEvent{{Introduced: "abc123"}, {Fixed: "def456"}},
					},
				},
			},
		},
	}

	sug, err := Suggest(context.Background(), []osv.Vuln{v}, "npm", "pkg", "1.0.0")
	if err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	if sug != nil {
		t.Errorf("GIT range should not yield a suggestion, got %+v", sug)
	}
}

// --- Integration test (real registry) ---

func TestIntegration_Suggest_KnownPatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// lodash@4.17.20 has a known prototype pollution fix in 4.17.21.
	v := osv.Vuln{
		ID: "GHSA-p6mc-m468-83gw",
		Affected: []osv.Affected{
			{
				Package: osv.AffectedPackage{Ecosystem: "npm", Name: "lodash"},
				Ranges: []osv.AffectedRange{
					{Type: "SEMVER", Events: []osv.RangeEvent{
						{Introduced: "0"},
						{Fixed: "4.17.21"},
					}},
				},
			},
		},
	}

	sug, err := Suggest(context.Background(), []osv.Vuln{v}, "npm", "lodash", "4.17.20")
	if err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	if sug == nil {
		t.Fatal("expected a suggestion, got nil")
	}
	if sug.Kind != KindPatch {
		t.Errorf("Kind = %q, want KindPatch", sug.Kind)
	}
	if sug.Version != "4.17.21" {
		t.Errorf("Version = %q, want 4.17.21", sug.Version)
	}
}
