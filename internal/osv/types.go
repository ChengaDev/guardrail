// Package osv provides types and a client for the OSV.dev API.
// API reference: https://google.github.io/osv.dev/api/
package osv

import (
	"fmt"
	"strings"

	"github.com/ChengaDev/guardrail/internal/severity"
)

// BatchRequest is the body sent to POST /v1/querybatch.
type BatchRequest struct {
	Queries []Query `json:"queries"`
}

// Query represents a single package query by PURL.
type Query struct {
	Package   PackageRef `json:"package"`
	PageToken string     `json:"page_token,omitempty"`
}

// PackageRef holds the PURL for a single package.
type PackageRef struct {
	PURL string `json:"purl"`
}

// BatchResponse is the top-level response from POST /v1/querybatch.
type BatchResponse struct {
	Results []QueryResult `json:"results"`
}

// QueryResult holds vulnerabilities for one queried package.
type QueryResult struct {
	Vulns         []Vuln `json:"vulns"`
	NextPageToken string `json:"next_page_token,omitempty"`
}

// Vuln is a single OSV vulnerability record.
type Vuln struct {
	ID               string            `json:"id"`
	Aliases          []string          `json:"aliases,omitempty"`
	Summary          string            `json:"summary,omitempty"`
	Details          string            `json:"details,omitempty"`
	Severity         []SevEntry        `json:"severity,omitempty"`
	References       []Reference       `json:"references,omitempty"`
	DatabaseSpecific *DatabaseSpecific `json:"database_specific,omitempty"`
	Affected         []Affected        `json:"affected,omitempty"`
}

// Affected describes the packages and version ranges affected by a vulnerability.
type Affected struct {
	Package  AffectedPackage `json:"package"`
	Ranges   []AffectedRange `json:"ranges,omitempty"`
	Versions []string        `json:"versions,omitempty"`
}

// AffectedPackage identifies the package within an affected entry.
type AffectedPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl,omitempty"`
}

// AffectedRange describes a version range in which a vulnerability is present.
type AffectedRange struct {
	Type   string       `json:"type"` // SEMVER, ECOSYSTEM, or GIT
	Events []RangeEvent `json:"events,omitempty"`
}

// RangeEvent marks the version at which a vulnerability was introduced or fixed.
type RangeEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// DatabaseSpecific holds advisory-database-specific metadata.
type DatabaseSpecific struct {
	// Severity is a plain-language severity label (e.g. "HIGH", "MODERATE").
	Severity string `json:"severity"`
}

// SevEntry holds a single severity rating (e.g. CVSS v3).
type SevEntry struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Reference is a link to an external advisory or fix.
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Level computes the normalised severity level for the vulnerability.
// Priority: CVSS numeric score → database_specific.severity → MEDIUM default.
func (v *Vuln) Level() severity.Level {
	best := severity.LevelNone
	for _, s := range v.Severity {
		score := parseCVSSScore(s.Score)
		if score > 0 {
			lvl := severity.FromCVSS(score)
			if lvl > best {
				best = lvl
			}
		}
	}
	if best != severity.LevelNone {
		return best
	}
	if v.DatabaseSpecific != nil && v.DatabaseSpecific.Severity != "" {
		return parseDBSeverity(v.DatabaseSpecific.Severity)
	}
	return severity.LevelMedium
}

func parseDBSeverity(s string) severity.Level {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return severity.LevelCritical
	case "HIGH":
		return severity.LevelHigh
	case "MODERATE", "MEDIUM":
		return severity.LevelMedium
	case "LOW":
		return severity.LevelLow
	default:
		return severity.LevelMedium
	}
}

// CVE returns the first CVE alias found, or the OSV id if none.
func (v *Vuln) CVE() string {
	for _, a := range v.Aliases {
		if len(a) > 4 && a[:4] == "CVE-" {
			return a
		}
	}
	return v.ID
}

// OSVLink returns the canonical OSV advisory URL.
func (v *Vuln) OSVLink() string {
	return "https://osv.dev/vulnerability/" + v.ID
}

// FixedVersions returns all versions that fix this vulnerability for the given
// ecosystem and package name. Returns nil if no fix is documented.
func (v *Vuln) FixedVersions(ecosystem, name string) []string {
	var fixed []string
	for _, a := range v.Affected {
		if !affectedMatches(a, ecosystem, name) {
			continue
		}
		for _, r := range a.Ranges {
			if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
				continue
			}
			for _, e := range r.Events {
				if e.Fixed != "" {
					fixed = append(fixed, e.Fixed)
				}
			}
		}
	}
	return fixed
}

// IntroducedVersions returns the versions at which this vulnerability was first
// introduced for the given ecosystem and package name.
func (v *Vuln) IntroducedVersions(ecosystem, name string) []string {
	var introduced []string
	for _, a := range v.Affected {
		if !affectedMatches(a, ecosystem, name) {
			continue
		}
		for _, r := range a.Ranges {
			if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
				continue
			}
			for _, e := range r.Events {
				// "0" means "from the beginning" — not useful for rollback suggestions.
				if e.Introduced != "" && e.Introduced != "0" {
					introduced = append(introduced, e.Introduced)
				}
			}
		}
	}
	return introduced
}

func affectedMatches(a Affected, ecosystem, name string) bool {
	return normalizeEcosystem(a.Package.Ecosystem) == normalizeEcosystem(ecosystem) &&
		strings.EqualFold(a.Package.Name, name)
}

// normalizeEcosystem maps OSV ecosystem labels to the internal names used by guardrail.
func normalizeEcosystem(eco string) string {
	switch strings.ToLower(eco) {
	case "npm":
		return "npm"
	case "pypi":
		return "pypi"
	case "cargo", "crates.io":
		return "cargo"
	case "golang", "go":
		return "golang"
	default:
		return strings.ToLower(eco)
	}
}

// parseCVSSScore extracts the numeric base score from a CVSS vector string.
// e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" → look for /BS: or use AV parsing
// Simpler: OSV also sometimes provides the score directly; we handle both forms.
func parseCVSSScore(score string) float64 {
	// Some OSV entries store the numeric score directly, e.g. "9.8"
	var f float64
	_, err := parseFloat(score, &f)
	if err == nil && f >= 0 && f <= 10 {
		return f
	}

	// Extract base score from CVSS vector notation (not trivial without a library).
	// For now return 0 to fall back to MEDIUM default; a future improvement would
	// use a cvss package to calculate the score from the vector string.
	return 0
}

// parseFloat is a minimal helper to attempt float parsing without importing strconv at package scope.
func parseFloat(s string, f *float64) (int, error) {
	_, err := fmt.Sscanf(s, "%f", f)
	return 0, err
}
