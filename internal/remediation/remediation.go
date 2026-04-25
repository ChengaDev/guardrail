// Package remediation suggests safe package versions when CVEs are found.
//
// It prefers upgrading to the highest known fixed version. When no fix exists,
// it falls back to the latest registry version that predates the vulnerability.
package remediation

import (
	"context"
	"fmt"
	"strings"

	"github.com/chengazit/guardrail/internal/osv"
	"github.com/chengazit/guardrail/internal/resolver"
)

// fetchAllVersions is the function used to retrieve all published versions of a package.
// It can be replaced in tests to avoid real HTTP calls.
var fetchAllVersions = resolver.AllVersions

// Kind describes the nature of the suggested version.
type Kind string

const (
	// KindPatch means the suggestion is an upgrade to an officially patched version.
	KindPatch Kind = "patch"
	// KindLastSafe means no patch exists; the suggestion is the newest version
	// that predates the vulnerability introduction.
	KindLastSafe Kind = "last_safe"
)

// Suggestion is a recommended safe version for a vulnerable package.
type Suggestion struct {
	Version string
	Kind    Kind
}

// Suggest returns the best available safe version for name in ecosystem given the
// list of blocking vulnerabilities. currentVersion is the installed version string.
//
// Strategy:
//  1. If every vuln has a fixed version in OSV data → recommend max(fixed versions).
//  2. If some vulns have fixes but not all → still recommend max(fixed versions) as a
//     partial improvement (the caller sees Kind=KindPatch).
//  3. If no fixes at all → fetch all registry versions and recommend the latest one
//     that predates the earliest introduction event (Kind=KindLastSafe).
//
// Returns nil if no useful suggestion can be determined.
func Suggest(ctx context.Context, vulns []osv.Vuln, ecosystem, name, currentVersion string) (*Suggestion, error) {
	if len(vulns) == 0 {
		return nil, nil
	}

	var allFixed []string
	var allIntroduced []string

	for _, v := range vulns {
		allFixed = append(allFixed, v.FixedVersions(ecosystem, name)...)
		allIntroduced = append(allIntroduced, v.IntroducedVersions(ecosystem, name)...)
	}

	if len(allFixed) > 0 {
		if fix := maxVersion(allFixed); fix != "" {
			return &Suggestion{Version: fix, Kind: KindPatch}, nil
		}
	}

	// No official fix documented. Find the last safe version before the earliest
	// introduction across all vulns.
	if len(allIntroduced) == 0 {
		return nil, nil
	}
	earliest := minVersion(allIntroduced)
	if earliest == "" {
		return nil, nil
	}

	versions, err := fetchAllVersions(ctx, ecosystem, name)
	if err != nil || len(versions) == 0 {
		return nil, err
	}

	lastSafe := ""
	for _, v := range versions {
		if compareVersions(v, earliest) < 0 {
			if lastSafe == "" || compareVersions(v, lastSafe) > 0 {
				lastSafe = v
			}
		}
	}
	if lastSafe == "" {
		return nil, nil
	}
	return &Suggestion{Version: lastSafe, Kind: KindLastSafe}, nil
}

// maxVersion returns the highest semver string from versions.
func maxVersion(versions []string) string {
	best := ""
	for _, v := range versions {
		if best == "" || compareVersions(v, best) > 0 {
			best = v
		}
	}
	return best
}

// minVersion returns the lowest semver string from versions.
func minVersion(versions []string) string {
	best := ""
	for _, v := range versions {
		if best == "" || compareVersions(v, best) < 0 {
			best = v
		}
	}
	return best
}

// compareVersions compares two semver-like version strings.
// Returns -1, 0, or 1 (a < b, a == b, a > b).
// Handles MAJOR.MINOR.PATCH with optional pre-release suffix (treated as lower than base).
func compareVersions(a, b string) int {
	a = strings.TrimPrefix(a, "v")
	b = strings.TrimPrefix(b, "v")

	aPre, bPre := "", ""
	if i := strings.IndexByte(a, '-'); i >= 0 {
		aPre, a = a[i:], a[:i]
	}
	if i := strings.IndexByte(b, '-'); i >= 0 {
		bPre, b = b[i:], b[:i]
	}

	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")
	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}

	for i := 0; i < maxLen; i++ {
		var an, bn int
		if i < len(aParts) {
			fmt.Sscanf(aParts[i], "%d", &an)
		}
		if i < len(bParts) {
			fmt.Sscanf(bParts[i], "%d", &bn)
		}
		if an < bn {
			return -1
		}
		if an > bn {
			return 1
		}
	}

	// Equal base version; pre-release sorts below release.
	switch {
	case aPre != "" && bPre == "":
		return -1
	case aPre == "" && bPre != "":
		return 1
	case aPre < bPre:
		return -1
	case aPre > bPre:
		return 1
	}
	return 0
}
