// Package purl builds Package URL (PURL) strings per ecosystem.
// Spec: https://github.com/package-url/purl-spec
package purl

import (
	"fmt"
	"net/url"
	"strings"
)

// Build returns the PURL string for a given ecosystem, package name, and version.
func Build(ecosystem, name, version string) string {
	switch strings.ToLower(ecosystem) {
	case "npm":
		return buildNPM(name, version)
	case "pypi":
		return buildPyPI(name, version)
	case "cargo":
		return fmt.Sprintf("pkg:cargo/%s@%s", name, version)
	case "golang":
		return fmt.Sprintf("pkg:golang/%s@%s", name, version)
	default:
		return fmt.Sprintf("pkg:%s/%s@%s", strings.ToLower(ecosystem), name, version)
	}
}

// buildNPM handles scoped packages like @scope/name → pkg:npm/%40scope%2Fname@version
func buildNPM(name, version string) string {
	if strings.HasPrefix(name, "@") {
		// scoped package: @scope/name → %40scope%2Fname
		// url.PathEscape encodes / but not @; encode @ manually first.
		withoutAt := name[1:] // strip leading @
		encoded := "%40" + url.PathEscape(withoutAt)
		return fmt.Sprintf("pkg:npm/%s@%s", encoded, version)
	}
	return fmt.Sprintf("pkg:npm/%s@%s", name, version)
}

// buildPyPI normalizes the package name (underscores → dashes, lowercase).
func buildPyPI(name, version string) string {
	normalized := strings.ToLower(strings.ReplaceAll(name, "_", "-"))
	return fmt.Sprintf("pkg:pypi/%s@%s", normalized, version)
}

// Parse extracts ecosystem, name, and version from a PURL string.
// e.g., "pkg:npm/express@4.18.2" → ("npm", "express", "4.18.2", nil)
func Parse(purl string) (ecosystem, name, version string, err error) {
	if !strings.HasPrefix(purl, "pkg:") {
		return "", "", "", fmt.Errorf("invalid PURL: must start with 'pkg:'")
	}
	rest := purl[4:] // strip "pkg:"
	slashIdx := strings.Index(rest, "/")
	if slashIdx < 0 {
		return "", "", "", fmt.Errorf("invalid PURL: missing type separator")
	}
	ecosystem = rest[:slashIdx]
	rest = rest[slashIdx+1:]

	atIdx := strings.LastIndex(rest, "@")
	if atIdx < 0 {
		name = rest
		version = ""
	} else {
		name = rest[:atIdx]
		version = rest[atIdx+1:]
	}

	// URL-decode the name
	decoded, decErr := url.PathUnescape(name)
	if decErr == nil {
		name = decoded
	}

	return ecosystem, name, version, nil
}
