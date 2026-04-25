// Package resolver fetches the latest published version of a package from
// its native registry when the user does not specify an explicit version.
package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var defaultClient = &http.Client{Timeout: 10 * time.Second}

// Latest returns the latest published version of name in the given ecosystem.
// ecosystem is one of: npm, pypi, cargo, golang.
func Latest(ctx context.Context, ecosystem, name string) (string, error) {
	switch strings.ToLower(ecosystem) {
	case "npm":
		return latestNPM(ctx, name)
	case "pypi":
		return latestPyPI(ctx, name)
	case "cargo":
		return latestCargo(ctx, name)
	case "golang":
		return latestGo(ctx, name)
	default:
		return "", fmt.Errorf("resolver: unsupported ecosystem %q", ecosystem)
	}
}

// latestNPM fetches https://registry.npmjs.org/<name>/latest
func latestNPM(ctx context.Context, name string) (string, error) {
	url := "https://registry.npmjs.org/" + name + "/latest"
	var payload struct {
		Version string `json:"version"`
	}
	if err := getJSON(ctx, url, &payload); err != nil {
		return "", fmt.Errorf("npm registry for %q: %w", name, err)
	}
	if payload.Version == "" {
		return "", fmt.Errorf("npm registry: no version found for %q", name)
	}
	return payload.Version, nil
}

// latestPyPI fetches https://pypi.org/pypi/<name>/json
func latestPyPI(ctx context.Context, name string) (string, error) {
	url := "https://pypi.org/pypi/" + name + "/json"
	var payload struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
	}
	if err := getJSON(ctx, url, &payload); err != nil {
		return "", fmt.Errorf("PyPI registry for %q: %w", name, err)
	}
	if payload.Info.Version == "" {
		return "", fmt.Errorf("PyPI registry: no version found for %q", name)
	}
	return payload.Info.Version, nil
}

// latestCargo fetches https://crates.io/api/v1/crates/<name>
func latestCargo(ctx context.Context, name string) (string, error) {
	url := "https://crates.io/api/v1/crates/" + name
	var payload struct {
		Crate struct {
			NewestVersion string `json:"newest_version"`
		} `json:"crate"`
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	// crates.io requires a User-Agent
	req.Header.Set("User-Agent", "guardrail/0.1 (https://github.com/chengazit/guardrail)")
	resp, err := defaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("crates.io for %q: %w", name, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("crates.io: HTTP %d for %q", resp.StatusCode, name)
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("crates.io: parsing response for %q: %w", name, err)
	}
	if payload.Crate.NewestVersion == "" {
		return "", fmt.Errorf("crates.io: no version found for %q", name)
	}
	return payload.Crate.NewestVersion, nil
}

// latestGo fetches https://proxy.golang.org/<module>/@latest
func latestGo(ctx context.Context, module string) (string, error) {
	url := "https://proxy.golang.org/" + module + "/@latest"
	var payload struct {
		Version string `json:"Version"`
	}
	if err := getJSON(ctx, url, &payload); err != nil {
		return "", fmt.Errorf("Go proxy for %q: %w", module, err)
	}
	if payload.Version == "" {
		return "", fmt.Errorf("Go proxy: no version found for %q", module)
	}
	return payload.Version, nil
}

// AllVersions returns all published versions of name in ecosystem.
// The slice is unordered; callers that need ordering must sort it themselves.
// Only npm, pypi, and cargo are supported; others return an error.
func AllVersions(ctx context.Context, ecosystem, name string) ([]string, error) {
	switch strings.ToLower(ecosystem) {
	case "npm":
		return allVersionsNPM(ctx, name)
	case "pypi":
		return allVersionsPyPI(ctx, name)
	case "cargo":
		return allVersionsCargo(ctx, name)
	default:
		return nil, fmt.Errorf("resolver: AllVersions not supported for ecosystem %q", ecosystem)
	}
}

func allVersionsNPM(ctx context.Context, name string) ([]string, error) {
	url := "https://registry.npmjs.org/" + name
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// Use the npm install-v1 abbreviated format to reduce payload size.
	req.Header.Set("Accept", "application/vnd.npm.install-v1+json")
	resp, err := defaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("npm registry for %q: %w", name, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("npm registry: HTTP %d for %q", resp.StatusCode, name)
	}
	var payload struct {
		Versions map[string]json.RawMessage `json:"versions"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("npm: parsing versions for %q: %w", name, err)
	}
	versions := make([]string, 0, len(payload.Versions))
	for v := range payload.Versions {
		versions = append(versions, v)
	}
	return versions, nil
}

func allVersionsPyPI(ctx context.Context, name string) ([]string, error) {
	url := "https://pypi.org/pypi/" + name + "/json"
	var payload struct {
		Releases map[string]json.RawMessage `json:"releases"`
	}
	if err := getJSON(ctx, url, &payload); err != nil {
		return nil, fmt.Errorf("PyPI for %q: %w", name, err)
	}
	versions := make([]string, 0, len(payload.Releases))
	for v := range payload.Releases {
		versions = append(versions, v)
	}
	return versions, nil
}

func allVersionsCargo(ctx context.Context, name string) ([]string, error) {
	url := "https://crates.io/api/v1/crates/" + name + "/versions"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "guardrail/0.1 (https://github.com/chengazit/guardrail)")
	resp, err := defaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crates.io for %q: %w", name, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crates.io: HTTP %d for %q", resp.StatusCode, name)
	}
	var payload struct {
		Versions []struct {
			Num string `json:"num"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("crates.io: parsing versions for %q: %w", name, err)
	}
	versions := make([]string, 0, len(payload.Versions))
	for _, v := range payload.Versions {
		if v.Num != "" {
			versions = append(versions, v.Num)
		}
	}
	return versions, nil
}

// getJSON performs a GET request and JSON-decodes the response into dst.
func getJSON(ctx context.Context, url string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := defaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return json.Unmarshal(body, dst)
}
