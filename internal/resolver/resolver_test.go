package resolver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
)

// withMockClient temporarily replaces defaultClient with one pointing at srv.
func withMockClient(t *testing.T, srv *httptest.Server) {
	t.Helper()
	old := defaultClient
	defaultClient = srv.Client()
	// Redirect requests to the test server by replacing the Host.
	defaultClient.Transport = &hostOverrideTransport{
		base:    srv.Client().Transport,
		baseURL: srv.URL,
	}
	t.Cleanup(func() { defaultClient = old })
}

// hostOverrideTransport rewrites the scheme+host of every outbound request to baseURL.
type hostOverrideTransport struct {
	base    http.RoundTripper
	baseURL string
}

func (h *hostOverrideTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	cloned.URL.Scheme = "http"
	cloned.URL.Host = h.baseURL[len("http://"):]
	cloned.Host = cloned.URL.Host
	if req.Body != nil && req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		cloned.Body = body
	}
	return h.base.RoundTrip(cloned)
}

// --- Latest ---

func TestLatestNPM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/express/latest" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"version": "4.18.2"})
	}))
	t.Cleanup(srv.Close)
	withMockClient(t, srv)

	got, err := Latest(context.Background(), "npm", "express")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "4.18.2" {
		t.Errorf("Latest = %q, want %q", got, "4.18.2")
	}
}

func TestLatestPyPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pypi/django/json" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"info": map[string]any{"version": "4.2.1"},
		})
	}))
	t.Cleanup(srv.Close)
	withMockClient(t, srv)

	got, err := Latest(context.Background(), "pypi", "django")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "4.2.1" {
		t.Errorf("Latest = %q, want %q", got, "4.2.1")
	}
}

func TestLatestUnsupportedEcosystem(t *testing.T) {
	_, err := Latest(context.Background(), "unknown", "pkg")
	if err == nil {
		t.Error("expected error for unsupported ecosystem, got nil")
	}
}

func TestLatestHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	withMockClient(t, srv)

	_, err := Latest(context.Background(), "npm", "nonexistent")
	if err == nil {
		t.Error("expected error for 404 response, got nil")
	}
}

// --- AllVersions ---

func TestAllVersionsNPM(t *testing.T) {
	wantVersions := []string{"1.0.0", "1.1.0", "2.0.0"}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/lodash" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		// Return a minimal npm registry payload with just the versions map.
		versions := map[string]any{}
		for _, v := range wantVersions {
			versions[v] = map[string]any{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"versions": versions})
	}))
	t.Cleanup(srv.Close)
	withMockClient(t, srv)

	got, err := AllVersions(context.Background(), "npm", "lodash")
	if err != nil {
		t.Fatalf("AllVersions: %v", err)
	}
	sort.Strings(got)
	sort.Strings(wantVersions)
	if len(got) != len(wantVersions) {
		t.Fatalf("AllVersions = %v, want %v", got, wantVersions)
	}
	for i := range wantVersions {
		if got[i] != wantVersions[i] {
			t.Errorf("AllVersions[%d] = %q, want %q", i, got[i], wantVersions[i])
		}
	}
}

func TestAllVersionsPyPI(t *testing.T) {
	wantVersions := []string{"3.0.0", "3.2.0", "4.0.0"}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pypi/django/json" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		releases := map[string]any{}
		for _, v := range wantVersions {
			releases[v] = []any{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"info":     map[string]any{"version": "4.0.0"},
			"releases": releases,
		})
	}))
	t.Cleanup(srv.Close)
	withMockClient(t, srv)

	got, err := AllVersions(context.Background(), "pypi", "django")
	if err != nil {
		t.Fatalf("AllVersions: %v", err)
	}
	sort.Strings(got)
	sort.Strings(wantVersions)
	if len(got) != len(wantVersions) {
		t.Fatalf("AllVersions = %v, want %v", got, wantVersions)
	}
}

func TestAllVersionsCargo(t *testing.T) {
	wantVersions := []string{"0.9.0", "1.0.0", "1.0.1"}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/crates/serde/versions" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		type ver struct {
			Num string `json:"num"`
		}
		versions := []ver{}
		for _, v := range wantVersions {
			versions = append(versions, ver{Num: v})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"versions": versions})
	}))
	t.Cleanup(srv.Close)
	withMockClient(t, srv)

	got, err := AllVersions(context.Background(), "cargo", "serde")
	if err != nil {
		t.Fatalf("AllVersions: %v", err)
	}
	sort.Strings(got)
	sort.Strings(wantVersions)
	if len(got) != len(wantVersions) {
		t.Fatalf("AllVersions = %v, want %v", got, wantVersions)
	}
	for i := range wantVersions {
		if got[i] != wantVersions[i] {
			t.Errorf("AllVersions[%d] = %q, want %q", i, got[i], wantVersions[i])
		}
	}
}

func TestAllVersionsUnsupportedEcosystem(t *testing.T) {
	_, err := AllVersions(context.Background(), "golang", "github.com/gin-gonic/gin")
	if err == nil {
		t.Error("expected error for unsupported ecosystem, got nil")
	}
}

func TestAllVersionsHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	withMockClient(t, srv)

	_, err := AllVersions(context.Background(), "npm", "nonexistent")
	if err == nil {
		t.Error("expected error for 404 response, got nil")
	}
}

// --- Integration tests ---

func TestIntegration_LatestNPM(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	ver, err := Latest(context.Background(), "npm", "lodash")
	if err != nil {
		t.Fatalf("Latest npm/lodash: %v", err)
	}
	if ver == "" {
		t.Error("expected a non-empty version")
	}
	t.Logf("lodash latest: %s", ver)
}

func TestIntegration_AllVersionsNPM(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	versions, err := AllVersions(context.Background(), "npm", "lodash")
	if err != nil {
		t.Fatalf("AllVersions npm/lodash: %v", err)
	}
	if len(versions) < 10 {
		t.Errorf("expected many versions for lodash, got %d", len(versions))
	}
	t.Logf("lodash: %d versions", len(versions))
}
