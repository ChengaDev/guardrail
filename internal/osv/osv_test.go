package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ChengaDev/guardrail/internal/severity"
)

// --- Vuln unit tests ---

func TestVulnLevel(t *testing.T) {
	tests := []struct {
		name string
		vuln Vuln
		want severity.Level
	}{
		{
			name: "CVSS numeric score 9.8 → CRITICAL",
			vuln: Vuln{Severity: []SevEntry{{Type: "CVSS_V3", Score: "9.8"}}},
			want: severity.LevelCritical,
		},
		{
			name: "CVSS numeric score 7.5 → HIGH",
			vuln: Vuln{Severity: []SevEntry{{Type: "CVSS_V3", Score: "7.5"}}},
			want: severity.LevelHigh,
		},
		{
			name: "CVSS numeric score 5.0 → MEDIUM",
			vuln: Vuln{Severity: []SevEntry{{Type: "CVSS_V3", Score: "5.0"}}},
			want: severity.LevelMedium,
		},
		{
			name: "CVSS numeric score 2.1 → LOW",
			vuln: Vuln{Severity: []SevEntry{{Type: "CVSS_V3", Score: "2.1"}}},
			want: severity.LevelLow,
		},
		{
			name: "no severity → MEDIUM (conservative default)",
			vuln: Vuln{},
			want: severity.LevelMedium,
		},
		{
			name: "vector string only (unparseable) → MEDIUM default",
			vuln: Vuln{Severity: []SevEntry{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}},
			want: severity.LevelMedium,
		},
		{
			name: "multiple entries — highest wins",
			vuln: Vuln{Severity: []SevEntry{
				{Type: "CVSS_V2", Score: "5.0"},
				{Type: "CVSS_V3", Score: "9.1"},
			}},
			want: severity.LevelCritical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.vuln.Level()
			if got != tt.want {
				t.Errorf("Level() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVulnCVE(t *testing.T) {
	tests := []struct {
		name string
		vuln Vuln
		want string
	}{
		{
			name: "alias contains CVE ID",
			vuln: Vuln{ID: "GHSA-xxxx-yyyy-zzzz", Aliases: []string{"CVE-2021-44228", "GHSA-other"}},
			want: "CVE-2021-44228",
		},
		{
			name: "no CVE alias — falls back to OSV ID",
			vuln: Vuln{ID: "GHSA-xxxx-yyyy-zzzz", Aliases: []string{"GHSA-other"}},
			want: "GHSA-xxxx-yyyy-zzzz",
		},
		{
			name: "no aliases at all",
			vuln: Vuln{ID: "GHSA-no-aliases"},
			want: "GHSA-no-aliases",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.vuln.CVE()
			if got != tt.want {
				t.Errorf("CVE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVulnOSVLink(t *testing.T) {
	v := Vuln{ID: "GHSA-xxxx-yyyy-zzzz"}
	want := "https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz"
	if got := v.OSVLink(); got != want {
		t.Errorf("OSVLink() = %q, want %q", got, want)
	}
}

// --- FixedVersions / IntroducedVersions ---

func semverRange(intro, fixed string) Affected {
	events := []RangeEvent{}
	if intro != "" {
		events = append(events, RangeEvent{Introduced: intro})
	}
	if fixed != "" {
		events = append(events, RangeEvent{Fixed: fixed})
	}
	return Affected{
		Package: AffectedPackage{Ecosystem: "npm", Name: "lodash"},
		Ranges:  []AffectedRange{{Type: "SEMVER", Events: events}},
	}
}

func TestFixedVersions(t *testing.T) {
	tests := []struct {
		name      string
		vuln      Vuln
		ecosystem string
		pkg       string
		want      []string
	}{
		{
			name:      "single fix",
			vuln:      Vuln{Affected: []Affected{semverRange("0", "4.17.21")}},
			ecosystem: "npm", pkg: "lodash",
			want: []string{"4.17.21"},
		},
		{
			name: "multiple ranges each with a fix",
			vuln: Vuln{Affected: []Affected{
				{
					Package: AffectedPackage{Ecosystem: "npm", Name: "lodash"},
					Ranges: []AffectedRange{
						{Type: "SEMVER", Events: []RangeEvent{{Introduced: "4.0.0"}, {Fixed: "4.17.21"}}},
						{Type: "SEMVER", Events: []RangeEvent{{Introduced: "3.0.0"}, {Fixed: "3.10.1"}}},
					},
				},
			}},
			ecosystem: "npm", pkg: "lodash",
			want: []string{"4.17.21", "3.10.1"},
		},
		{
			name:      "no fix event",
			vuln:      Vuln{Affected: []Affected{semverRange("0", "")}},
			ecosystem: "npm", pkg: "lodash",
			want:      nil,
		},
		{
			name:      "GIT range is ignored",
			vuln:      Vuln{Affected: []Affected{{
				Package: AffectedPackage{Ecosystem: "npm", Name: "lodash"},
				Ranges:  []AffectedRange{{Type: "GIT", Events: []RangeEvent{{Fixed: "abc123"}}}},
			}}},
			ecosystem: "npm", pkg: "lodash",
			want:      nil,
		},
		{
			name:      "ecosystem mismatch — no results",
			vuln:      Vuln{Affected: []Affected{semverRange("0", "4.17.21")}},
			ecosystem: "pypi", pkg: "lodash",
			want:      nil,
		},
		{
			name:      "name mismatch — no results",
			vuln:      Vuln{Affected: []Affected{semverRange("0", "4.17.21")}},
			ecosystem: "npm", pkg: "express",
			want:      nil,
		},
		{
			name: "OSV ecosystem PyPI matched by internal pypi (case fold)",
			vuln: Vuln{Affected: []Affected{{
				Package: AffectedPackage{Ecosystem: "PyPI", Name: "django"},
				Ranges:  []AffectedRange{{Type: "SEMVER", Events: []RangeEvent{{Introduced: "0"}, {Fixed: "4.2.1"}}}},
			}}},
			ecosystem: "pypi", pkg: "django",
			want: []string{"4.2.1"},
		},
		{
			name: "crates.io ecosystem matched by internal cargo",
			vuln: Vuln{Affected: []Affected{{
				Package: AffectedPackage{Ecosystem: "crates.io", Name: "serde"},
				Ranges:  []AffectedRange{{Type: "SEMVER", Events: []RangeEvent{{Introduced: "0"}, {Fixed: "1.0.100"}}}},
			}}},
			ecosystem: "cargo", pkg: "serde",
			want: []string{"1.0.100"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.vuln.FixedVersions(tt.ecosystem, tt.pkg)
			if len(got) != len(tt.want) {
				t.Fatalf("FixedVersions() = %v, want %v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("FixedVersions()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestIntroducedVersions(t *testing.T) {
	tests := []struct {
		name      string
		vuln      Vuln
		ecosystem string
		pkg       string
		want      []string
	}{
		{
			name:      "single introduced (non-zero)",
			vuln:      Vuln{Affected: []Affected{semverRange("3.0.0", "4.17.21")}},
			ecosystem: "npm", pkg: "lodash",
			want:      []string{"3.0.0"},
		},
		{
			name:      "introduced=0 is skipped",
			vuln:      Vuln{Affected: []Affected{semverRange("0", "4.17.21")}},
			ecosystem: "npm", pkg: "lodash",
			want:      nil,
		},
		{
			name:      "no introduced event",
			vuln:      Vuln{Affected: []Affected{semverRange("", "4.17.21")}},
			ecosystem: "npm", pkg: "lodash",
			want:      nil,
		},
		{
			name:      "GIT range is ignored",
			vuln:      Vuln{Affected: []Affected{{
				Package: AffectedPackage{Ecosystem: "npm", Name: "lodash"},
				Ranges:  []AffectedRange{{Type: "GIT", Events: []RangeEvent{{Introduced: "abc123"}}}},
			}}},
			ecosystem: "npm", pkg: "lodash",
			want:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.vuln.IntroducedVersions(tt.ecosystem, tt.pkg)
			if len(got) != len(tt.want) {
				t.Fatalf("IntroducedVersions() = %v, want %v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("IntroducedVersions()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestNormalizeEcosystem(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"npm", "npm"},
		{"NPM", "npm"},
		{"PyPI", "pypi"},
		{"pypi", "pypi"},
		{"crates.io", "cargo"},
		{"Crates.io", "cargo"},
		{"cargo", "cargo"},
		{"Go", "golang"},
		{"golang", "golang"},
		{"maven", "maven"}, // unknown — lowercased
	}
	for _, tt := range tests {
		got := normalizeEcosystem(tt.input)
		if got != tt.want {
			t.Errorf("normalizeEcosystem(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// --- Client tests with mock HTTP server ---

func TestQueryBatchEmpty(t *testing.T) {
	c := NewClient()
	results, err := c.QueryBatch(context.Background(), nil)
	if err != nil {
		t.Fatalf("QueryBatch(nil): %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

// mockOSVServer starts an httptest server that implements the /v1/querybatch endpoint.
// The provided handler receives the decoded BatchRequest and returns a BatchResponse.
func mockOSVServer(t *testing.T, handler func(req BatchRequest) BatchResponse) (*httptest.Server, *Client) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" || r.Method != http.MethodPost {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var req BatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resp := handler(req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))

	// Wire a Client that uses a custom http.Transport pointing at our test server.
	transport := &mockTransport{
		realTransport: srv.Client().Transport,
		serverURL:     srv.URL,
	}
	client := &Client{http: &http.Client{Transport: transport}}
	t.Cleanup(srv.Close)
	return srv, client
}

// mockTransport rewrites requests to baseURL → srv.URL so the Client code is unchanged.
type mockTransport struct {
	realTransport http.RoundTripper
	serverURL     string
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the scheme+host of the request URL with our test server.
	newURL := *req.URL
	newURL.Scheme = "http"
	newURL.Host = req.Host

	// Parse server URL to get host
	var serverHost string
	fmt.Sscanf(m.serverURL, "http://%s", &serverHost)
	newURL.Host = serverHost

	newReq := req.Clone(req.Context())
	newReq.URL = &newURL

	// Re-read the body for the new request (body was already set as GetBody or directly).
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		newReq.Body = body
	}

	return m.realTransport.RoundTrip(newReq)
}

// newTestClient creates a Client that routes all requests to the given test server.
func newTestClient(srv *httptest.Server) *Client {
	transport := &redirectTransport{serverURL: srv.URL, base: srv.Client().Transport}
	return &Client{http: &http.Client{Transport: transport}}
}

// redirectTransport replaces the Host of outbound requests with the test server.
type redirectTransport struct {
	serverURL string
	base      http.RoundTripper
}

func (r *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request and swap the URL host+scheme.
	cloned := req.Clone(req.Context())
	cloned.URL.Scheme = "http"
	// Extract host from serverURL ("http://127.0.0.1:PORT")
	host := r.serverURL[len("http://"):]
	cloned.URL.Host = host
	cloned.Host = host

	// Ensure the body is still readable.
	if req.Body != nil && req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		cloned.Body = body
	}
	return r.base.RoundTrip(cloned)
}

func TestQueryBatchMockServer(t *testing.T) {
	_, client := mockOSVServer(t, func(req BatchRequest) BatchResponse {
		results := make([]QueryResult, len(req.Queries))
		if len(results) > 0 {
			results[0] = QueryResult{
				Vulns: []Vuln{{
					ID:       "GHSA-mock-0001",
					Summary:  "mock vulnerability",
					Severity: []SevEntry{{Type: "CVSS_V3", Score: "9.8"}},
				}},
			}
		}
		return BatchResponse{Results: results}
	})

	purls := []string{
		"pkg:npm/lodash@4.17.20",
		"pkg:pypi/django@2.0.0",
	}
	results, err := client.QueryBatch(context.Background(), purls)
	if err != nil {
		t.Fatalf("QueryBatch: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if len(results[0].Vulns) != 1 || results[0].Vulns[0].ID != "GHSA-mock-0001" {
		t.Errorf("results[0] unexpected vulns: %+v", results[0].Vulns)
	}
	if len(results[1].Vulns) != 0 {
		t.Errorf("results[1]: expected 0 vulns, got %d", len(results[1].Vulns))
	}
}

func TestQueryBatchServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	client := newTestClient(srv)
	_, err := client.QueryBatch(context.Background(), []string{"pkg:npm/express@4.18.2"})
	if err == nil {
		t.Fatal("expected error from 500 response, got nil")
	}
}

func TestQueryBatchResultCountMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := BatchResponse{Results: []QueryResult{}} // empty — mismatches query count
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)

	client := newTestClient(srv)
	_, err := client.QueryBatch(context.Background(), []string{"pkg:npm/express@4.18.2"})
	if err == nil {
		t.Fatal("expected error for result count mismatch, got nil")
	}
}

func TestQueryBatchPagination(t *testing.T) {
	callCount := 0
	_, client := mockOSVServer(t, func(req BatchRequest) BatchResponse {
		callCount++
		results := make([]QueryResult, len(req.Queries))
		if callCount == 1 {
			// First call: return a next_page_token so the client paginates.
			results[0] = QueryResult{
				Vulns:         []Vuln{{ID: "GHSA-page1"}},
				NextPageToken: "token-page2",
			}
		} else {
			// Second call: no more pages.
			results[0] = QueryResult{
				Vulns: []Vuln{{ID: "GHSA-page2"}},
			}
		}
		return BatchResponse{Results: results}
	})

	results, err := client.QueryBatch(context.Background(), []string{"pkg:npm/express@4.18.2"})
	if err != nil {
		t.Fatalf("QueryBatch: %v", err)
	}
	if callCount != 2 {
		t.Errorf("expected 2 API calls (pagination), got %d", callCount)
	}
	if len(results[0].Vulns) != 2 {
		t.Errorf("expected 2 vulns (1 per page), got %d", len(results[0].Vulns))
	}
}

// postBatchDirect is a helper that calls postBatch with a raw JSON body for unit testing.
func postBatchDirect(t *testing.T, client *Client, body []byte) (*BatchResponse, error) {
	t.Helper()
	req := BatchRequest{}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("invalid test body: %v", err)
	}
	// Exercise the exported QueryBatch by constructing matching PURLs.
	_ = req
	return nil, nil
}

// ioutil replacement
func readAll(r io.Reader) []byte {
	b, _ := io.ReadAll(r)
	return b
}

var _ = bytes.NewReader // keep import used

// --- Integration tests (real OSV API) ---

func TestIntegration_KnownVulnerablePackages(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	c := NewClient()
	ctx := context.Background()

	purls := []string{
		"pkg:npm/lodash@4.17.20",  // prototype pollution CVEs
		"pkg:pypi/django@2.0.0",   // multiple known CVEs
		"pkg:cargo/regex@0.1.0",   // known CVEs
	}

	results, err := c.QueryBatch(ctx, purls)
	if err != nil {
		t.Fatalf("QueryBatch: %v", err)
	}
	if len(results) != len(purls) {
		t.Fatalf("expected %d results, got %d", len(purls), len(results))
	}

	for i, p := range purls {
		if len(results[i].Vulns) == 0 {
			t.Errorf("expected vulnerabilities for %s, got none", p)
		} else {
			t.Logf("%s: %d vulns (first: %s)", p, len(results[i].Vulns), results[i].Vulns[0].ID)
		}
	}
}

func TestIntegration_SafePackage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	c := NewClient()
	ctx := context.Background()

	purls := []string{"pkg:npm/lodash@4.17.21"}
	results, err := c.QueryBatch(ctx, purls)
	if err != nil {
		t.Fatalf("QueryBatch: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	t.Logf("pkg:npm/lodash@4.17.21: %d vulns", len(results[0].Vulns))
}
