package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

const (
	baseURL        = "https://api.osv.dev/v1"
	batchSizeLimit = 1000
)

// Client queries the OSV.dev API.
type Client struct {
	http *http.Client
}

// NewClient creates a Client that uses HTTP/2 as recommended by OSV.
func NewClient() *Client {
	transport := &http2.Transport{}
	return &Client{
		http: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
	}
}

// QueryBatch queries the OSV API for a list of PURLs and returns the results
// in the same order as the input. It handles pagination automatically.
func (c *Client) QueryBatch(ctx context.Context, purls []string) ([]QueryResult, error) {
	if len(purls) == 0 {
		return nil, nil
	}

	results := make([]QueryResult, len(purls))

	// Process in chunks of batchSizeLimit
	for start := 0; start < len(purls); start += batchSizeLimit {
		end := start + batchSizeLimit
		if end > len(purls) {
			end = len(purls)
		}
		chunk := purls[start:end]

		chunkResults, err := c.queryChunk(ctx, chunk)
		if err != nil {
			return nil, err
		}
		copy(results[start:end], chunkResults)
	}

	// querybatch returns stub records (id + modified only); hydrate with full details.
	if err := c.hydrateVulns(ctx, results); err != nil {
		return nil, err
	}

	return results, nil
}

// hydrateVulns fetches full vuln details for every stub returned by querybatch.
// Fetches are done concurrently (up to 20 in-flight) and deduplicated by ID.
func (c *Client) hydrateVulns(ctx context.Context, results []QueryResult) error {
	// Collect unique IDs across all results.
	seen := make(map[string]bool)
	for _, r := range results {
		for _, v := range r.Vulns {
			seen[v.ID] = true
		}
	}
	if len(seen) == 0 {
		return nil
	}

	const concurrency = 20
	sem := make(chan struct{}, concurrency)
	details := make(map[string]Vuln, len(seen))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for id := range seen {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			v, err := c.getVuln(ctx, id)
			if err == nil {
				mu.Lock()
				details[id] = *v
				mu.Unlock()
			}
		}(id)
	}
	wg.Wait()

	// Replace stubs with full records.
	for i := range results {
		for j := range results[i].Vulns {
			if full, ok := details[results[i].Vulns[j].ID]; ok {
				results[i].Vulns[j] = full
			}
		}
	}
	return nil
}

// getVuln fetches a single vulnerability record by its OSV ID.
func (c *Client) getVuln(ctx context.Context, id string) (*Vuln, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/vulns/"+id, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv: HTTP %d for %s", resp.StatusCode, id)
	}
	var v Vuln
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, fmt.Errorf("osv: parsing vuln %s: %w", id, err)
	}
	return &v, nil
}

// queryChunk sends a single batch request for a chunk of PURLs.
// It follows next_page_token if OSV paginates the response.
func (c *Client) queryChunk(ctx context.Context, purls []string) ([]QueryResult, error) {
	queries := make([]Query, len(purls))
	for i, p := range purls {
		queries[i] = Query{Package: PackageRef{PURL: p}}
	}

	req := BatchRequest{Queries: queries}
	results := make([]QueryResult, len(purls))

	// First request — no page tokens
	resp, err := c.postBatch(ctx, req)
	if err != nil {
		return nil, err
	}
	if len(resp.Results) != len(purls) {
		return nil, fmt.Errorf("osv: expected %d results, got %d", len(purls), len(resp.Results))
	}
	for i := range resp.Results {
		results[i].Vulns = append(results[i].Vulns, resp.Results[i].Vulns...)
	}

	// Handle per-query pagination (rare but supported by the spec)
	needsMore := false
	for _, r := range resp.Results {
		if r.NextPageToken != "" {
			needsMore = true
			break
		}
	}

	for needsMore {
		pageQueries := make([]Query, len(purls))
		needsMore = false
		for i, p := range purls {
			pageQueries[i] = Query{Package: PackageRef{PURL: p}}
			if resp.Results[i].NextPageToken != "" {
				pageQueries[i].PageToken = resp.Results[i].NextPageToken
				needsMore = true
			}
		}
		if !needsMore {
			break
		}

		pageReq := BatchRequest{Queries: pageQueries}
		resp, err = c.postBatch(ctx, pageReq)
		if err != nil {
			return nil, err
		}
		for i := range resp.Results {
			results[i].Vulns = append(results[i].Vulns, resp.Results[i].Vulns...)
		}
		// Update tokens for next round
		for i := range resp.Results {
			if resp.Results[i].NextPageToken != "" {
				needsMore = true
			}
		}
	}

	return results, nil
}

// postBatch makes a single HTTP POST to /v1/querybatch.
func (c *Client) postBatch(ctx context.Context, req BatchRequest) (*BatchResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("osv: marshalling request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/querybatch", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("osv: creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("osv: request failed: %w", err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("osv: reading response: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv: HTTP %d: %s", httpResp.StatusCode, string(respBody))
	}

	var batchResp BatchResponse
	if err := json.Unmarshal(respBody, &batchResp); err != nil {
		return nil, fmt.Errorf("osv: parsing response: %w", err)
	}

	return &batchResp, nil
}
