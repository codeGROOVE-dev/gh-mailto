// Package ghmailto provides email address discovery for GitHub users.
package ghmailto

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const maxErrorBodySize = 1024

// httpClient provides a reusable HTTP client with sensible defaults.
var httpClient = &http.Client{
	Timeout: 30 * time.Second,
}

// doRequest performs an HTTP request with proper error handling and resource cleanup.
func (lu *Lookup) doRequest(ctx context.Context, method, url string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+lu.token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "gh-mailto/1.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}

	return resp, nil
}

// doJSONRequest performs an HTTP request and decodes the JSON response.
//
//nolint:unparam // method parameter kept for future flexibility
func (lu *Lookup) doJSONRequest(ctx context.Context, method, url string, body io.Reader, result any) error {
	resp, err := lu.doRequest(ctx, method, url, body)
	if err != nil {
		return err
	}
	defer func() {
		// Drain and close body to reuse connection
		// These errors are intentionally ignored as they occur during cleanup
		_, _ = io.Copy(io.Discard, resp.Body) //nolint:errcheck // Best effort cleanup
		_ = resp.Body.Close()                 //nolint:errcheck // Best effort cleanup
	}()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
		if err != nil {
			return fmt.Errorf("HTTP %d: failed to read error response", resp.StatusCode)
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}

	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	return nil
}
