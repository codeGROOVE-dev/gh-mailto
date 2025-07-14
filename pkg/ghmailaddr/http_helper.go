package ghmailaddr

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// httpClient provides a reusable HTTP client with sensible defaults
var httpClient = &http.Client{
	Timeout: 30 * time.Second,
}

// doRequest performs an HTTP request with proper error handling and resource cleanup
func (lu *Lookup) doRequest(ctx context.Context, method, url string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	
	req.Header.Set("Authorization", "Bearer "+lu.token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "gh2addrs/1.0")
	
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	
	return resp, nil
}

// doJSONRequest performs an HTTP request and decodes the JSON response
func (lu *Lookup) doJSONRequest(ctx context.Context, method, url string, body io.Reader, result interface{}) error {
	resp, err := lu.doRequest(ctx, method, url, body)
	if err != nil {
		return err
	}
	defer func() {
		// Drain and close body to reuse connection
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()
	
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}
	
	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	
	return nil
}