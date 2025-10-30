// Package ghmailto provides email address discovery for GitHub users.
package ghmailto

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/retry"
)

const (
	maxErrorBodySize    = 1024
	maxResponseBodySize = 10 * 1024 * 1024 // 10MB maximum response size to prevent memory exhaustion
)

// httpClient provides a reusable HTTP client with sensible defaults.
var httpClient = &http.Client{
	Timeout: 30 * time.Second,
}

// doRequestWithAccept performs an HTTP request with a custom Accept header and exponential backoff.
func (lu *Lookup) doRequestWithAccept(ctx context.Context, method, url string, body io.Reader, accept string) (*http.Response, error) {
	var finalResp *http.Response

	err := retry.Do(
		func() error {
			req, reqErr := http.NewRequestWithContext(ctx, method, url, body)
			if reqErr != nil {
				return retry.Unrecoverable(fmt.Errorf("creating request: %w", reqErr))
			}

			req.Header.Set("Authorization", "Bearer "+lu.token)
			req.Header.Set("Accept", accept)
			req.Header.Set("User-Agent", "gh-mailto/1.0")

			resp, httpErr := httpClient.Do(req)
			if httpErr != nil {
				lu.logger.Debug("HTTP request failed, will retry", "error", httpErr, "url", url)
				return fmt.Errorf("executing request: %w", httpErr)
			}

			// Retry on server errors (5xx) and rate limiting (429)
			if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
				if closeErr := resp.Body.Close(); closeErr != nil {
					lu.logger.Debug("failed to close response body", "error", closeErr)
				}
				lu.logger.Debug("HTTP error, will retry", "status", resp.StatusCode, "url", url)
				return fmt.Errorf("HTTP %d error", resp.StatusCode)
			}

			finalResp = resp
			return nil
		},
		retry.Attempts(5),
		retry.Delay(100*time.Millisecond),
		retry.MaxDelay(2*time.Minute),
		retry.DelayType(retry.FullJitterBackoffDelay),
		retry.Context(ctx),
	)
	if err != nil {
		return nil, err
	}

	return finalResp, nil
}

// doJSONRequestWithAccept performs a GET request with custom Accept header and decodes the JSON response.
func (lu *Lookup) doJSONRequestWithAccept(ctx context.Context, url string, body io.Reader, result any, accept string) error {
	resp, err := lu.doRequestWithAccept(ctx, "GET", url, body, accept)
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

	// Read the response body with size limit to prevent memory exhaustion
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}

	// Check if we hit the limit
	if len(bodyBytes) == maxResponseBodySize {
		return fmt.Errorf("response body too large (>%d bytes)", maxResponseBodySize)
	}

	// Log response metadata only - never log response body for security
	lu.logger.Debug("API response received",
		"method", "GET",
		"url", url,
		"status", resp.StatusCode,
		"content_length", len(bodyBytes),
	)

	if err := json.Unmarshal(bodyBytes, result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	return nil
}

// doJSONPost performs a POST request with JSON body and decodes the JSON response.
func (lu *Lookup) doJSONPost(ctx context.Context, url string, payload any, result any) error {
	// Marshal payload to JSON
	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling request body: %w", err)
	}

	var bodyReader io.Reader

	var finalResp *http.Response
	retryErr := retry.Do(
		func() error {
			// Create fresh reader for each retry
			bodyReader = strings.NewReader(string(jsonBytes))

			req, reqErr := http.NewRequestWithContext(ctx, "POST", url, bodyReader)
			if reqErr != nil {
				return retry.Unrecoverable(fmt.Errorf("creating request: %w", reqErr))
			}

			req.Header.Set("Authorization", "Bearer "+lu.token)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json")
			req.Header.Set("User-Agent", "gh-mailto/1.0")

			resp, httpErr := httpClient.Do(req)
			if httpErr != nil {
				lu.logger.Debug("HTTP POST failed, will retry", "error", httpErr, "url", url)
				return fmt.Errorf("executing request: %w", httpErr)
			}

			// Retry on server errors (5xx) and rate limiting (429)
			if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
				if closeErr := resp.Body.Close(); closeErr != nil {
					lu.logger.Debug("failed to close response body", "error", closeErr)
				}
				lu.logger.Debug("HTTP error, will retry", "status", resp.StatusCode, "url", url)
				return fmt.Errorf("HTTP %d error", resp.StatusCode)
			}

			finalResp = resp
			return nil
		},
		retry.Attempts(5),
		retry.Delay(100*time.Millisecond),
		retry.MaxDelay(2*time.Minute),
		retry.DelayType(retry.FullJitterBackoffDelay),
		retry.Context(ctx),
	)
	if retryErr != nil {
		return retryErr
	}

	defer func() {
		// Drain and close body to reuse connection
		_, _ = io.Copy(io.Discard, finalResp.Body) //nolint:errcheck // Best effort cleanup
		_ = finalResp.Body.Close()                 //nolint:errcheck // Best effort cleanup
	}()

	if finalResp.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(io.LimitReader(finalResp.Body, maxErrorBodySize))
		if err != nil {
			return fmt.Errorf("HTTP %d: failed to read error response", finalResp.StatusCode)
		}
		return fmt.Errorf("HTTP %d: %s", finalResp.StatusCode, string(bodyBytes))
	}

	// Read the response body with size limit
	bodyBytes, err := io.ReadAll(io.LimitReader(finalResp.Body, maxResponseBodySize))
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}

	// Check if we hit the limit
	if len(bodyBytes) == maxResponseBodySize {
		return fmt.Errorf("response body too large (>%d bytes)", maxResponseBodySize)
	}

	// Log response metadata only - never log response body for security
	lu.logger.Debug("API response received",
		"method", "POST",
		"url", url,
		"status", finalResp.StatusCode,
		"content_length", len(bodyBytes),
	)

	if err := json.Unmarshal(bodyBytes, result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	return nil
}
