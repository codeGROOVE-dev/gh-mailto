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
		retry.DelayType(retry.BackOffDelay),
		retry.Context(ctx),
	)
	if err != nil {
		return nil, err
	}

	return finalResp, nil
}

// doJSONRequestWithAccept performs an HTTP request with custom Accept header and decodes the JSON response.
func (lu *Lookup) doJSONRequestWithAccept(ctx context.Context, method, url string, body io.Reader, result any, accept string) error {
	resp, err := lu.doRequestWithAccept(ctx, method, url, body, accept)
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
		"method", method,
		"url", url,
		"status", resp.StatusCode,
		"content_length", len(bodyBytes),
	)

	if err := json.Unmarshal(bodyBytes, result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	return nil
}

// doGraphQLQueryWithRetry performs a GraphQL query with retry logic for reliability.
func (lu *Lookup) doGraphQLQueryWithRetry(ctx context.Context, client interface {
	Query(ctx context.Context, q interface{}, variables map[string]interface{}) error
}, query interface{}, variables map[string]interface{},
) error {
	return retry.Do(
		func() error {
			err := client.Query(ctx, query, variables)
			if err != nil {
				// Check if it's a rate limit error that should be retried
				if strings.Contains(err.Error(), "rate limit") ||
					strings.Contains(err.Error(), "timeout") ||
					strings.Contains(err.Error(), "connection") ||
					strings.Contains(err.Error(), "temporary") {
					lu.logger.Debug("GraphQL query failed with retryable error", "error", err)
					return err // Retry
				}
				// Non-retryable errors (e.g., authentication, syntax errors)
				lu.logger.Debug("GraphQL query failed with non-retryable error", "error", err)
				return retry.Unrecoverable(err)
			}
			return nil
		},
		retry.Attempts(3), // Fewer attempts for GraphQL since it's more expensive
		retry.Delay(200*time.Millisecond),
		retry.MaxDelay(30*time.Second), // Shorter max delay for GraphQL
		retry.DelayType(retry.BackOffDelay),
		retry.Context(ctx),
	)
}
