// Package main provides a web interface for the gh-mailto tool.
package main

import (
	"context"
	_ "embed"
	"flag"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	ghmailto "github.com/codeGROOVE-dev/gh-mailto/pkg/gh-mailto"
	"golang.org/x/time/rate"
)

//go:embed static/index.html
var htmlTemplate string

//go:embed static/logo-small.png
var logoData []byte

type CacheEntry struct {
	Result    any
	Timestamp time.Time
}

type Cache struct {
	entries  map[string]CacheEntry
	mu       sync.RWMutex
	maxSize  int
	hitCount int
}

func NewCache(maxSize int) *Cache {
	return &Cache{
		entries: make(map[string]CacheEntry),
		maxSize: maxSize,
	}
}

func (c *Cache) Get(key string) (any, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if entry, exists := c.entries[key]; exists {
		// No TTL - cache entries are valid until evicted
		c.hitCount++
		return entry.Result, true
		// Entry is stale, will be cleaned up by next Set operation
	}
	return nil, false
}

func (c *Cache) Set(key string, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Security: Validate cache key to prevent malicious keys
	if len(key) > 100 {
		return // Reject overly long keys
	}

	// Clean up entries if we're at capacity (no TTL-based cleanup for Cloud Run)

	// If still at capacity, evict oldest entry
	if len(c.entries) >= c.maxSize {
		var oldestKey string
		var oldestTime time.Time

		first := true
		for key, entry := range c.entries {
			if first || entry.Timestamp.Before(oldestTime) {
				oldestKey = key
				oldestTime = entry.Timestamp
				first = false
			}
		}

		if oldestKey != "" {
			delete(c.entries, oldestKey)
		}
	}

	c.entries[key] = CacheEntry{
		Result:    value,
		Timestamp: time.Now(),
	}
}

func (c *Cache) Stats() (size, maxSize, hits int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries), c.maxSize, c.hitCount
}

type PageData struct { //nolint:govet // struct alignment acceptable for web interface data
	CacheSize            int
	CacheMaxSize         int
	CacheHits            int
	Username             string
	Domain               string
	Error                string
	Guess                bool
	CacheHit             bool
	Results              any
	LowConfidenceWarning bool
}

var (
	cache   *Cache
	limiter *rate.Limiter
)

func main() {
	port := flag.String("port", "", "Port to serve on (defaults to $PORT env var or 8080)")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	flag.Parse()

	// Initialize cache and rate limiter
	cache = NewCache(1000)
	limiter = rate.NewLimiter(rate.Limit(4), 8) // 4 QPS with burst of 8

	// Use PORT environment variable if available (for Cloud Run)
	if *port == "" {
		if envPort := os.Getenv("PORT"); envPort != "" {
			*port = envPort
		} else {
			*port = "8080"
		}
	}

	// Set up logger
	logLevel := slog.LevelWarn
	if *verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	}))

	// Parse template with custom functions
	tmpl := template.Must(template.New("index").Funcs(template.FuncMap{
		"add":  func(a, b int) int { return a + b },
		"join": strings.Join,
		"formatMethodWithOrgs": func(method string, sources map[string]string) string {
			methodName := method
			if strings.Contains(strings.ToLower(method), "commit") {
				if orgs, hasOrgs := sources["found_in_orgs"]; hasOrgs && orgs != "" {
					return methodName + " in " + orgs
				}
			}
			return methodName
		},
		"joinMethodsWithOrgs": func(methods []string, sources map[string]string) string {
			var formattedMethods []string
			for _, method := range methods {
				methodName := method
				if strings.Contains(strings.ToLower(method), "commit") {
					if orgs, hasOrgs := sources["found_in_orgs"]; hasOrgs && orgs != "" {
						methodName = method + " in " + orgs
					}
				}
				formattedMethods = append(formattedMethods, methodName)
			}
			return strings.Join(formattedMethods, ", ")
		},
		"formatSources": func(sources map[string]string) string {
			var sourceList []string

			// Collect all available sources in consistent order
			if sourceEmail, exists := sources["source_email"]; exists {
				sourceList = append(sourceList, sourceEmail)
			}
			if sourceName, exists := sources["source_name"]; exists {
				sourceList = append(sourceList, sourceName)
			}
			if sourceUsername, exists := sources["source_username"]; exists {
				sourceList = append(sourceList, sourceUsername)
			}

			if len(sourceList) > 0 {
				return strings.Join(sourceList, ", ")
			}
			return ""
		},
	}).Parse(htmlTemplate))

	// Serve embedded logo
	http.HandleFunc("/static/logo-small.png", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=31536000") // Cache for 1 year
		_, _ = w.Write(logoData)                                    //nolint:errcheck // Static data, write errors are not actionable
	})

	http.HandleFunc("/", rateLimitMiddleware(handleRequest(tmpl, logger), logger))

	logger.Info("starting server", "port", *port)
	fmt.Printf("GitHub email lookup server starting on http://localhost:%s\n", *port)
	fmt.Println("Cache initialized for 1000 entries (no TTL for Cloud Run)")

	server := &http.Server{
		Addr:         ":" + *port,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func rateLimitMiddleware(next http.HandlerFunc, logger *slog.Logger) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if !limiter.Allow() {
			logger.Warn("rate limit exceeded", "remote_addr", request.RemoteAddr)
			http.Error(writer, "Rate limit exceeded. Please slow down.", http.StatusTooManyRequests)
			return
		}
		next(writer, request)
	}
}

func handleRequest(tmpl *template.Template, logger *slog.Logger) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		data := PageData{}

		// Always populate cache stats
		size, maxSize, hits := cache.Stats()
		data.CacheSize = size
		data.CacheMaxSize = maxSize
		data.CacheHits = hits

		if request.Method == http.MethodPost {
			data = handlePostRequest(request, logger)
		}

		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := tmpl.Execute(writer, data); err != nil {
			logger.Error("template execution failed", "error", err)
			// Can't call http.Error here since we've already started writing the response
			// The error will be visible in the logs
		}
	}
}

func handlePostRequest(request *http.Request, logger *slog.Logger) PageData {
	username := strings.TrimSpace(request.FormValue("username"))
	domain := strings.TrimSpace(request.FormValue("domain"))
	guess := request.FormValue("guess") == "on"

	data := PageData{
		Username: username,
		Domain:   domain,
		Guess:    guess,
	}

	// Basic input sanitization - prevent control characters and excessive length
	if len(username) > 100 || len(domain) > 300 {
		data.Error = "Input too long"
		return data
	}

	if strings.ContainsAny(username, "\r\n\t\x00") || strings.ContainsAny(domain, "\r\n\t\x00") {
		data.Error = "Input contains invalid characters"
		return data
	}

	// Populate cache stats
	size, maxSize, hits := cache.Stats()
	data.CacheSize = size
	data.CacheMaxSize = maxSize
	data.CacheHits = hits

	if username == "" {
		data.Error = "Username is required"
		return data
	}

	// Generate cache key
	cacheKey := fmt.Sprintf("%s|%s|%t", username, domain, guess)

	// Try cache first
	if cachedResult, found := cache.Get(cacheKey); found {
		data.Results = cachedResult
		data.CacheHit = true
		logger.Debug("cache hit", "username", username, "domain", domain, "guess", guess)
		return data
	}

	token, err := getGHToken(request.Context())
	if err != nil {
		data.Error = fmt.Sprintf("Failed to get GitHub token: %v", err)
		return data
	}

	lookup := ghmailto.New(token, ghmailto.WithLogger(logger))
	ctx, cancel := context.WithTimeout(request.Context(), 30*time.Second)
	defer cancel()

	if guess && domain != "" {
		guessResult, err := lookup.Guess(ctx, username, "", ghmailto.GuessOptions{
			Domain: domain,
		})
		if err != nil {
			data.Error = fmt.Sprintf("Guess failed: %v", err)
		} else {
			// Use the same filtering logic as the CLI
			combinedResults, showWarning := ghmailto.CombineAndFilterGuessResults(guessResult, domain)

			// Create a new GuessResult with the combined filtered results
			// We need to split them back for display purposes, but they're already properly filtered
			filteredResult := &ghmailto.GuessResult{
				FoundAddresses: []ghmailto.Address{},
				Guesses:        combinedResults, // Put all results in Guesses for unified display
			}

			data.LowConfidenceWarning = showWarning
			data.Results = filteredResult
		}
	} else {
		result, err := lookup.Lookup(ctx, username, "")
		if err != nil {
			data.Error = fmt.Sprintf("Lookup failed: %v", err)
		} else {
			// Filter and normalize results
			filteredResult := result.FilterAndNormalize(ghmailto.FilterOptions{
				Domain: domain,
			})

			// Filter high-confidence results using the shared function
			filteredAddresses, showWarning := ghmailto.FilterHighConfidenceAddresses(filteredResult.Addresses)
			filteredResult.Addresses = filteredAddresses
			data.LowConfidenceWarning = showWarning

			data.Results = filteredResult
		}
	}

	// Cache the result if no error
	if data.Error == "" && data.Results != nil {
		cache.Set(cacheKey, data.Results)
		logger.Debug("cached result", "username", username, "domain", domain, "guess", guess)
	}

	return data
}

// getGHToken gets the GitHub token from environment variable or gh CLI.
func getGHToken(ctx context.Context) (string, error) {
	// First try environment variable (for Cloud Run)
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		return token, nil
	}

	// Fall back to gh CLI
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(timeoutCtx, "gh", "auth", "token")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("no GITHUB_TOKEN environment variable and gh auth token failed: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}
