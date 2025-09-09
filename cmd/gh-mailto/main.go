// Package main provides the gh-mailto CLI tool for discovering GitHub email addresses.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	ghmailto "github.com/codeGROOVE-dev/gh-mailto/pkg/gh-mailto"
)

// ANSI color codes for modern terminal output.
const (
	colorReset     = "\033[0m"
	colorBold      = "\033[1m"
	colorDim       = "\033[2m"
	colorUnderline = "\033[4m"

	// Colors.
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorWhite   = "\033[37m"

	// Bright colors.
	colorBrightBlue    = "\033[94m"
	colorBrightGreen   = "\033[92m"
	colorBrightYellow  = "\033[93m"
	colorBrightMagenta = "\033[95m"
	colorBrightCyan    = "\033[96m"

	// Background colors.
)

// Unicode symbols for modern output.
const (
	symbolVerified   = "🔒"
	symbolUnverified = "📧"
	symbolGuess      = "🔍"
	symbolFound      = "✨"
	symbolArrow      = "→"
	symbolBullet     = "•"
	symbolCheck      = "✓"
	symbolCross      = "✗"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		username = flag.String("user", "", "GitHub username")
		org      = flag.String("org", "", "GitHub organization")
		domain   = flag.String("domain", "", "Only include email addresses for this domain (e.g., stromberg.org)")
		guess    = flag.Bool("guess", false, "Guess email address for the domain specified by --domain (requires --user, --org, and --domain)")
		verbose  = flag.Bool("verbose", false, "Enable verbose logging to show queries and results from each method")
	)
	flag.Parse()

	if *username == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s --user <username> [--org <organization>]\n", os.Args[0])
		flag.PrintDefaults()
		return errors.New("missing required arguments")
	}

	// Basic input validation to prevent injection attacks
	if strings.ContainsAny(*username, "\r\n\t") {
		return errors.New("username cannot contain control characters")
	}

	if *org != "" && strings.ContainsAny(*org, "\r\n\t") {
		return errors.New("organization cannot contain control characters")
	}

	if *domain != "" && strings.ContainsAny(*domain, "\r\n\t") {
		return errors.New("domain cannot contain control characters")
	}

	// Additional security validation will be performed by the ghmailto package

	if *guess && *domain == "" {
		return errors.New("--guess requires --domain to be specified")
	}

	// Set up logger
	logLevel := slog.LevelWarn
	if *verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	}))

	// Get token
	token, err := getGHToken()
	if err != nil {
		logger.Error("failed to get GitHub token", "error", err)
		return err
	}

	// Create context with timeout (hard-coded to 30 seconds)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create lookup with hard-coded defaults
	lookup := ghmailto.New(token, ghmailto.WithLogger(logger))

	// Handle guess mode
	if *guess {
		fmt.Fprintf(os.Stderr, "Guessing %s@%s...\n\n", *username, *domain)

		guessResult, err := lookup.Guess(ctx, *username, *org, ghmailto.GuessOptions{
			Domain: *domain,
		})
		if err != nil {
			logger.Error("failed to guess addresses", "error", err)
			return err
		}

		printGuessResults(guessResult, *username, *org, *domain)
		return nil
	}

	// Show progress message
	if *org != "" {
		fmt.Fprintf(os.Stderr, "Looking up %s/%s...\n\n", *org, *username)
	} else {
		fmt.Fprintf(os.Stderr, "Looking up %s...\n\n", *username)
	}

	result, err := lookup.Lookup(ctx, *username, *org)
	if err != nil {
		logger.Error("failed to lookup addresses", "error", err)
		return err
	}

	// Filter and normalize results
	filteredResult := result.FilterAndNormalize(ghmailto.FilterOptions{
		Domain: *domain,
	})

	// Print results
	printResults(filteredResult, *username, *org)
	return nil
}

// getGHToken runs 'gh auth token' to get the GitHub token.
func getGHToken() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "gh", "auth", "token")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("gh auth token failed: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

// printResults displays the lookup results in a formatted manner.
func printResults(result *ghmailto.Result, username, org string) {
	if len(result.Addresses) == 0 {
		if org != "" {
			fmt.Printf("%sNo email addresses found for %s%s%s in %s%s%s%s\n",
				colorDim, colorBrightBlue, username, colorDim,
				colorBrightMagenta, org, colorDim, colorReset)
		} else {
			fmt.Printf("%sNo email addresses found for %s%s%s%s\n",
				colorDim, colorBrightBlue, username, colorDim, colorReset)
		}
		return
	}

	// Filter results to show only high-confidence ones if any exist above 60%
	addressesToShow := filterHighConfidenceResults(result.Addresses)

	// Display addresses with clean Unix-style formatting
	for index, addr := range addressesToShow {
		// Status symbol and confidence
		var statusSymbol, statusColor string
		if addr.Verified {
			statusSymbol = symbolVerified
			statusColor = colorBrightGreen
		} else {
			statusSymbol = symbolUnverified
			statusColor = colorBrightYellow
		}

		// Confidence visualization
		confidenceBar := getConfidenceBar(addr.Confidence)

		fmt.Printf("%s%s %s%s%s %s(%d%%)%s\n",
			statusColor, statusSymbol, colorBold+colorWhite, addr.Email, colorReset,
			confidenceBar, addr.Confidence, colorReset)

		// Sources with subtle styling
		sourcesText := formatAddressSourcesModern(addr)
		if sourcesText != "" {
			fmt.Printf("  %s%s%s\n", colorDim, sourcesText, colorReset)
		}

		if index < len(addressesToShow)-1 {
			fmt.Println()
		}
	}
	fmt.Println()
}

// getConfidenceBar creates a visual confidence bar.
func getConfidenceBar(confidence int) string {
	var color string
	switch {
	case confidence >= 95:
		color = colorBrightGreen
	case confidence >= 80:
		color = colorBrightYellow
	case confidence >= 60:
		color = colorYellow
	default:
		color = colorRed
	}

	return fmt.Sprintf("%s%s", color, colorReset)
}

// formatAddressSourcesModern formats sources with modern styling.
func formatAddressSourcesModern(addr ghmailto.Address) string {
	if len(addr.Sources) == 0 && len(addr.Methods) == 0 {
		return ""
	}

	if len(addr.Sources) > 0 {
		var sources []string
		for _, method := range addr.Methods {
			if rawEmail, exists := addr.Sources[method]; exists {
				methodName := formatMethodModern(method)

				// Check if we have organization info for commit-related methods
				var orgInfo string
				if strings.Contains(strings.ToLower(method), "commit") {
					if orgs, hasOrgs := addr.Sources["found_in_orgs"]; hasOrgs && orgs != "" {
						orgInfo = fmt.Sprintf(" in %s", orgs)
					}
				}

				if rawEmail != addr.Email {
					sources = append(sources, fmt.Sprintf("%s%s%s%s %s%s%s",
						colorBrightCyan, methodName, orgInfo, colorReset,
						colorDim, rawEmail, colorReset))
				} else {
					sources = append(sources, fmt.Sprintf("%s%s%s%s",
						colorBrightCyan, methodName, orgInfo, colorReset))
				}
			}
		}
		if len(sources) > 0 {
			return fmt.Sprintf("%s via %s", symbolArrow, strings.Join(sources, ", "))
		}
	}

	// Fallback to methods only
	if len(addr.Methods) > 0 {
		var methods []string
		for _, method := range addr.Methods {
			methodName := formatMethodModern(method)

			// Check if we have organization info for commit-related methods
			var orgInfo string
			if strings.Contains(strings.ToLower(method), "commit") {
				if orgs, hasOrgs := addr.Sources["found_in_orgs"]; hasOrgs && orgs != "" {
					orgInfo = fmt.Sprintf(" in %s", orgs)
				}
			}

			methods = append(methods, fmt.Sprintf("%s%s%s%s",
				colorBrightCyan, methodName, orgInfo, colorReset))
		}
		return fmt.Sprintf("%s via %s", symbolArrow, strings.Join(methods, ", "))
	}

	return ""
}

// formatMethodModern converts method names to modern display format.
func formatMethodModern(method string) string {
	switch method {
	case "public_api":
		return "Public API"
	case "commits":
		return "Git Commits"
	case "saml_identity":
		return "SAML Identity"
	case "org_verified_domains":
		return "Verified Domains"
	case "org_members":
		return "Organization"
	case "github_issues":
		return "Issues"
	case "github_prs":
		return "Pull Requests"
	case "github_issues_prs":
		return "Issues & PRs"
	case "github_commits":
		return "Commits"
	case "github_issue_content":
		return "Issue Content"
	case "github_pr_content":
		return "PR Content"
	default:
		words := strings.Split(method, "_")
		for i, word := range words {
			if word != "" {
				words[i] = strings.ToUpper(word[:1]) + word[1:]
			}
		}
		return strings.Join(words, " ")
	}
}

// printGuessResults displays the guess results in a formatted manner.
func printGuessResults(result *ghmailto.GuessResult, _, _, domain string) {
	// Filter found addresses by domain if specified
	filteredFoundAddresses := result.FoundAddresses
	if domain != "" {
		var filtered []ghmailto.Address
		for _, addr := range result.FoundAddresses {
			// Extract domain from email address
			atIndex := strings.LastIndex(addr.Email, "@")
			if atIndex != -1 && atIndex < len(addr.Email)-1 {
				emailDomain := addr.Email[atIndex+1:]
				if strings.EqualFold(emailDomain, domain) {
					filtered = append(filtered, addr)
				}
			}
		}
		filteredFoundAddresses = filtered
	}

	// Combine all results (guesses + found addresses) into a single list
	var allResults []ghmailto.Address
	seen := make(map[string]bool)

	// Add found addresses first (they have priority over guesses)
	for _, addr := range filteredFoundAddresses {
		email := strings.ToLower(addr.Email)
		if !seen[email] {
			allResults = append(allResults, addr)
			seen[email] = true
		}
	}

	// Add guesses (skip if already seen as found address)
	for _, guess := range result.Guesses {
		email := strings.ToLower(guess.Email)
		if !seen[email] {
			allResults = append(allResults, guess)
			seen[email] = true
		}
	}

	if len(allResults) == 0 {
		printNoGuessesMessageModern()
		return
	}

	// Sort by confidence (highest first)
	sort.Slice(allResults, func(i, j int) bool {
		return allResults[i].Confidence > allResults[j].Confidence
	})

	// Display unified results
	printUnifiedResults(allResults)
}

// printUnifiedResults displays all results (guesses + found addresses) sorted by confidence.
func printUnifiedResults(results []ghmailto.Address) {
	// Filter results to show only high-confidence ones if any exist above 60%
	resultsToShow := filterHighConfidenceResults(results)

	for index, result := range resultsToShow {
		// Determine symbol and color based on whether it's a guess or found address
		var symbol, symbolColor string
		switch {
		case result.Pattern != "":
			// This is a guess (has pattern)
			symbol = symbolGuess
			symbolColor = colorBrightYellow
		case result.Verified:
			// This is a verified found address
			symbol = symbolVerified
			symbolColor = colorBrightGreen
		default:
			// This is an unverified found address
			symbol = symbolUnverified
			symbolColor = colorBrightYellow
		}

		// Confidence visualization
		confidenceBar := getConfidenceBar(result.Confidence)

		// Display the result
		fmt.Printf("%s%s %s%s%s %s(%d%%)%s",
			symbolColor, symbol, colorBold+colorWhite, result.Email, colorReset,
			confidenceBar, result.Confidence, colorReset)

		// Show pattern for guesses or method summary for found addresses
		if result.Pattern != "" {
			// Show guess pattern with source information if available
			patternDisplay := result.Pattern
			if sourceEmail, exists := result.Sources["source_email"]; exists {
				patternDisplay = fmt.Sprintf("%s (from %s)", result.Pattern, sourceEmail)
			} else if sourceName, exists := result.Sources["source_name"]; exists {
				patternDisplay = fmt.Sprintf("%s (from name: %s)", result.Pattern, sourceName)
			} else if sourceUsername, exists := result.Sources["source_username"]; exists {
				patternDisplay = fmt.Sprintf("%s (from username: %s)", result.Pattern, sourceUsername)
			}
			fmt.Printf(" %s%s%s", colorDim, patternDisplay, colorReset)
		}
		fmt.Println()

		// Show sources/methods with subtle styling
		sourcesText := formatAddressSourcesModern(result)
		if sourcesText != "" {
			fmt.Printf("  %s%s%s\n", colorDim, sourcesText, colorReset)
		}

		if index < len(resultsToShow)-1 {
			fmt.Println()
		}
	}
}

// printNoGuessesMessageModern prints a simple message when no guesses are generated.
func printNoGuessesMessageModern() {
	fmt.Printf("%sNo email guesses could be generated%s\n", colorDim, colorReset)
}

// filterHighConfidenceResults filters results to show only high-confidence ones (>60%)
// if any exist, otherwise returns all results.
func filterHighConfidenceResults(addresses []ghmailto.Address) []ghmailto.Address {
	// Check if any addresses have confidence > 60%
	hasHighConfidence := false
	for _, addr := range addresses {
		if addr.Confidence > 60 {
			hasHighConfidence = true
			break
		}
	}

	// If we have high-confidence results, filter to show only those
	if hasHighConfidence {
		var filtered []ghmailto.Address
		for _, addr := range addresses {
			if addr.Confidence > 60 {
				filtered = append(filtered, addr)
			}
		}
		return filtered
	}

	// Otherwise, return all results
	return addresses
}
