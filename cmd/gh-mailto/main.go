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
		fmt.Fprintf(os.Stderr, "Hunting for possible e-mail addresses for %s within %s...\n\n", *username, *domain)

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
	addressesToShow, showLowConfidenceWarning := ghmailto.FilterHighConfidenceAddresses(result.Addresses)

	// Show warning if we're displaying low-confidence results
	if showLowConfidenceWarning {
		fmt.Printf("%s⚠️  No high confidence addresses found, showing all possibilities:%s\n\n",
			colorYellow, colorReset)
	}

	// Display addresses with clean Unix-style formatting
	for _, addr := range addressesToShow {
		sourceText := extractSourceText(addr)
		fmt.Printf("• %d%% - %s%s%s: %s%s%s\n",
			addr.Confidence,
			colorBold+colorWhite, addr.Email, colorReset,
			colorDim, sourceText, colorReset)
	}
	fmt.Println()
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

// extractSourceText extracts a clean source description from an address.
func extractSourceText(addr ghmailto.Address) string {
	// Check for pattern-based sources (guesses)
	if addr.Pattern != "" {
		var sources []string

		// Collect all available sources
		if sourceEmail, exists := addr.Sources["source_email"]; exists {
			sources = append(sources, sourceEmail)
		}
		if sourceName, exists := addr.Sources["source_name"]; exists {
			sources = append(sources, sourceName)
		}
		if sourceUsername, exists := addr.Sources["source_username"]; exists {
			sources = append(sources, sourceUsername)
		}

		if len(sources) > 0 {
			return fmt.Sprintf("from %s", strings.Join(sources, ", "))
		}
		return fmt.Sprintf("from %s", addr.Pattern)
	}

	// Check for method-based sources
	if len(addr.Methods) > 0 {
		method := addr.Methods[0] // Use first method
		methodName := formatMethodModern(method)

		// Add organization info if available
		if strings.Contains(strings.ToLower(method), "commit") {
			if orgs, hasOrgs := addr.Sources["found_in_orgs"]; hasOrgs && orgs != "" {
				return fmt.Sprintf("from %s in %s", methodName, orgs)
			}
		}
		return fmt.Sprintf("from %s", methodName)
	}

	return "unknown source"
}

// printGuessResults displays the guess results in a formatted manner.
func printGuessResults(result *ghmailto.GuessResult, _, _, domain string) {
	// Use the shared filtering logic
	allResults, showWarning := ghmailto.CombineAndFilterGuessResults(result, domain)

	if len(allResults) == 0 {
		printNoGuessesMessageModern()
		return
	}

	// Show warning if we're displaying low-confidence results
	if showWarning {
		fmt.Printf("%s⚠️  No high confidence addresses found, showing all possibilities:%s\n\n",
			colorYellow, colorReset)
	}

	// Use same simple format for all results
	for _, result := range allResults {
		sourceText := extractSourceText(result)
		fmt.Printf("• %d%% - %s%s%s: %s%s%s\n",
			result.Confidence,
			colorBold+colorWhite, result.Email, colorReset,
			colorDim, sourceText, colorReset)
	}
}

// printNoGuessesMessageModern prints a simple message when no guesses are generated.
func printNoGuessesMessageModern() {
	fmt.Printf("%sNo email guesses could be generated%s\n", colorDim, colorReset)
}
