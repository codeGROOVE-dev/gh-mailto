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
	"sync"
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
		username     = flag.String("user", "", "GitHub username (optional if --org is specified)")
		org          = flag.String("org", "", "GitHub organization (required when --user is omitted)")
		domain       = flag.String("domain", "", "Only include email addresses for this domain (e.g., stromberg.org)")
		guess        = flag.Bool("guess", false, "Guess email address for the domain specified by --domain (requires --user, --org, and --domain)")
		verbose      = flag.Bool("verbose", false, "Enable verbose logging to show queries and results from each method")
		commitsLimit = flag.Int("commits", 100, "Number of commits to search (1-100, default: 100)")
	)
	flag.Parse()

	// Determine mode: if --user is provided, do user lookup; if --org only, list org
	if *username == "" && *org == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s --user <username> [--org <organization>]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "   or: %s --org <organization> [--domain <domain>] (list all org users)\n", os.Args[0])
		flag.PrintDefaults()
		return errors.New("must provide either --user or --org")
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

	// Validate commits limit
	if *commitsLimit < 1 || *commitsLimit > 100 {
		return errors.New("--commits must be between 1 and 100")
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

	// Create lookup with configured options
	lookup := ghmailto.New(token,
		ghmailto.WithLogger(logger),
		ghmailto.WithCommitsLimit(*commitsLimit),
	)

	// Handle org-list mode (--org without --user)
	if *username == "" && *org != "" {
		fmt.Fprintf(os.Stderr, "Fetching all users in %s...\n\n", *org)

		orgCache := ghmailto.NewOrgCacheService(token)
		cache, err := orgCache.OrgCache(ctx, *org)
		if err != nil {
			logger.Error("failed to fetch org cache", "error", err)
			return err
		}

		printOrgList(cache, *domain, *guess, lookup, ctx, *org)
		return nil
	}

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

	// Show all addresses without filtering
	// (Filtering can hide valid results when multiple strong patterns exist)
	addressesToShow := result.Addresses

	// Display addresses with clean Unix-style formatting
	for _, addr := range addressesToShow {
		sourceText := extractSourceText(addr)
		patternText := formatPattern(addr.Pattern)
		confirmationText := formatConfirmationSource(addr.Sources, addr.Pattern)

		fmt.Printf("• %d%% - %s%s%s: %s%s%s",
			addr.Confidence,
			colorBold+colorWhite, addr.Email, colorReset,
			colorDim, sourceText, colorReset)

		// Add pattern information if available
		if patternText != "" {
			fmt.Printf(" %s[%s]%s", colorDim, patternText, colorReset)
		}

		// Add confirmation information if available
		if confirmationText != "" {
			fmt.Printf(" %s✓ %s%s", colorDim, confirmationText, colorReset)
		}

		fmt.Print("\n")
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

// formatPattern converts a technical pattern identifier to a user-friendly display name.
func formatPattern(pattern string) string {
	if pattern == "" {
		return ""
	}

	// Handle combined patterns (e.g., "flast+flast") - patterns combined with "+"
	if strings.Contains(pattern, "+") {
		combinedParts := strings.Split(pattern, "+")
		var formattedParts []string
		for _, part := range combinedParts {
			if formatted := formatSinglePattern(part); formatted != "" {
				formattedParts = append(formattedParts, formatted)
			}
		}
		if len(formattedParts) > 1 {
			return strings.Join(formattedParts, " + ")
		} else if len(formattedParts) == 1 {
			return formattedParts[0]
		}
	}

	return formatSinglePattern(pattern)
}

// formatSinglePattern formats a single pattern without combined logic.
func formatSinglePattern(pattern string) string {
	// Handle compound patterns (e.g., "first.last_username_commits_found")
	parts := strings.Split(pattern, "_")
	basePattern := parts[0]

	switch basePattern {
	case "first.last":
		return "First.Last"
	case "first":
		return "FirstName"
	case "flast":
		return "F.LastName"
	case "last":
		return "LastName"
	case "initials":
		return "Initials"
	case "firstlast":
		return "FirstnameLastname"
	case "github":
		if len(parts) > 2 && parts[1] == "username" {
			if parts[2] == "exact" {
				return "GitHub Username"
			}
			if parts[2] == "prefix" {
				return "GitHub Username Prefix"
			}
		}
		return "GitHub Username"
	case "same":
		if len(parts) >= 4 && strings.Join(parts[:4], "_") == "same_prefix_as_other" {
			return "Same Prefix"
		}
		return "Same Pattern"
	case "single":
		return "Single Name"
	case "parsed":
		if len(parts) > 1 && parts[1] == "username" {
			return "Parsed Username"
		}
		return "Parsed"
	case "profile":
		if len(parts) >= 3 && strings.Join(parts[:3], "_") == "profile_parsed_username" {
			return "Profile-Based Parse"
		}
		return "Profile-Based"
	case "git":
		if len(parts) > 1 && parts[1] == "commits" {
			return "Discovery (actual email found)"
		}
		return "Git-Based"
	case "verified":
		return "Verified Address"
	case "saml":
		return "SAML Identity"
	case "org":
		if len(parts) > 1 {
			switch parts[1] {
			case "verified":
				return "Org Verified Domains"
			case "member":
				return "Org Member"
			default:
				return "Organization"
			}
		}
		return "Organization"
	case "public":
		if len(parts) > 1 && parts[1] == "api" {
			return "Public API"
		}
		return "Public"
	default:
		// Handle unknown patterns gracefully by capitalizing first letter
		cleaned := strings.ReplaceAll(basePattern, "_", " ")
		if cleaned == "" {
			return ""
		}
		return strings.ToUpper(cleaned[:1]) + cleaned[1:]
	}
}

// formatConfirmationSource extracts and formats the confirmation source from address sources.
func formatConfirmationSource(sources map[string]string, pattern string) string {
	if sources == nil {
		return ""
	}

	// Check for GitHub search confirmations with specific details
	if searchResult, exists := sources["github_search"]; exists {
		return fmt.Sprintf("GitHub Issues/PRs (%s)", searchResult)
	}
	if searchResult, exists := sources["batched_github_search"]; exists {
		return fmt.Sprintf("GitHub Issues/PRs (%s)", searchResult)
	}

	// Check for commit-based confirmations with specific details
	if commitResult, exists := sources["commit_search"]; exists {
		return fmt.Sprintf("Git Commits (%s)", commitResult)
	}
	if commitResult, exists := sources["github_commits_found"]; exists {
		return fmt.Sprintf("Git Commits (%s)", commitResult)
	}

	// Check for organizations found in commits
	if orgs, exists := sources["found_in_orgs"]; exists && orgs != "" {
		return fmt.Sprintf("Git Commits (in %s)", orgs)
	}

	// Check pattern-based indications
	if strings.Contains(pattern, "git_commits") {
		return "Git Commits"
	}
	if strings.Contains(pattern, "commits_found") {
		return "Git Commits"
	}

	// Check for other validation sources
	if _, exists := sources["github_issues"]; exists {
		return "GitHub Issues"
	}
	if _, exists := sources["github_prs"]; exists {
		return "GitHub PRs"
	}

	return ""
}

// printGuessResults displays the guess results in a formatted manner.
func printGuessResults(result *ghmailto.GuessResult, _, _, domain string) {
	// Use the shared filtering logic
	allResults, showWarning := ghmailto.CombineAndFilterGuessResults(result, domain)

	if len(allResults) == 0 {
		fmt.Printf("%sNo email guesses could be generated%s\n", colorDim, colorReset)
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
		patternText := formatPattern(result.Pattern)
		confirmationText := formatConfirmationSource(result.Sources, result.Pattern)

		fmt.Printf("• %d%% - %s%s%s: %s%s%s",
			result.Confidence,
			colorBold+colorWhite, result.Email, colorReset,
			colorDim, sourceText, colorReset)

		// Add pattern information if available
		if patternText != "" {
			fmt.Printf(" %s[%s]%s", colorDim, patternText, colorReset)
		}

		// Add confirmation information if available
		if confirmationText != "" {
			fmt.Printf(" %s✓ %s%s", colorDim, confirmationText, colorReset)
		}

		fmt.Print("\n")
	}
}

// printOrgList displays all users in an organization with their highest confidence email.
func printOrgList(cache *ghmailto.OrgIdentityCache, domainFilter string, shouldGuess bool, lookup *ghmailto.Lookup, ctx context.Context, org string) {
	if len(cache.Identities) == 0 {
		fmt.Printf("%sNo users found in organization%s\n", colorDim, colorReset)
		return
	}

	// Print header
	fmt.Printf("%sFound %d users in %s%s%s%s:\n\n",
		colorDim, len(cache.Identities),
		colorBrightMagenta, cache.Organization, colorDim, colorReset)

	// Helper function to check if email matches domain filter
	emailMatchesDomain := func(email, domain string) bool {
		if domain == "" {
			return true // No filter, all emails match
		}
		emailParts := strings.Split(email, "@")
		if len(emailParts) < 2 {
			return false
		}
		return strings.EqualFold(emailParts[1], domain)
	}

	// If guessing is enabled, collect users who need guessing in parallel
	type guessTask struct {
		identity ghmailto.OrgIdentity
		index    int
	}

	var tasksToGuess []guessTask
	var results []struct {
		index    int
		username string
		email    string
		confidence int
		sourceText string
		patternText string
		hasGuess bool
	}

	// First pass: identify who needs guessing
	for i, identity := range cache.Identities {
		needsGuess := false

		if shouldGuess && domainFilter != "" && lookup != nil {
			// Need to guess if:
			// 1. No email at all, OR
			// 2. Has email but it doesn't match the target domain
			if identity.PrimaryEmail == "" {
				needsGuess = true
			} else if !emailMatchesDomain(identity.PrimaryEmail, domainFilter) {
				needsGuess = true
			}
		}

		if needsGuess {
			tasksToGuess = append(tasksToGuess, guessTask{identity: identity, index: i})
		}
	}

	// Perform guesses in parallel if there are any
	if len(tasksToGuess) > 0 {
		fmt.Fprintf(os.Stderr, "%sGuessing emails for %d users...%s\n", colorDim, len(tasksToGuess), colorReset)

		type guessResult struct {
			index    int
			username string
			guessResult *ghmailto.GuessResult
			err      error
		}

		resultsChan := make(chan guessResult, len(tasksToGuess))
		var wg sync.WaitGroup

		// Limit parallelism to avoid rate limiting
		// Set to 1 for sequential processing to avoid hitting GitHub rate limits
		semaphore := make(chan struct{}, 1)

		for _, task := range tasksToGuess {
			wg.Add(1)
			go func(t guessTask) {
				defer wg.Done()
				semaphore <- struct{}{}        // Acquire
				defer func() { <-semaphore }() // Release

				guessRes, err := lookup.Guess(ctx, t.identity.GitHubUsername, org, ghmailto.GuessOptions{
					Domain: domainFilter,
				})
				resultsChan <- guessResult{
					index:       t.index,
					username:    t.identity.GitHubUsername,
					guessResult: guessRes,
					err:         err,
				}
			}(task)
		}

		go func() {
			wg.Wait()
			close(resultsChan)
		}()

		// Collect results
		guessMap := make(map[int]guessResult)
		for res := range resultsChan {
			guessMap[res.index] = res
		}

		// Convert to display format
		for idx, res := range guessMap {
			if res.err == nil && res.guessResult != nil && len(res.guessResult.Guesses) > 0 {
				topGuess := res.guessResult.Guesses[0]
				sourceText := extractSourceText(topGuess)
				patternText := formatPattern(topGuess.Pattern)

				results = append(results, struct {
					index       int
					username    string
					email       string
					confidence  int
					sourceText  string
					patternText string
					hasGuess    bool
				}{
					index:       idx,
					username:    res.username,
					email:       topGuess.Email,
					confidence:  topGuess.Confidence,
					sourceText:  sourceText,
					patternText: patternText,
					hasGuess:    true,
				})
			}
		}
	}

	// Create a map for quick lookup of guess results by index
	guessResultMap := make(map[int]struct {
		email       string
		confidence  int
		sourceText  string
		patternText string
	})
	for _, r := range results {
		guessResultMap[r.index] = struct {
			email       string
			confidence  int
			sourceText  string
			patternText string
		}{
			email:       r.email,
			confidence:  r.confidence,
			sourceText:  r.sourceText,
			patternText: r.patternText,
		}
	}

	// Second pass: print results
	guessCount := 0
	for i, identity := range cache.Identities {
		// Check if we have a guess for this user
		if guessRes, hasGuess := guessResultMap[i]; hasGuess {
			guessCount++
			fmt.Printf("• %d%% - %s%-20s%s → %s%s%s %s(%s)%s",
				guessRes.confidence,
				colorBrightBlue, identity.GitHubUsername, colorReset,
				colorBold+colorWhite, guessRes.email, colorReset,
				colorDim, guessRes.sourceText, colorReset)

			if guessRes.patternText != "" {
				fmt.Printf(" %s[%s]%s", colorDim, guessRes.patternText, colorReset)
			}
			fmt.Print("\n")
			continue
		}

		// Skip if domain filter specified and doesn't match
		if domainFilter != "" && identity.PrimaryEmail != "" {
			if !emailMatchesDomain(identity.PrimaryEmail, domainFilter) {
				continue
			}
		}

		// Determine confidence based on source
		confidence := 85
		if identity.Verified {
			confidence = 95
		}

		// Format source
		sourceText := formatSourceText(identity.Source, identity.Verified)

		if identity.PrimaryEmail != "" {
			fmt.Printf("• %d%% - %s%-20s%s → %s%s%s %s(%s)%s\n",
				confidence,
				colorBrightBlue, identity.GitHubUsername, colorReset,
				colorBold+colorWhite, identity.PrimaryEmail, colorReset,
				colorDim, sourceText, colorReset)
		} else {
			// Only show "no email" if not guessing or domain filter not specified
			if !shouldGuess || domainFilter == "" {
				fmt.Printf("• %s%-20s%s %s(no email)%s\n",
					colorBrightBlue, identity.GitHubUsername, colorReset,
					colorDim, colorReset)
			}
		}
	}

	fmt.Printf("\n%sStatistics:%s\n", colorDim, colorReset)
	fmt.Printf("  • Total members: %d\n", cache.TotalMembers)
	fmt.Printf("  • SAML identities: %d\n", cache.SAMLCount)
	fmt.Printf("  • Verified domains: %d\n", cache.VerifiedCount)
	fmt.Printf("  • Public emails: %d\n", cache.PublicEmailCount)
	if guessCount > 0 {
		fmt.Printf("  • Guessed emails: %d\n", guessCount)
	}
	fmt.Println()
}

// formatSourceText formats the identity source for display.
func formatSourceText(source string, verified bool) string {
	var sourceDisplay string
	switch source {
	case "saml":
		sourceDisplay = "SAML"
	case "verified_domain":
		sourceDisplay = "Verified Domain"
	case "public_profile":
		sourceDisplay = "Public Profile"
	case "org_member":
		sourceDisplay = "Org Member"
	default:
		sourceDisplay = source
	}

	if verified {
		return fmt.Sprintf("%s ✓", sourceDisplay)
	}
	return sourceDisplay
}
