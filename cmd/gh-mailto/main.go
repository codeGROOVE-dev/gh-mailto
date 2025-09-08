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

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		username  = flag.String("user", "", "GitHub username")
		org       = flag.String("org", "", "GitHub organization")
		domain    = flag.String("domain", "", "Only include email addresses for this domain (e.g., stromberg.org)")
		normalize = flag.Bool("normalize", false, "Normalize email addresses (remove +suffix, lowercase)")
		guess     = flag.Bool("guess", false, "Guess email address for the domain specified by --domain (requires --user, --org, and --domain)")
		verbose   = flag.Bool("verbose", false, "Enable verbose logging to show queries and results from each method")
	)
	flag.Parse()

	if *username == "" || *org == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s --user <username> --org <organization>\n", os.Args[0])
		flag.PrintDefaults()
		return errors.New("missing required arguments")
	}

	// Basic input validation to prevent injection attacks
	if strings.ContainsAny(*username, "\r\n\t") || strings.ContainsAny(*org, "\r\n\t") {
		return errors.New("username and organization cannot contain control characters")
	}

	if *domain != "" && strings.ContainsAny(*domain, "\r\n\t") {
		return errors.New("domain cannot contain control characters")
	}

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
		fmt.Fprintf(os.Stderr, "Guessing email address for %s in %s for domain %s...\n", *username, *org, *domain)

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
	fmt.Fprintf(os.Stderr, "Looking up email addresses for %s in %s...\n", *username, *org)

	result, err := lookup.Lookup(ctx, *username, *org)
	if err != nil {
		logger.Error("failed to lookup addresses", "error", err)
		return err
	}

	// Filter and normalize results
	filteredResult := result.FilterAndNormalize(ghmailto.FilterOptions{
		Domain:    *domain,
		Normalize: *normalize,
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
	// Header
	const separatorLength = 50
	fmt.Println()
	fmt.Println("GitHub Email Address Lookup")
	fmt.Printf("%s\n", strings.Repeat("=", separatorLength))
	fmt.Printf("User: %s\n", username)
	fmt.Printf("Organization: %s\n", org)
	fmt.Printf("%s\n", strings.Repeat("-", separatorLength))

	if len(result.Addresses) == 0 {
		fmt.Println("\nNo email addresses found.")
		return
	}

	// Group addresses by verification status
	var verified, unverified []ghmailto.Address
	for _, addr := range result.Addresses {
		if addr.Verified {
			verified = append(verified, addr)
		} else {
			unverified = append(unverified, addr)
		}
	}

	// Display verified addresses first
	if len(verified) > 0 {
		fmt.Println("\nVerified Addresses:")
		for _, addr := range verified {
			fmt.Printf("  ✓ %s", addr.Email)
			if len(addr.Methods) > 0 {
				var formatted []string
				for _, method := range addr.Methods {
					formatted = append(formatted, formatMethod(method))
				}
				fmt.Printf(" (via %s)", strings.Join(formatted, ", "))
			}
			fmt.Println()
		}
	}

	// Display unverified addresses
	if len(unverified) > 0 {
		fmt.Println("\nUnverified Addresses:")
		for _, addr := range unverified {
			fmt.Printf("  - %s", addr.Email)
			if len(addr.Methods) > 0 {
				var formatted []string
				for _, method := range addr.Methods {
					formatted = append(formatted, formatMethod(method))
				}
				fmt.Printf(" (via %s)", strings.Join(formatted, ", "))
			}
			fmt.Println()
		}
	}

	// Summary
	fmt.Printf("\n%s\n", strings.Repeat("-", separatorLength))
	fmt.Printf("Total: %d address(es) found", len(result.Addresses))
	if len(verified) > 0 {
		fmt.Printf(" (%d verified)", len(verified))
	}
	fmt.Print("\n\n")
}

// printGuessResults displays the guess results in a formatted manner.
func printGuessResults(result *ghmailto.GuessResult, username, org, domain string) {
	// Header
	const separatorLength = 50
	fmt.Println()
	fmt.Println("GitHub Email Address Guessing")
	fmt.Printf("%s\n", strings.Repeat("=", separatorLength))
	fmt.Printf("User: %s\n", username)
	fmt.Printf("Organization: %s\n", org)
	fmt.Printf("Target Domain: %s\n", domain)
	fmt.Printf("%s\n", strings.Repeat("-", separatorLength))

	if len(result.Guesses) == 0 {
		fmt.Println("\nNo email address guesses generated.")
		fmt.Println("This could happen if:")
		fmt.Println("  - No addresses were found during lookup")
		fmt.Println("  - User has no public name information")
		fmt.Println("  - No usable patterns could be extracted")
	} else {
		fmt.Println("\nEmail Address Guesses (in order of confidence):")
		for i, guess := range result.Guesses {
			fmt.Printf("  %d. %s\n", i+1, guess)
		}
	}

	// Show found addresses for context
	if len(result.FoundAddresses) > 0 {
		fmt.Println("\nAddresses found during lookup (for reference):")
		for _, addr := range result.FoundAddresses {
			fmt.Printf("  - %s", addr.Email)
			if len(addr.Methods) > 0 {
				var formatted []string
				for _, method := range addr.Methods {
					formatted = append(formatted, formatMethod(method))
				}
				fmt.Printf(" (via %s)", strings.Join(formatted, ", "))
			}
			if addr.Verified {
				fmt.Print(" ✓")
			}
			fmt.Println()
		}
	}

	// Summary
	fmt.Printf("\n%s\n", strings.Repeat("-", separatorLength))
	fmt.Printf("Generated %d guess(es) for domain %s", len(result.Guesses), domain)
	fmt.Print("\n\n")
}

// formatMethod converts method constant to human-readable format.
func formatMethod(method string) string {
	switch method {
	case "public_api":
		return "Public API"
	case "commits":
		return "Git Commits"
	case "saml_identity":
		return "SAML Identity"
	case "org_verified_domains":
		return "Org Verified Domains"
	case "org_members":
		return "Org Members API"
	default:
		return method
	}
}
