// Package main provides the gh-mailto CLI tool for discovering GitHub email addresses.
package main

import (
	"context"
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
	var (
		username  = flag.String("user", "", "GitHub username")
		org       = flag.String("org", "", "GitHub organization")
		domain    = flag.String("domain", "", "Only include email addresses for this domain (e.g., stromberg.org)")
		normalize = flag.Bool("normalize", false, "Normalize email addresses (remove +suffix, lowercase)")
	)
	flag.Parse()

	if *username == "" || *org == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s --user <username> --org <organization>\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Set up logger
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	}))

	// Get token
	token, err := getGHToken()
	if err != nil {
		logger.Error("failed to get GitHub token", "error", err)
		os.Exit(1)
	}

	// Create context with timeout (hard-coded to 30 seconds)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	// Create lookup with hard-coded defaults
	lookup := ghmailto.New(token, ghmailto.WithLogger(logger))

	// Show progress message
	fmt.Fprintf(os.Stderr, "Looking up email addresses for %s in %s...\n", *username, *org)

	result, err := lookup.Lookup(ctx, *username, *org)
	if err != nil {
		logger.Error("failed to lookup addresses", "error", err)
		cancel()
		os.Exit(1)
	}
	cancel()

	// Filter and normalize results
	filteredResult := result.FilterAndNormalize(ghmailto.FilterOptions{
		Domain:    *domain,
		Normalize: *normalize,
	})

	// Print results
	printResults(filteredResult, *username, *org)
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
