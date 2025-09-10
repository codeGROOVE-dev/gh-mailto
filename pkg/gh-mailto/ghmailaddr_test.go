package ghmailto

import (
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestIsValidEmail(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid email", "user@example.com", true},
		{"valid with subdomain", "test.user@sub.example.com", true},
		{"valid with plus", "user+tag@example.com", true},
		{"valid with dots", "first.last@example.com", true},
		{"invalid - no @", "invalid", false},
		{"invalid - no local", "@example.com", false},
		{"invalid - no domain", "user@", false},
		{"invalid - no TLD", "user@example", false},
		{"invalid - empty", "", false},
		{"invalid - generic noreply", "noreply@github.com", false},
		{"valid - GitHub user noreply", "147884153+golanglemonade@users.noreply.github.com", true},
		{"invalid - double dots", "user..name@example.com", false},
		{"invalid - starts with dot", ".user@example.com", false},
		{"invalid - ends with dot", "user.@example.com", false},
		{"invalid - space", "user name@example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidEmail(tt.input)
			if got != tt.want {
				t.Errorf("isValidEmail(%q) = %v, want %v", tt.input, got, tt.want)
			}
			// Test backward compatibility (now using isValidEmail directly)
			got2 := isValidEmail(tt.input)
			if got2 != tt.want {
				t.Errorf("isValidEmail(%q) = %v, want %v", tt.input, got2, tt.want)
			}
		})
	}
}

func TestContextCancellation(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	lookup := New("test-token", WithLogger(logger))

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// This should handle the cancelled context gracefully
	result, err := lookup.Lookup(ctx, "testuser", "testorg")
	// We expect it to return quickly with an empty result (methods will fail due to cancelled context)
	if err != nil {
		t.Logf("Got expected error from cancelled context: %v", err)
	}

	if result == nil {
		t.Error("expected non-nil result even with cancelled context")
	} else if result.Username != "testuser" {
		t.Errorf("expected username to be set to testuser, got %s", result.Username)
	}
}

func TestFilterAndNormalize(t *testing.T) {
	// Create test result with various email addresses
	result := &Result{
		Username: "testuser",
		Addresses: []Address{
			{Email: "User.Test+tag@Example.com", Methods: []string{"commits"}, Verified: true},
			{Email: "admin@stromberg.org", Methods: []string{"api"}, Verified: false},
			{Email: "John.Doe+Work@STROMBERG.ORG", Methods: []string{"saml"}, Verified: true},
			{Email: "contact@other.com", Methods: []string{"commits"}, Verified: false},
			{Email: "invalid-email", Methods: []string{"commits"}, Verified: false},
		},
	}

	tests := []struct {
		name     string
		opts     FilterOptions
		expected []string // expected email addresses in result
	}{
		{
			name: "no filtering (emails are always normalized)",
			opts: FilterOptions{},
			expected: []string{
				"user.test@example.com",
				"admin@stromberg.org",
				"john.doe@stromberg.org",
				"contact@other.com",
				"invalid-email",
			},
		},
		{
			name: "filter by domain (case insensitive)",
			opts: FilterOptions{Domain: "stromberg.org"},
			expected: []string{
				"admin@stromberg.org",
				"john.doe@stromberg.org",
			},
		},
		{
			name: "filter by domain with different case",
			opts: FilterOptions{Domain: "STROMBERG.ORG"},
			expected: []string{
				"admin@stromberg.org",
				"john.doe@stromberg.org",
			},
		},
		{
			name:     "filter by non-existent domain",
			opts:     FilterOptions{Domain: "notfound.com"},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := result.FilterAndNormalize(tt.opts)

			if filtered.Username != result.Username {
				t.Errorf("Username not preserved: got %s, want %s", filtered.Username, result.Username)
			}

			if len(filtered.Addresses) != len(tt.expected) {
				t.Errorf("Expected %d addresses, got %d", len(tt.expected), len(filtered.Addresses))
			}

			// Check that all expected emails are present
			gotEmails := make([]string, len(filtered.Addresses))
			for i, addr := range filtered.Addresses {
				gotEmails[i] = addr.Email
			}

			for _, expected := range tt.expected {
				found := false
				for _, got := range gotEmails {
					if got == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected email %s not found in result: %v", expected, gotEmails)
				}
			}

			// Verify methods and verification status are preserved
			for _, addr := range filtered.Addresses {
				if len(addr.Methods) == 0 {
					t.Errorf("Methods not preserved for address %s", addr.Email)
				}
			}
		})
	}
}

func TestFilterAndNormalizeNilResult(t *testing.T) {
	var result *Result
	opts := FilterOptions{Domain: "example.com"}

	filtered := result.FilterAndNormalize(opts)
	if filtered != nil {
		t.Error("Expected nil result to remain nil after filtering")
	}
}

func TestFilterAndNormalizeDeduplication(t *testing.T) {
	// Create test result with addresses that will be duplicates after normalization
	result := &Result{
		Username: "testuser",
		Addresses: []Address{
			{Email: "user@example.com", Methods: []string{"commits"}, Verified: false},
			{Email: "User@Example.com", Methods: []string{"api"}, Verified: true},                        // Same after normalize
			{Email: "user+tag1@example.com", Methods: []string{"saml"}, Verified: false},                 // Same after normalize
			{Email: "user+tag2@example.com", Methods: []string{"org_verified_domains"}, Verified: false}, // Same after normalize
			{Email: "different@example.com", Methods: []string{"commits"}, Verified: false},              // Different
		},
	}

	opts := FilterOptions{}
	filtered := result.FilterAndNormalize(opts)

	// Should have only 2 unique addresses after normalization: user@example.com and different@example.com
	if len(filtered.Addresses) != 2 {
		t.Errorf("Expected 2 unique addresses after deduplication, got %d", len(filtered.Addresses))
	}

	// Find the deduplicated user@example.com address
	var userAddr *Address
	var differentAddr *Address
	for i, addr := range filtered.Addresses {
		if addr.Email == "user@example.com" {
			userAddr = &filtered.Addresses[i]
		}
		if addr.Email == "different@example.com" {
			differentAddr = &filtered.Addresses[i]
		}
	}

	if userAddr == nil {
		t.Fatal("Expected to find user@example.com in results")
	}
	if differentAddr == nil {
		t.Fatal("Expected to find different@example.com in results")
	}

	// The user@example.com address should be verified (upgraded from any verified source)
	if !userAddr.Verified {
		t.Error("Expected user@example.com to be verified after merging")
	}

	// Should have all methods from the deduplicated addresses
	expectedMethods := []string{"api", "commits", "org_verified_domains", "saml"}
	if len(userAddr.Methods) != len(expectedMethods) {
		t.Errorf("Expected %d methods for user@example.com, got %d: %v", len(expectedMethods), len(userAddr.Methods), userAddr.Methods)
	}

	// Verify all expected methods are present (order doesn't matter since they're sorted)
	for _, expectedMethod := range expectedMethods {
		found := false
		for _, method := range userAddr.Methods {
			if method == expectedMethod {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected method %s not found in: %v", expectedMethod, userAddr.Methods)
		}
	}

	// The different@example.com should remain unchanged
	if differentAddr.Verified {
		t.Error("Expected different@example.com to remain unverified")
	}
	if len(differentAddr.Methods) != 1 || differentAddr.Methods[0] != "commits" {
		t.Errorf("Expected different@example.com to have only commits method, got: %v", differentAddr.Methods)
	}
}

func TestNormalizeEmail(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normal email",
			input:    "user@example.com",
			expected: "user@example.com",
		},
		{
			name:     "uppercase email",
			input:    "USER@EXAMPLE.COM",
			expected: "user@example.com",
		},
		{
			name:     "mixed case with plus suffix",
			input:    "User.Name+Tag@Example.Com",
			expected: "user.name@example.com",
		},
		{
			name:     "multiple plus signs",
			input:    "user+tag1+tag2@example.com",
			expected: "user@example.com",
		},
		{
			name:     "plus at beginning of local part",
			input:    "+tag@example.com",
			expected: "@example.com",
		},
		{
			name:     "invalid email no domain",
			input:    "user@",
			expected: "user@",
		},
		{
			name:     "invalid email no at sign",
			input:    "invalid-email",
			expected: "invalid-email",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeEmail(tt.input)
			if got != tt.expected {
				t.Errorf("normalizeEmail(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normal email",
			input:    "user@example.com",
			expected: "example.com",
		},
		{
			name:     "subdomain",
			input:    "user@mail.example.com",
			expected: "mail.example.com",
		},
		{
			name:     "no domain",
			input:    "user@",
			expected: "",
		},
		{
			name:     "no at sign",
			input:    "invalid",
			expected: "",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "multiple at signs",
			input:    "user@domain@example.com",
			expected: "domain@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDomain(tt.input)
			if got != tt.expected {
				t.Errorf("extractDomain(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestGuess(t *testing.T) {
	tests := []struct {
		name           string
		addresses      []Address
		domain         string
		expectedGuess  string
		shouldHaveMore bool // if we expect more than one guess
	}{
		{
			name: "verified address in target domain",
			addresses: []Address{
				{Email: "user@example.com", Name: "John Doe", Verified: true, Methods: []string{"public_api"}},
				{Email: "user@other.com", Name: "John Doe", Verified: false, Methods: []string{"commits"}},
			},
			domain:         "example.com",
			expectedGuess:  "user@example.com",
			shouldHaveMore: false,
		},
		{
			name: "SAML identity in target domain",
			addresses: []Address{
				{Email: "user@other.com", Name: "John Doe", Verified: false, Methods: []string{"commits"}},
				{Email: "john@example.com", Name: "John Doe", Verified: false, Methods: []string{"saml_identity"}},
			},
			domain:         "example.com",
			expectedGuess:  "john@example.com",
			shouldHaveMore: false,
		},
		{
			name: "intelligent guess from other domain prefix",
			addresses: []Address{
				{Email: "john.doe@other.com", Name: "John Doe", Verified: false, Methods: []string{"commits"}},
			},
			domain:         "example.com",
			expectedGuess:  "john.doe@example.com",
			shouldHaveMore: true, // should also have name-based guesses
		},
		{
			name: "name-based guess only",
			addresses: []Address{
				{Email: "different@other.com", Name: "Thomas Stromberg", Verified: false, Methods: []string{"commits"}},
			},
			domain:         "example.com",
			expectedGuess:  "different@example.com", // prefix extraction comes first
			shouldHaveMore: true,                    // should also have name-based guesses
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guesses := simulateGuessLogic(tt.addresses, tt.domain)

			// Verify results
			if len(guesses) == 0 {
				t.Error("Expected at least one guess, got none")
				return
			}

			if guesses[0] != tt.expectedGuess {
				t.Errorf("Expected first guess to be %s, got %s", tt.expectedGuess, guesses[0])
			}

			if tt.shouldHaveMore && len(guesses) == 1 {
				t.Error("Expected more than one guess, got only one")
			}

			if !tt.shouldHaveMore && len(guesses) > 1 {
				t.Errorf("Expected only one guess, got %d: %v", len(guesses), guesses)
			}
		})
	}
}

// simulateGuessLogic simulates the guess logic for testing purposes
func simulateGuessLogic(addresses []Address, domain string) []string {
	targetDomain := strings.ToLower(domain)
	var guesses []string
	seen := make(map[string]bool)

	// Test precedence rules
	if guess := checkVerifiedDomainEmail(addresses, targetDomain); guess != "" {
		return []string{guess}
	}
	if guess := checkSAMLIdentity(addresses, targetDomain); guess != "" {
		return []string{guess}
	}

	// Generate intelligent guesses
	guesses = addPrefixGuesses(addresses, targetDomain, guesses, seen)
	guesses = addNameBasedGuesses(addresses, targetDomain, guesses, seen)

	return guesses
}

func checkVerifiedDomainEmail(addresses []Address, targetDomain string) string {
	for _, addr := range addresses {
		normalizedEmail := normalizeEmail(addr.Email)
		if addr.Verified && strings.EqualFold(extractDomain(normalizedEmail), targetDomain) {
			return normalizedEmail
		}
	}
	return ""
}

func checkSAMLIdentity(addresses []Address, targetDomain string) string {
	for _, addr := range addresses {
		normalizedEmail := normalizeEmail(addr.Email)
		if containsMethod(addr.Methods, "saml_identity") &&
			strings.EqualFold(extractDomain(normalizedEmail), targetDomain) {
			return normalizedEmail
		}
	}
	return ""
}

func addPrefixGuesses(addresses []Address, targetDomain string, guesses []string, seen map[string]bool) []string {
	for _, addr := range addresses {
		normalizedEmail := normalizeEmail(addr.Email)
		if !strings.EqualFold(extractDomain(normalizedEmail), targetDomain) {
			// Extract prefix (local part before @)
			parts := strings.SplitN(normalizedEmail, "@", 2)
			if len(parts) == 2 && parts[0] != "" {
				guess := parts[0] + "@" + targetDomain
				if !seen[guess] {
					guesses = append(guesses, guess)
					seen[guess] = true
				}
			}
		}
	}
	return guesses
}

func addNameBasedGuesses(addresses []Address, targetDomain string, guesses []string, seen map[string]bool) []string {
	for _, addr := range addresses {
		if addr.Name != "" {
			nameGuesses := generateNameBasedGuesses(addr.Name, targetDomain)
			for _, guess := range nameGuesses {
				if !seen[guess.Email] {
					guesses = append(guesses, guess.Email)
					seen[guess.Email] = true
				}
			}
		}
	}
	return guesses
}

func TestGenerateNameBasedGuesses(t *testing.T) {
	tests := []struct {
		name     string
		realName string
		domain   string
		expected []string
	}{
		{
			name:     "normal two-part name",
			realName: "Thomas Stromberg",
			domain:   "example.com",
			expected: []string{"thomas.stromberg@example.com", "thomas@example.com", "tstromberg@example.com", "stromberg@example.com", "ts@example.com", "thomasstromberg@example.com"},
		},
		{
			name:     "three-part name",
			realName: "John Doe Smith",
			domain:   "example.com",
			expected: []string{"john.smith@example.com", "john@example.com", "jsmith@example.com", "smith@example.com", "js@example.com", "johnsmith@example.com"},
		},
		{
			name:     "single letter first name",
			realName: "T Stromberg",
			domain:   "example.com",
			expected: nil, // Single-letter names are now filtered out for quality
		},
		{
			name:     "single name",
			realName: "Madonna",
			domain:   "example.com",
			expected: []string{"madonna@example.com"}, // Single names now generate guesses
		},
		{
			name:     "empty name",
			realName: "",
			domain:   "example.com",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateNameBasedGuesses(tt.realName, tt.domain)
			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d guesses, got %d: %v", len(tt.expected), len(result), result)
				return
			}
			for i, expected := range tt.expected {
				if result[i].Email != expected {
					t.Errorf("Expected guess %d to be %s, got %s", i, expected, result[i].Email)
				}
			}
		})
	}
}

func TestExtractPrefix(t *testing.T) {
	// Local helper function for testing the inlined extract prefix logic
	extractPrefix := func(email string) string {
		parts := strings.SplitN(email, "@", 2)
		if len(parts) != 2 {
			return ""
		}
		return parts[0]
	}

	tests := []struct {
		name     string
		email    string
		expected string
	}{
		{
			name:     "normal email",
			email:    "user@example.com",
			expected: "user",
		},
		{
			name:     "complex prefix",
			email:    "first.last+tag@example.com",
			expected: "first.last+tag",
		},
		{
			name:     "invalid email",
			email:    "invalid",
			expected: "",
		},
		{
			name:     "empty email",
			email:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractPrefix(tt.email)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestContainsMethod(t *testing.T) {
	methods := []string{"commits", "public_api", "saml_identity"}

	if !containsMethod(methods, "commits") {
		t.Error("Expected to find 'commits' method")
	}

	if containsMethod(methods, "nonexistent") {
		t.Error("Expected not to find 'nonexistent' method")
	}
}

func TestFilterAndNormalizeGitHubNoreply(t *testing.T) {
	// Test that GitHub noreply emails are preserved (not normalized)
	result := &Result{
		Username: "testuser",
		Addresses: []Address{
			{Email: "147884153+golanglemonade@users.noreply.github.com", Methods: []string{"commits"}, Verified: false},
			{Email: "normal+tag@example.com", Methods: []string{"api"}, Verified: false},
			{Email: "", Name: "Empty Email User", Methods: []string{"api"}, Verified: false}, // Should be filtered out
		},
	}

	filtered := result.FilterAndNormalize(FilterOptions{})

	// Should have 2 addresses (GitHub noreply + normalized regular email, empty email filtered out)
	if len(filtered.Addresses) != 2 {
		t.Errorf("Expected 2 addresses, got %d", len(filtered.Addresses))
	}

	// Find the GitHub noreply address
	var githubAddr *Address
	var normalAddr *Address
	for i, addr := range filtered.Addresses {
		if strings.Contains(addr.Email, "users.noreply.github.com") {
			githubAddr = &filtered.Addresses[i]
		} else {
			normalAddr = &filtered.Addresses[i]
		}
	}

	if githubAddr == nil {
		t.Fatal("Expected to find GitHub noreply address")
	}
	if normalAddr == nil {
		t.Fatal("Expected to find normal address")
	}

	// GitHub noreply address should preserve the +username part
	if githubAddr.Email != "147884153+golanglemonade@users.noreply.github.com" {
		t.Errorf("Expected GitHub noreply to be preserved, got %s", githubAddr.Email)
	}

	// Normal address should be normalized (remove +tag)
	if normalAddr.Email != "normal@example.com" {
		t.Errorf("Expected normal email to be normalized to normal@example.com, got %s", normalAddr.Email)
	}
}

func TestSkipGitHubNoreplyInPrefixGuessing(t *testing.T) {
	// Test that GitHub noreply addresses (with +username) are skipped when generating prefix-based guesses
	addresses := []Address{
		{Email: "147884153+golanglemonade@users.noreply.github.com", Name: "Sarah Funkhouser", Methods: []string{"commits"}},
		{Email: "real.user@other.com", Name: "Real User", Methods: []string{"commits"}},
	}

	lookup := New("fake-token")
	guesses := lookup.generateIntelligentGuesses(context.Background(), "golanglemonade", addresses, "example.com")

	// Should not include 147884153@example.com (from GitHub noreply ID)
	// Should include real.user@example.com (from other domain)
	var hasGitHubPrefix, hasRealPrefix bool
	for _, guess := range guesses {
		if guess.Email == "147884153@example.com" {
			hasGitHubPrefix = true
			t.Logf("Found unwanted GitHub prefix guess: %s (pattern: %s, source: %s)",
				guess.Email, guess.Pattern, guess.Sources["source_email"])
		}
		if guess.Email == "real.user@example.com" {
			hasRealPrefix = true
		}
	}

	if hasGitHubPrefix {
		t.Error("Should not generate prefix guess from GitHub noreply address - the numeric ID is not a useful email prefix")
	}
	if !hasRealPrefix {
		t.Error("Should generate prefix guess from real email address")
	}

	// Additional verification: check that we do get name-based guesses from the GitHub noreply address
	var hasNameGuess bool
	for _, guess := range guesses {
		if strings.Contains(guess.Email, "sarah") || strings.Contains(guess.Email, "funkhouser") {
			hasNameGuess = true
			break
		}
	}
	if !hasNameGuess {
		t.Error("Should still generate name-based guesses from GitHub noreply address name field")
	}
}

func TestSkipGenericPrefixesInGuessing(t *testing.T) {
	// Mock addresses that include generic prefixes that should be filtered out
	addresses := []Address{
		{Email: "mail@example.com"},       // Should be skipped - generic
		{Email: "info@company.org"},       // Should be skipped - generic
		{Email: "admin@business.net"},     // Should be skipped - generic
		{Email: "support@service.io"},     // Should be skipped - generic
		{Email: "contact@website.dev"},    // Should be skipped - generic
		{Email: "john.doe@personal.com"},  // Should be used - not generic
		{Email: "realuser@somewhere.org"}, // Should be used - not generic
	}

	lookup := New("fake-token")
	guesses := lookup.generateIntelligentGuesses(context.Background(), "testuser", addresses, "target.com")

	// Track which guesses we found
	foundGuesses := make(map[string]bool)
	for _, guess := range guesses {
		if guess.Pattern == "same_prefix_as_other_domain" {
			foundGuesses[guess.Email] = true
		}
	}

	// Should NOT find guesses from generic prefixes
	genericShouldNotExist := []string{
		"mail@target.com", "info@target.com", "admin@target.com",
		"support@target.com", "contact@target.com",
	}
	for _, shouldNotExist := range genericShouldNotExist {
		if foundGuesses[shouldNotExist] {
			t.Errorf("Generic prefix should not generate guess: %s", shouldNotExist)
		}
	}

	// Should find guesses from non-generic prefixes
	shouldExist := []string{
		"john.doe@target.com", "realuser@target.com",
	}
	for _, shouldExist := range shouldExist {
		if !foundGuesses[shouldExist] {
			t.Errorf("Non-generic prefix should generate guess: %s", shouldExist)
		}
	}
}

func TestParseUsernameForNames(t *testing.T) {
	tests := []struct {
		name       string
		username   string
		domain     string
		knownNames []string
		expected   []string
	}{
		{
			name:       "profile-based parsing with known name",
			username:   "amyoxley",
			domain:     "example.com",
			knownNames: []string{"amy"},
			expected:   []string{"amy.oxley@example.com"},
		},
		{
			name:       "profile-based parsing with full known name",
			username:   "johndoe123",
			domain:     "example.com",
			knownNames: []string{"John Doe"},
			expected:   []string{"john.doe123@example.com"},
		},
		{
			name:       "fallback to common names when no profile match",
			username:   "mikesmith",
			domain:     "example.com",
			knownNames: []string{"Robert"},
			expected:   []string{"mike.smith@example.com"},
		},
		{
			name:       "common name parsing without profile",
			username:   "sarahjones",
			domain:     "example.com",
			knownNames: []string{},
			expected:   []string{"sarah.jones@example.com"},
		},
		{
			name:       "username too short - no guesses",
			username:   "amy",
			domain:     "example.com",
			knownNames: []string{"amy"},
			expected:   []string{},
		},
		{
			name:       "no valid last name part",
			username:   "amy12",
			domain:     "example.com",
			knownNames: []string{"amy"},
			expected:   []string{},
		},
		{
			name:       "no common name match",
			username:   "xyz123abc",
			domain:     "example.com",
			knownNames: []string{"Bob"},
			expected:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseUsernameForNames(tt.username, tt.domain, tt.knownNames...)
			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d guesses, got %d: %v", len(tt.expected), len(result), result)
				return
			}
			for i, expected := range tt.expected {
				if result[i].Email != expected {
					t.Errorf("Expected guess %d to be %s, got %s", i, expected, result[i].Email)
				}
			}
		})
	}
}

func TestParseUsernameForNamesConfidenceLevels(t *testing.T) {
	// Profile-based parsing should have higher confidence than generic parsing
	profileResult := parseUsernameForNames("amyoxley", "example.com", "amy")
	genericResult := parseUsernameForNames("amyoxley", "example.com")

	if len(profileResult) == 0 || len(genericResult) == 0 {
		t.Fatal("Expected results from both parsing methods")
	}

	if profileResult[0].Confidence <= genericResult[0].Confidence {
		t.Errorf("Profile-based parsing should have higher confidence: profile=%d, generic=%d",
			profileResult[0].Confidence, genericResult[0].Confidence)
	}

	if profileResult[0].Pattern != "profile_parsed_username" {
		t.Errorf("Expected profile-based pattern, got %s", profileResult[0].Pattern)
	}

	if genericResult[0].Pattern != "parsed_username" {
		t.Errorf("Expected generic parsed pattern, got %s", genericResult[0].Pattern)
	}
}

func TestRealWorldGitHubNoreplyCase(t *testing.T) {
	// Test the exact case from matoszz user to replicate the real-world issue
	addresses := []Address{
		{Email: "42154938+matoszz@users.noreply.github.com", Name: "Matt Anderson", Methods: []string{"commits"}, Verified: false},
		// Simulate empty email from public API with just name data
		{Email: "", Name: "Matt Anderson", Methods: []string{"public_api"}, Verified: false},
	}

	lookup := New("fake-token")
	guesses := lookup.generateIntelligentGuesses(context.Background(), "matoszz", addresses, "theopenlane.io")

	// Debug: log all guesses
	for i, guess := range guesses {
		t.Logf("Guess %d: %s (pattern: %s, source: %s)", i, guess.Email, guess.Pattern, guess.Sources["source_email"])
	}

	// Check that we don't get 42154938@theopenlane.io
	var hasUnwantedGitHubPrefix bool
	for _, guess := range guesses {
		if guess.Email == "42154938@theopenlane.io" {
			hasUnwantedGitHubPrefix = true
			t.Errorf("Found unwanted GitHub noreply prefix: %s (source: %s)",
				guess.Email, guess.Sources["source_email"])
		}
	}

	if hasUnwantedGitHubPrefix {
		t.Fatal("GitHub noreply numeric prefix should not be used for guessing")
	}

	// Verify we still get proper name-based guesses
	var hasNameBasedGuess bool
	for _, guess := range guesses {
		if strings.Contains(guess.Email, "matt") || strings.Contains(guess.Email, "anderson") {
			hasNameBasedGuess = true
			break
		}
	}
	if !hasNameBasedGuess {
		t.Error("Should generate name-based guesses from Matt Anderson")
	}
}

func TestContainsEmail(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		email    string
		expected bool
	}{
		{
			name:     "exact match",
			content:  "Contact me at john@example.com for details",
			email:    "john@example.com",
			expected: true,
		},
		{
			name:     "substring false positive - should not match",
			content:  "Contact me at kjohn@example.com for details",
			email:    "john@example.com",
			expected: false,
		},
		{
			name:     "kimsterv case - klewandowski vs lewandowski",
			content:  "Please reach out to klewandowski@google.com for more info",
			email:    "lewandowski@google.com",
			expected: false,
		},
		{
			name:     "kimsterv case - klewandowski exact match",
			content:  "Please reach out to klewandowski@google.com for more info",
			email:    "klewandowski@google.com",
			expected: true,
		},
		{
			name:     "email at start of content",
			content:  "john@example.com is the contact person",
			email:    "john@example.com",
			expected: true,
		},
		{
			name:     "email at end of content",
			content:  "The contact person is john@example.com",
			email:    "john@example.com",
			expected: true,
		},
		{
			name:     "email with punctuation boundaries",
			content:  "Email: john@example.com, Phone: 555-1234",
			email:    "john@example.com",
			expected: true,
		},
		{
			name:     "case insensitive matching",
			content:  "Contact JOHN@EXAMPLE.COM for details",
			email:    "john@example.com",
			expected: true,
		},
		{
			name:     "no match",
			content:  "Contact jane@example.com for details",
			email:    "john@example.com",
			expected: false,
		},
		{
			name:     "multiple occurrences with one valid",
			content:  "Don't use kjohn@example.com, use john@example.com instead",
			email:    "john@example.com",
			expected: true,
		},
		{
			name:     "email prefix with alphanumeric - should not match",
			content:  "The account test123john@example.com is invalid",
			email:    "john@example.com",
			expected: false,
		},
		{
			name:     "email suffix with alphanumeric - should not match",
			content:  "The account john@example.com456 is invalid",
			email:    "john@example.com",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsEmail(tt.content, tt.email)
			if result != tt.expected {
				t.Errorf("containsEmail(%q, %q) = %v; want %v", tt.content, tt.email, result, tt.expected)
			}
		})
	}
}

func TestEmailValidationNoSubstringRegression(t *testing.T) {
	// This test specifically covers the kimsterv regression case
	// to ensure we don't accidentally validate lewandowski@google.com
	// when the content only contains klewandowski@google.com

	// Simulate GitHub search results that contain klewandowski@google.com
	testContent := `
	Issue Title: Update team contact information
	Issue Body: Please update the team contacts. 
	
	For technical questions, reach out to klewandowski@google.com
	For administrative questions, contact admin@google.com
	
	Thanks!
	`

	emails := []string{
		"klewandowski@google.com", // Should match - exact match
		"lewandowski@google.com",  // Should NOT match - substring of klewandowski
		"admin@google.com",        // Should match - exact match
		"missing@google.com",      // Should NOT match - not in content
	}

	expectedMatches := map[string]bool{
		"klewandowski@google.com": true,
		"lewandowski@google.com":  false, // This is the regression test
		"admin@google.com":        true,
		"missing@google.com":      false,
	}

	for _, email := range emails {
		result := containsEmail(testContent, email)
		expected := expectedMatches[email]

		if result != expected {
			if email == "lewandowski@google.com" && result == true {
				t.Fatalf("REGRESSION: lewandowski@google.com incorrectly matched when content only has klewandowski@google.com")
			}
			t.Errorf("Email %s: expected %v, got %v", email, expected, result)
		}
	}

	// Additional test with more complex boundaries
	complexContent := "The emails are: alice@test.com, bob.alice@test.com, and alice@test.com.backup"

	// alice@test.com should match the exact occurrences but not the substring in bob.alice@test.com or alice@test.com.backup
	if !containsEmail(complexContent, "alice@test.com") {
		t.Error("Should find exact matches for alice@test.com")
	}

	// Verify it doesn't match partial strings
	if containsEmail("user.alice@test.com only", "alice@test.com") {
		t.Error("Should not match alice@test.com in user.alice@test.com")
	}
}
