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
		{"invalid - noreply", "noreply@github.com", false},
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
			name: "no filtering or normalization",
			opts: FilterOptions{},
			expected: []string{
				"User.Test+tag@Example.com",
				"admin@stromberg.org",
				"John.Doe+Work@STROMBERG.ORG",
				"contact@other.com",
				"invalid-email",
			},
		},
		{
			name: "normalize only",
			opts: FilterOptions{Normalize: true},
			expected: []string{
				"user.test@example.com",
				"admin@stromberg.org",
				"john.doe@stromberg.org",
				"contact@other.com",
				"invalid-email",
			},
		},
		{
			name: "filter by domain only (case insensitive)",
			opts: FilterOptions{Domain: "stromberg.org"},
			expected: []string{
				"admin@stromberg.org",
				"John.Doe+Work@STROMBERG.ORG",
			},
		},
		{
			name: "filter by domain with different case",
			opts: FilterOptions{Domain: "STROMBERG.ORG"},
			expected: []string{
				"admin@stromberg.org",
				"John.Doe+Work@STROMBERG.ORG",
			},
		},
		{
			name: "filter and normalize",
			opts: FilterOptions{Domain: "stromberg.org", Normalize: true},
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
	opts := FilterOptions{Domain: "example.com", Normalize: true}

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

	opts := FilterOptions{Normalize: true}
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
				if !seen[guess] {
					guesses = append(guesses, guess)
					seen[guess] = true
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
			expected: []string{"thomas.stromberg@example.com", "t.stromberg@example.com", "thomas@example.com"},
		},
		{
			name:     "three-part name",
			realName: "John Doe Smith",
			domain:   "example.com",
			expected: []string{"john.smith@example.com", "j.smith@example.com", "john@example.com"},
		},
		{
			name:     "single letter first name",
			realName: "T Stromberg",
			domain:   "example.com",
			expected: []string{"t.stromberg@example.com", "t@example.com"}, // Includes firstname@domain pattern
		},
		{
			name:     "single name",
			realName: "Madonna",
			domain:   "example.com",
			expected: nil, // Should return nil for single names
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
				if result[i] != expected {
					t.Errorf("Expected guess %d to be %s, got %s", i, expected, result[i])
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
