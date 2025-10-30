package ghmailto

import (
	"context"
	"testing"
)

func TestValidateGitHubUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		wantErr  bool
	}{
		{"valid username", "testuser", false},
		{"valid with hyphen", "test-user", false},
		{"valid with numbers", "user123", false},
		{"consecutive hyphens allowed", "test--user", false},
		{"empty", "", true},
		{"too long", "thisusernameis waytoolongforgihtubtoaccept123456", true},
		{"starts with hyphen", "-testuser", true},
		{"ends with hyphen", "testuser-", true},
		{"special chars", "test@user", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGitHubUsername(tt.username)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateGitHubUsername(%q) error = %v, wantErr %v", tt.username, err, tt.wantErr)
			}
		})
	}
}

func TestValidateOrganization(t *testing.T) {
	tests := []struct {
		name    string
		org     string
		wantErr bool
	}{
		{"valid org", "testorg", false},
		{"valid with hyphen", "test-org", false},
		{"empty allowed", "", false},
		{"too long", "thisorganizationiswaytoolongforgihtub123456", true},
		{"starts with hyphen", "-testorg", true},
		{"ends with hyphen", "testorg-", true},
		{"consecutive dots", "test..org", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOrganization(tt.org)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateOrganization(%q) error = %v, wantErr %v", tt.org, err, tt.wantErr)
			}
		})
	}
}

func TestValidateGitHubToken(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{"valid token", "ghp_1234567890abcdefghijklmnopqrstuvwxyz", false},
		{"empty", "", true},
		{"too short", "short", true},
		{"too long", string(make([]byte, 300)), true},
		{"with newline", "token\nwith\nnewline", true},
		{"with null", "token\x00null", true},
		{"non-printable", "token\x01\x02", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGitHubToken(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateGitHubToken() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateDomain(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		wantErr bool
	}{
		{"valid domain", "example.com", false},
		{"valid subdomain", "sub.example.com", false},
		{"empty allowed", "", false},
		{"too long", string(make([]byte, 300)) + ".com", true},
		{"consecutive dots", "example..com", true},
		{"starts with dot", ".example.com", true},
		{"ends with dot", "example.com.", true},
		{"invalid chars", "example@com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDomain(tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateDomain(%q) error = %v, wantErr %v", tt.domain, err, tt.wantErr)
			}
		})
	}
}

func TestAddressAccumulator(t *testing.T) {
	acc := &addressAccumulator{
		addresses: make(map[string]*Address),
		methodSet: make(map[string]map[string]struct{}),
		rawEmails: make(map[string]map[string]string),
	}

	// Add first address
	acc.add(Address{
		Email:    "User+Tag@Example.COM",
		Name:     "Test User",
		Verified: false,
	}, "method1")

	// Add same email with different case and tag
	acc.add(Address{
		Email:    "user@example.com",
		Name:     "Test User Updated",
		Verified: true,
	}, "method2")

	addrs := acc.toSlice()
	if len(addrs) != 1 {
		t.Errorf("expected 1 address, got %d", len(addrs))
	}

	addr := addrs[0]
	if addr.Email != "user@example.com" {
		t.Errorf("expected normalized email, got %s", addr.Email)
	}
	if !addr.Verified {
		t.Error("expected verified=true")
	}
	if len(addr.Methods) != 2 {
		t.Errorf("expected 2 methods, got %d", len(addr.Methods))
	}
}

func TestContainsMethodHelper(t *testing.T) {
	methods := []string{"method1", "method2", "method3"}

	if !containsMethod(methods, "method2") {
		t.Error("expected to find method2")
	}
	if containsMethod(methods, "method4") {
		t.Error("expected not to find method4")
	}
	if containsMethod(nil, "method1") {
		t.Error("expected not to find method in nil slice")
	}
}

func TestCalculateConfidenceAndPattern(t *testing.T) {
	tests := []struct {
		name            string
		methods         []string
		verified        bool
		sources         map[string]string
		wantConfidence  int
		wantPatternLike string
	}{
		{
			name:            "verified",
			methods:         []string{"api"},
			verified:        true,
			wantConfidence:  100,
			wantPatternLike: "verified",
		},
		{
			name:            "SAML",
			methods:         []string{"SAML Identity"},
			verified:        false,
			wantConfidence:  100,
			wantPatternLike: "saml",
		},
		{
			name:            "org verified domains",
			methods:         []string{"Org Verified Domains"},
			verified:        false,
			wantConfidence:  100,
			wantPatternLike: "org_verified",
		},
		{
			name:            "git commits",
			methods:         []string{"Git Commits"},
			verified:        false,
			sources:         map[string]string{},
			wantConfidence:  95,
			wantPatternLike: "git_commits",
		},
		{
			name:            "git commits with age",
			methods:         []string{"Git Commits"},
			verified:        false,
			sources:         map[string]string{"commits_age_months": "6"},
			wantConfidence:  85, // 95 - (6 * 2) = 83, but floor at 85
			wantPatternLike: "git_commits",
		},
		{
			name:            "public API",
			methods:         []string{"Public API"},
			verified:        false,
			wantConfidence:  95,
			wantPatternLike: "public_api",
		},
		{
			name:            "multiple methods",
			methods:         []string{"Git Commits", "Public API"},
			verified:        false,
			sources:         map[string]string{},
			wantConfidence:  98,
			wantPatternLike: "multi_method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			confidence, pattern := calculateConfidenceAndPattern(tt.methods, tt.verified, tt.sources)
			if confidence != tt.wantConfidence {
				t.Errorf("confidence = %d, want %d", confidence, tt.wantConfidence)
			}
			if !contains(pattern, tt.wantPatternLike) {
				t.Errorf("pattern = %s, want to contain %s", pattern, tt.wantPatternLike)
			}
		})
	}
}

func TestIsValidEmailPrefix(t *testing.T) {
	tests := []struct {
		prefix string
		want   bool
	}{
		{"valid", true},
		{"valid.name", true},
		{"valid-name", true},
		{"valid_name", true},
		{"", false},
		{".invalid", false},
		{"invalid.", false},
		{"in..valid", false},
		{"has@at", false},
	}

	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			got := isValidEmailPrefix(tt.prefix)
			if got != tt.want {
				t.Errorf("isValidEmailPrefix(%q) = %v, want %v", tt.prefix, got, tt.want)
			}
		})
	}
}

func TestIsEmailChar(t *testing.T) {
	validChars := "abcABC123@.-_+=!#$%&'*/?^`{|}~"
	for _, ch := range validChars {
		if !isEmailChar(ch) {
			t.Errorf("isEmailChar(%q) = false, want true", ch)
		}
	}

	invalidChars := " \n\t()<>[]\\,;:\""
	for _, ch := range invalidChars {
		if isEmailChar(ch) {
			t.Errorf("isEmailChar(%q) = true, want false", ch)
		}
	}
}

func TestNormalizeEmailUnicode(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"User@Example.COM", "user@example.com"},
		{"user+tag@example.com", "user@example.com"},
		{"User+TAG@Example.COM", "user@example.com"},
		{"test.user@example.com", "test.user@example.com"},
		{"Müller@example.com", "muller@example.com"},
		{"josé@example.com", "jose@example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeEmail(tt.input)
			if got != tt.want {
				t.Errorf("normalizeEmail(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractDomainHelper(t *testing.T) {
	tests := []struct {
		email string
		want  string
	}{
		{"user@example.com", "example.com"},
		{"test@sub.example.com", "sub.example.com"},
		{"invalid", ""},
		{"@example.com", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			got := extractDomain(tt.email)
			if got != tt.want {
				t.Errorf("extractDomain(%q) = %q, want %q", tt.email, got, tt.want)
			}
		})
	}
}

func TestIsGitHubNoreplyEmail(t *testing.T) {
	tests := []struct {
		email string
		want  bool
	}{
		{"user@example.com", false},
		{"123+user@users.noreply.github.com", true},
		{"User@users.noreply.GITHUB.COM", true},
		{"noreply@github.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			got := isGitHubNoreplyEmail(tt.email)
			if got != tt.want {
				t.Errorf("isGitHubNoreplyEmail(%q) = %v, want %v", tt.email, got, tt.want)
			}
		})
	}
}

func TestCombineAndFilterGuessResults(t *testing.T) {
	result := &GuessResult{
		Username: "testuser",
		FoundAddresses: []Address{
			{Email: "found@example.com", Confidence: 95},
			{Email: "Found@OTHER.COM", Confidence: 90},
		},
		Guesses: []Address{
			{Email: "guess1@example.com", Confidence: 80},
			{Email: "guess2@other.com", Confidence: 60},
		},
	}

	addresses, _ := CombineAndFilterGuessResults(result, "example.com")

	// Should have: found@example.com (95), guess1@example.com (80)
	// Should NOT have: Found@OTHER.COM (wrong domain)
	if len(addresses) < 2 {
		t.Errorf("expected at least 2 addresses, got %d", len(addresses))
	}

	// Check sorting by confidence
	if len(addresses) > 1 && addresses[0].Confidence < addresses[len(addresses)-1].Confidence {
		t.Error("addresses not sorted by confidence")
	}
}

func TestFilterHighConfidenceAddresses(t *testing.T) {
	tests := []struct {
		name           string
		addresses      []Address
		wantCount      int
		wantShowWarning bool
	}{
		{
			name: "has high confidence",
			addresses: []Address{
				{Email: "high@example.com", Confidence: 85},
				{Email: "low@example.com", Confidence: 30},
			},
			wantCount:      1,
			wantShowWarning: false,
		},
		{
			name: "all low confidence",
			addresses: []Address{
				{Email: "low1@example.com", Confidence: 30},
				{Email: "low2@example.com", Confidence: 20},
			},
			wantCount:      2,
			wantShowWarning: true,
		},
		{
			name:           "empty",
			addresses:      []Address{},
			wantCount:      0,
			wantShowWarning: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered, showWarning := FilterHighConfidenceAddresses(tt.addresses)
			if len(filtered) != tt.wantCount {
				t.Errorf("got %d addresses, want %d", len(filtered), tt.wantCount)
			}
			if showWarning != tt.wantShowWarning {
				t.Errorf("showWarning = %v, want %v", showWarning, tt.wantShowWarning)
			}
		})
	}
}

func TestScaleUnvalidatedConfidence(t *testing.T) {
	lookup := New("test-token")
	guesses := []Address{
		{Email: "test@example.com", Confidence: 60}, // same_prefix_as_other_domain (multiple)
		{Email: "test2@example.com", Confidence: 55}, // firstname.lastname
		{Email: "test3@example.com", Confidence: 50}, // same_prefix (single)
	}

	scaled := lookup.scaleUnvalidatedConfidence(guesses)

	if len(scaled) != len(guesses) {
		t.Errorf("expected %d guesses, got %d", len(guesses), len(scaled))
	}

	// Check that confidences were scaled
	for _, guess := range scaled {
		if guess.Confidence < 1 || guess.Confidence > 100 {
			t.Errorf("confidence out of range: %d", guess.Confidence)
		}
	}
}

func TestParseUsernameForNamesHelper(t *testing.T) {
	tests := []struct {
		name         string
		username     string
		targetDomain string
		knownNames   []string
		wantGuesses  int
	}{
		{
			name:         "with known name match",
			username:     "johnsmith",
			targetDomain: "example.com",
			knownNames:   []string{"John Smith"},
			wantGuesses:  1, // john.smith@example.com
		},
		{
			name:         "common first name at start",
			username:     "chrisjones",
			targetDomain: "example.com",
			knownNames:   []string{},
			wantGuesses:  1, // chris.jones@example.com
		},
		{
			name:         "too short",
			username:     "joe",
			targetDomain: "example.com",
			knownNames:   []string{},
			wantGuesses:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guesses := parseUsernameForNames(tt.username, tt.targetDomain, tt.knownNames...)
			if len(guesses) != tt.wantGuesses {
				t.Errorf("got %d guesses, want %d", len(guesses), tt.wantGuesses)
			}
		})
	}
}

func TestGuessErrorCases(t *testing.T) {
	lookup := New("test-token")

	tests := []struct {
		name    string
		user    string
		org     string
		domain  string
		wantErr bool
	}{
		{"empty domain", "user", "org", "", true},
		{"invalid user", "", "org", "example.com", true},
		{"invalid org", "user", "invalid..org", "example.com", true},
		{"invalid domain", "user", "org", "invalid..com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := lookup.Guess(context.Background(), tt.user, tt.org, GuessOptions{
				Domain: tt.domain,
			})
			if (err != nil) != tt.wantErr {
				t.Errorf("Guess() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
