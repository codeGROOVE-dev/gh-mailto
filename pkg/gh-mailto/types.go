package ghmailto

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

// Address represents an email address found for a GitHub user.
type Address struct {
	// Email is the email address.
	Email string
	// Name is the associated name (if available) from the discovery method.
	Name string
	// Methods contains the sorted list of discovery methods that found this address.
	Methods []string
	// Verified indicates whether the email address has been verified by GitHub.
	Verified bool
}

// Result contains the email addresses found for a GitHub user.
type Result struct {
	// Username is the GitHub username that was searched.
	Username string
	// Addresses contains all discovered email addresses.
	Addresses []Address
}

// Lookup provides email address discovery for GitHub users within an organization.
// It uses multiple methods to find email addresses including public API data,
// commit history, SAML identities, and organization member information.
type Lookup struct {
	logger *slog.Logger
	token  string
}

// Option configures a Lookup instance.
type Option func(*Lookup)

// WithLogger returns an Option that sets a custom logger for the Lookup instance.
func WithLogger(logger *slog.Logger) Option {
	return func(lu *Lookup) {
		lu.logger = logger
	}
}

// New creates a new Lookup instance with the given GitHub token.
// The token should have appropriate permissions to access organization data.
func New(token string, opts ...Option) *Lookup {
	lu := &Lookup{
		token:  token,
		logger: slog.Default(),
	}
	for _, opt := range opts {
		opt(lu)
	}
	return lu
}

// addressAccumulator helps accumulate unique addresses with their discovery methods.
// It deduplicates addresses by email and tracks all methods that discovered each address.
type addressAccumulator struct {
	addresses map[string]*Address
	methodSet map[string]map[string]struct{} // email -> set of methods
}

// add merges an address into the accumulator.
// If the email already exists:
//   - The verified flag is upgraded to true if any method reports it as verified
//   - The discovery method is added to the set of methods for this address
//   - The name is updated if the new address has a name and the existing one doesn't
func (a *addressAccumulator) add(addr Address) {
	email := addr.Email
	method := addr.Methods[0] // New addresses come with single method

	if existing, ok := a.addresses[email]; ok {
		// Once an address is verified by any method, it stays verified
		if addr.Verified {
			existing.Verified = true
		}
		// Update name if we don't have one or if the new one is more complete
		if existing.Name == "" || (addr.Name != "" && len(addr.Name) > len(existing.Name)) {
			existing.Name = addr.Name
		}
		// Track this discovery method
		if _, exists := a.methodSet[email][method]; !exists {
			a.methodSet[email][method] = struct{}{}
		}
	} else {
		// First time seeing this email
		a.addresses[email] = &Address{
			Email:    email,
			Name:     addr.Name,
			Verified: addr.Verified,
			Methods:  []string{}, // Will be populated from methodSet
		}
		a.methodSet[email] = map[string]struct{}{
			method: {},
		}
	}
}

// toSlice converts the accumulated addresses to a slice with sorted method lists.
func (a *addressAccumulator) toSlice() []Address {
	result := make([]Address, 0, len(a.addresses))
	for email, addr := range a.addresses {
		// Convert method set to sorted slice
		methods := make([]string, 0, len(a.methodSet[email]))
		for method := range a.methodSet[email] {
			methods = append(methods, method)
		}
		sort.Strings(methods)
		addr.Methods = methods
		result = append(result, *addr)
	}
	return result
}

// Lookup performs email address lookup for the given GitHub username within an organization.
func (lu *Lookup) Lookup(ctx context.Context, username, organization string) (*Result, error) {
	lu.logger.Info("looking up email addresses",
		"username", username,
		"organization", organization,
	)

	result := &Result{
		Username: username,
		// Addresses will be nil if no addresses found, which is fine
	}

	// Define lookup methods with names
	type methodInfo struct {
		fn   func(context.Context, string, string) ([]Address, error)
		name string
	}

	methods := []methodInfo{
		{lu.lookupViaPublicAPI, "Public API"},
		{lu.lookupViaCommits, "Git Commits"},
		{lu.lookupViaSAMLIdentity, "SAML Identity"},
		{lu.lookupViaOrgVerifiedDomains, "Org Verified Domains"},
		{lu.lookupViaOrgMembers, "Org Members API"},
	}

	accumulator := &addressAccumulator{
		addresses: make(map[string]*Address),
		methodSet: make(map[string]map[string]struct{}),
	}

	// Execute methods in parallel
	type methodResult struct { //nolint:govet // Local struct, field alignment not critical
		addresses []Address
		name      string
		err       error
	}

	resultChan := make(chan methodResult, len(methods))
	var wg sync.WaitGroup

	for _, method := range methods {
		wg.Add(1)
		go func(m methodInfo) {
			defer wg.Done()
			addresses, err := m.fn(ctx, username, organization)
			resultChan <- methodResult{
				name:      m.name,
				addresses: addresses,
				err:       err,
			}
		}(method)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for result := range resultChan {
		if result.err != nil {
			lu.logger.Warn("lookup method failed",
				"method", result.name,
				"error", result.err,
				"username", username,
				"organization", organization,
			)
			continue
		}
		for _, addr := range result.addresses {
			accumulator.add(addr)
		}
	}

	result.Addresses = accumulator.toSlice()

	lu.logger.Info("lookup completed",
		"username", username,
		"addressesFound", len(result.Addresses),
	)

	return result, nil
}

// FilterOptions contains options for filtering and normalizing email addresses.
type FilterOptions struct {
	// Domain filters results to only include addresses with this domain.
	// If empty, no domain filtering is applied.
	Domain string
	// Normalize determines whether to normalize email addresses by
	// removing +suffix from the user part and converting to lowercase.
	Normalize bool
}

// FilterAndNormalize filters and normalizes the addresses in a Result based on options.
func (r *Result) FilterAndNormalize(opts FilterOptions) *Result {
	if r == nil {
		return nil
	}

	// Use accumulator to handle deduplication after normalization
	accumulator := &addressAccumulator{
		addresses: make(map[string]*Address),
		methodSet: make(map[string]map[string]struct{}),
	}

	for _, addr := range r.Addresses {
		email := addr.Email

		// Normalize email if requested
		if opts.Normalize {
			email = normalizeEmail(email)
		}

		// Filter by domain if specified
		if opts.Domain != "" {
			emailDomain := extractDomain(email)
			if !strings.EqualFold(emailDomain, opts.Domain) {
				continue
			}
		}

		// Create normalized address and add to accumulator for deduplication
		normalizedAddr := Address{
			Email:    email,
			Name:     addr.Name,
			Methods:  addr.Methods,
			Verified: addr.Verified,
		}
		accumulator.add(normalizedAddr)
	}

	return &Result{
		Username:  r.Username,
		Addresses: accumulator.toSlice(),
	}
}

// normalizeEmail normalizes an email address by removing +suffix and making it lowercase.
func normalizeEmail(email string) string {
	// Convert to lowercase
	email = strings.ToLower(email)

	// Split on @ to separate user and domain parts
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return email // Invalid email, return as-is
	}

	user := parts[0]
	domain := parts[1]

	// Remove +suffix from user part
	if plusIndex := strings.Index(user, "+"); plusIndex >= 0 {
		user = user[:plusIndex]
	}

	return user + "@" + domain
}

// extractDomain extracts the domain part from an email address.
func extractDomain(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

// GuessOptions contains options for email address guessing.
type GuessOptions struct {
	// Domain is the target domain to guess email addresses for (required).
	Domain string
}

// GuessResult contains the result of email address guessing.
type GuessResult struct {
	// Username is the GitHub username that was searched.
	Username string
	// Guesses contains email address guesses in order of confidence.
	Guesses []string
	// FoundAddresses contains the addresses that were found during lookup.
	FoundAddresses []Address
}

// Guess provides intelligent email address guessing for a GitHub user within a specific domain.
// It first performs a lookup to find existing addresses, then applies precedence rules to find
// the most likely email address for the given domain.
func (lu *Lookup) Guess(ctx context.Context, username, organization string, opts GuessOptions) (*GuessResult, error) {
	if opts.Domain == "" {
		return nil, errors.New("domain is required for guessing")
	}

	lu.logger.Info("guessing email address",
		"username", username,
		"organization", organization,
		"domain", opts.Domain,
	)

	// First, perform a regular lookup to get all available addresses
	result, err := lu.Lookup(ctx, username, organization)
	if err != nil {
		return nil, fmt.Errorf("lookup failed: %w", err)
	}

	guessResult := &GuessResult{
		Username:       username,
		Guesses:        []string{},
		FoundAddresses: result.Addresses,
	}

	// Apply precedence rules to find addresses in the target domain
	targetDomain := strings.ToLower(opts.Domain)

	// Normalize all addresses for comparison
	normalizedAddresses := make([]Address, len(result.Addresses))
	for i, addr := range result.Addresses {
		normalizedAddresses[i] = Address{
			Email:    normalizeEmail(addr.Email),
			Name:     addr.Name,
			Methods:  addr.Methods,
			Verified: addr.Verified,
		}
	}

	// Rule 1: Verified domain email (any method that provides verification)
	for _, addr := range normalizedAddresses {
		if addr.Verified && strings.EqualFold(extractDomain(addr.Email), targetDomain) {
			guessResult.Guesses = append(guessResult.Guesses, addr.Email)
			return guessResult, nil
		}
	}

	// Rule 2: SAML identity within domain
	for _, addr := range normalizedAddresses {
		if containsMethod(addr.Methods, methodSAMLIdentity) &&
			strings.EqualFold(extractDomain(addr.Email), targetDomain) {
			guessResult.Guesses = append(guessResult.Guesses, addr.Email)
			return guessResult, nil
		}
	}

	// Rule 3: Organization member email within domain
	for _, addr := range normalizedAddresses {
		if containsMethod(addr.Methods, methodOrgMembers) &&
			strings.EqualFold(extractDomain(addr.Email), targetDomain) {
			guessResult.Guesses = append(guessResult.Guesses, addr.Email)
			return guessResult, nil
		}
	}

	// Rule 4: Public API email within domain
	for _, addr := range normalizedAddresses {
		if containsMethod(addr.Methods, methodPublicAPI) &&
			strings.EqualFold(extractDomain(addr.Email), targetDomain) {
			guessResult.Guesses = append(guessResult.Guesses, addr.Email)
			return guessResult, nil
		}
	}

	// Rule 5: Commit email within domain
	for _, addr := range normalizedAddresses {
		if containsMethod(addr.Methods, methodCommits) &&
			strings.EqualFold(extractDomain(addr.Email), targetDomain) {
			guessResult.Guesses = append(guessResult.Guesses, addr.Email)
			return guessResult, nil
		}
	}

	// If no direct match found, generate intelligent guesses
	guesses := lu.generateIntelligentGuesses(ctx, username, normalizedAddresses, targetDomain)
	guessResult.Guesses = guesses

	return guessResult, nil
}

// generateIntelligentGuesses creates email guesses based on existing patterns and user info.
func (*Lookup) generateIntelligentGuesses(_ context.Context, _ string, addresses []Address, targetDomain string) []string {
	var guesses []string
	seen := make(map[string]bool)

	// Strategy 1: Use unique normalized prefixes from other domains
	for _, addr := range addresses {
		email := addr.Email
		if !strings.EqualFold(extractDomain(email), targetDomain) {
			// Extract prefix (local part before @)
			parts := strings.SplitN(email, "@", 2)
			if len(parts) == 2 && parts[0] != "" {
				guess := parts[0] + "@" + targetDomain
				if !seen[guess] {
					guesses = append(guesses, guess)
					seen[guess] = true
				}
			}
		}
	}

	// Strategy 2 & 3: Use names from addresses (populated by lookup methods)
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

// generateNameBasedGuesses creates email guesses from a real name.
func generateNameBasedGuesses(realName, domain string) []string {
	if realName == "" {
		return nil
	}

	// Normalize Unicode characters and clean the name
	normalizedName := normalizeUnicode(realName)
	parts := strings.Fields(normalizedName)
	if len(parts) < 2 {
		return nil
	}

	var guesses []string
	firstName := parts[0]
	lastName := parts[len(parts)-1] // Use last part as surname

	// firstname.lastname@domain
	guess1 := firstName + "." + lastName + "@" + domain
	guesses = append(guesses, guess1)

	// firstletter.lastname@domain (only if different from above)
	if len(firstName) > 1 {
		guess2 := string(firstName[0]) + "." + lastName + "@" + domain
		guesses = append(guesses, guess2)
	}

	// firstname@domain (lower precedence)
	guess3 := firstName + "@" + domain
	guesses = append(guesses, guess3)

	return guesses
}

// containsMethod checks if a method exists in the methods slice.
func containsMethod(methods []string, method string) bool {
	for _, m := range methods {
		if m == method {
			return true
		}
	}
	return false
}

// normalizeUnicode converts Unicode characters to their ASCII equivalents for email addresses.
// Examples: Ö → O, é → e, ñ → n, ł → l, ø → o, etc.
func normalizeUnicode(input string) string {
	// Fast path: if string is already ASCII-lowercase, return as-is
	if isASCIILowercase(input) {
		return input
	}

	// Handle multi-character replacements first
	s := strings.ReplaceAll(input, "ß", "ss")
	s = strings.ReplaceAll(s, "þ", "th")
	s = strings.ReplaceAll(s, "Þ", "th")
	s = strings.ReplaceAll(s, "æ", "ae")
	s = strings.ReplaceAll(s, "Æ", "ae")
	s = strings.ReplaceAll(s, "œ", "oe")
	s = strings.ReplaceAll(s, "Œ", "oe")

	// Create a transformer that:
	// 1. Normalizes to NFD (decomposed form) - separates base chars from combining diacriticals
	// 2. Removes non-ASCII characters (diacritical marks)
	// 3. Maps special characters to ASCII equivalents
	// 4. Converts to lowercase for consistency
	t := transform.Chain(
		norm.NFD,                           // Normalize to decomposed form
		runes.Remove(runes.In(unicode.Mn)), // Remove nonspacing marks (diacriticals)
		runes.Map(func(r rune) rune {
			// Handle characters that don't decompose but need ASCII mapping
			switch r {
			case 'ł', 'Ł':
				return 'l'
			case 'ø', 'Ø':
				return 'o'
			case 'đ', 'Đ':
				return 'd'
			case 'ð', 'Ð':
				return 'd'
			default:
				return unicode.ToLower(r)
			}
		}),
	)

	result, _, err := transform.String(t, s)
	if err != nil {
		// If transformation fails, return the input string as fallback
		return s
	}
	return result
}

// isASCIILowercase checks if string contains only ASCII lowercase letters and spaces.
func isASCIILowercase(input string) bool {
	for _, r := range input {
		if r > 127 || (r < 'a' || r > 'z') && r != ' ' {
			return false
		}
	}
	return true
}
