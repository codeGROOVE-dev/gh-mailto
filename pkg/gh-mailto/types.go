package ghmailto

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

// Address represents an email address found for a GitHub user.
type Address struct {
	// Email is the normalized email address.
	Email string
	// Name is the associated name (if available) from the discovery method.
	Name string
	// Pattern describes how this address was discovered or guessed (for synthetic guesses).
	Pattern string
	// Methods contains the sorted list of discovery methods that found this address.
	Methods []string
	// Sources maps discovery method names to the raw email addresses they found.
	// For synthetic guesses, this will be empty.
	Sources map[string]string
	// Confidence is the confidence score (0-100) based on discovery methods.
	Confidence int
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
	logger             *slog.Logger
	token              string
	commitMessages     []string        // Recent commit messages for email validation
	recentCommitEmails map[string]bool // Recent commit author/committer emails for validation
	currentUsername    string          // Current GitHub username being looked up
	currentUserNames   []string        // Known names for the current user (for validation)
}

// Option configures a Lookup instance.
type Option func(*Lookup)

// WithLogger returns an Option that sets a custom logger for the Lookup instance.
func WithLogger(logger *slog.Logger) Option {
	return func(lu *Lookup) {
		lu.logger = logger
	}
}

// GitHub username validation regex - GitHub usernames can only contain alphanumeric characters and single hyphens.
// Cannot start or end with hyphen, cannot have consecutive hyphens, max 39 characters.
var githubUsernameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$`)

// Confidence levels for different validation techniques.
const (
	ConfidenceValidatedOrg = 100 // Validated org address (official verification)
	ConfidenceSAML         = 99  // SAML identity (enterprise auth)
	ConfidenceCommits      = 95  // Git commits (direct authorship)
	ConfidencePRs          = 90  // Pull requests (authored content)
	ConfidenceIssues       = 85  // Issues (authored content)
	ConfidenceComments     = 80  // Comments (user participation)
)

// validateGitHubUsername validates a GitHub username for security.
func validateGitHubUsername(username string) error {
	if username == "" {
		return errors.New("username cannot be empty")
	}
	if len(username) > 39 {
		return errors.New("username too long (max 39 characters)")
	}

	if !githubUsernameRegex.MatchString(username) {
		return errors.New("username contains invalid characters")
	}

	// Additional security checks
	if strings.Contains(username, "..") {
		return errors.New("username cannot contain consecutive dots")
	}

	return nil
}

// validateOrganization validates a GitHub organization name for security.
func validateOrganization(organization string) error {
	// Organization can be empty (for web interface)
	if organization == "" {
		return nil
	}
	if len(organization) > 39 {
		return errors.New("organization name too long (max 39 characters)")
	}

	if !githubUsernameRegex.MatchString(organization) {
		return errors.New("organization name contains invalid characters")
	}

	// Additional security checks
	if strings.Contains(organization, "..") {
		return errors.New("organization name cannot contain consecutive dots")
	}

	return nil
}

// validateGitHubToken validates a GitHub token format for security.
func validateGitHubToken(token string) error {
	if token == "" {
		return errors.New("token cannot be empty")
	}

	// GitHub tokens should be reasonable length
	if len(token) < 10 || len(token) > 255 {
		return errors.New("token has invalid length")
	}

	// GitHub tokens should not contain control characters
	if strings.ContainsAny(token, "\r\n\t\x00") {
		return errors.New("token contains invalid characters")
	}

	// GitHub tokens should be printable ASCII
	for _, r := range token {
		if r < 32 || r > 126 {
			return errors.New("token contains non-printable characters")
		}
	}

	return nil
}

// New creates a new Lookup instance with the given GitHub token.
// The token should have appropriate permissions to access organization data.
func New(token string, opts ...Option) *Lookup {
	// Validate token before storing it
	if err := validateGitHubToken(token); err != nil {
		// Use a secure logger that won't expose the token
		slog.Error("invalid GitHub token provided", "error", err)
		// Return a non-functional lookup with empty token to prevent crashes
		return &Lookup{
			token:  "",
			logger: slog.Default(),
		}
	}

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
// It deduplicates addresses by normalized email and tracks all methods that discovered each address.
type addressAccumulator struct {
	addresses map[string]*Address            // normalized email -> Address
	methodSet map[string]map[string]struct{} // normalized email -> set of methods
	rawEmails map[string]map[string]string   // normalized email -> method -> raw email
}

// add merges an address into the accumulator with the specified method name.
// It normalizes the email and tracks both the normalized and raw versions.
func (a *addressAccumulator) add(addr Address, methodName string) {
	rawEmail := addr.Email
	normalizedEmail := normalizeEmail(rawEmail)

	if existing, ok := a.addresses[normalizedEmail]; ok {
		// Once an address is verified by any method, it stays verified
		if addr.Verified {
			existing.Verified = true
		}
		// Update name if we don't have one or if the new one is more complete
		if existing.Name == "" || (addr.Name != "" && len(addr.Name) > len(existing.Name)) {
			existing.Name = addr.Name
		}
		// Track this discovery method
		if _, exists := a.methodSet[normalizedEmail][methodName]; !exists {
			a.methodSet[normalizedEmail][methodName] = struct{}{}
		}
		// Track raw email for this method and preserve original Sources data
		if a.rawEmails[normalizedEmail] == nil {
			a.rawEmails[normalizedEmail] = make(map[string]string)
		}
		a.rawEmails[normalizedEmail][methodName] = rawEmail
		// Preserve original Sources data (like age data for commits)
		for key, value := range addr.Sources {
			a.rawEmails[normalizedEmail][key] = value
		}
	} else {
		// First time seeing this normalized email
		a.addresses[normalizedEmail] = &Address{
			Email:    normalizedEmail,
			Name:     addr.Name,
			Verified: addr.Verified,
			Methods:  []string{}, // Will be populated from methodSet
			Sources:  nil,        // Will be populated from rawEmails
		}
		a.methodSet[normalizedEmail] = map[string]struct{}{
			methodName: {},
		}
		a.rawEmails[normalizedEmail] = map[string]string{
			methodName: rawEmail,
		}
		// Preserve original Sources data (like age data for commits)
		for key, value := range addr.Sources {
			a.rawEmails[normalizedEmail][key] = value
		}
	}
}

// addWithMethods merges an address that already has multiple methods and sources.
func (a *addressAccumulator) addWithMethods(addr Address) {
	// addr.Email is already normalized, and Sources contains the raw emails
	normalizedEmail := addr.Email

	if existing, ok := a.addresses[normalizedEmail]; ok {
		// Once an address is verified by any method, it stays verified
		if addr.Verified {
			existing.Verified = true
		}
		// Update name if we don't have one or if the new one is more complete
		if existing.Name == "" || (addr.Name != "" && len(addr.Name) > len(existing.Name)) {
			existing.Name = addr.Name
		}
		// Track all discovery methods from the address
		for _, method := range addr.Methods {
			if _, exists := a.methodSet[normalizedEmail][method]; !exists {
				a.methodSet[normalizedEmail][method] = struct{}{}
			}
		}
		// Track raw emails from sources
		if a.rawEmails[normalizedEmail] == nil {
			a.rawEmails[normalizedEmail] = make(map[string]string)
		}
		for method, rawEmail := range addr.Sources {
			a.rawEmails[normalizedEmail][method] = rawEmail
		}
	} else {
		// First time seeing this normalized email
		a.addresses[normalizedEmail] = &Address{
			Email:    normalizedEmail,
			Name:     addr.Name,
			Verified: addr.Verified,
			Methods:  []string{}, // Will be populated from methodSet
			Sources:  nil,        // Will be populated from rawEmails
		}
		a.methodSet[normalizedEmail] = make(map[string]struct{})
		for _, method := range addr.Methods {
			a.methodSet[normalizedEmail][method] = struct{}{}
		}
		a.rawEmails[normalizedEmail] = make(map[string]string)
		for method, rawEmail := range addr.Sources {
			a.rawEmails[normalizedEmail][method] = rawEmail
		}
	}
}

// toSlice converts the accumulated addresses to a slice with sorted method lists and confidence scores.
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

		// Populate Sources from rawEmails BEFORE confidence calculation
		if len(a.rawEmails[email]) > 0 {
			addr.Sources = make(map[string]string)
			for method, rawEmail := range a.rawEmails[email] {
				addr.Sources[method] = rawEmail
			}
		}

		// Calculate confidence with populated Sources
		addr.Confidence, addr.Pattern = calculateConfidenceAndPattern(methods, addr.Verified, addr.Sources)

		result = append(result, *addr)
	}

	// Sort addresses by decreasing confidence, then by email for consistency
	sort.Slice(result, func(i, j int) bool {
		if result[i].Confidence == result[j].Confidence {
			return result[i].Email < result[j].Email
		}
		return result[i].Confidence > result[j].Confidence
	})

	return result
}

// Lookup performs email address lookup for the given GitHub username within an organization.
func (lu *Lookup) Lookup(ctx context.Context, username, organization string) (*Result, error) {
	// Validate inputs for security
	if err := validateGitHubUsername(username); err != nil {
		return nil, fmt.Errorf("invalid username: %w", err)
	}

	if err := validateOrganization(organization); err != nil {
		return nil, fmt.Errorf("invalid organization: %w", err)
	}

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

	// Build list of methods to try based on whether we have an organization
	methods := []methodInfo{
		{lu.lookupViaPublicAPI, "Public API"},
		{lu.lookupViaCommits, "Git Commits"},
	}

	// Only add org-specific methods if we have an organization
	if organization != "" {
		methods = append(methods,
			methodInfo{lu.lookupViaSAMLIdentity, "SAML Identity"},
			methodInfo{lu.lookupViaOrgVerifiedDomains, "Org Verified Domains"},
			methodInfo{lu.lookupViaOrgMembers, "Org Members API"},
		)
	}

	accumulator := &addressAccumulator{
		addresses: make(map[string]*Address),
		methodSet: make(map[string]map[string]struct{}),
		rawEmails: make(map[string]map[string]string),
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
			accumulator.add(addr, result.name)
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
}

// FilterAndNormalize filters and normalizes the addresses in a Result based on options.
// All emails are normalized and raw emails are preserved in Sources.
func (r *Result) FilterAndNormalize(opts FilterOptions) *Result {
	if r == nil {
		return nil
	}

	// Use accumulator to handle deduplication and normalization
	accumulator := &addressAccumulator{
		addresses: make(map[string]*Address),
		methodSet: make(map[string]map[string]struct{}),
		rawEmails: make(map[string]map[string]string),
	}

	for _, addr := range r.Addresses {
		// Skip addresses with empty emails
		if addr.Email == "" {
			continue
		}

		// Determine whether to normalize this email
		var processedEmail string
		if isGitHubNoreplyEmail(addr.Email) {
			// Preserve GitHub noreply addresses as-is (don't normalize)
			processedEmail = strings.ToLower(addr.Email)
		} else {
			// Apply normal normalization
			processedEmail = normalizeEmail(addr.Email)
		}

		// Filter by domain if specified
		if opts.Domain != "" {
			emailDomain := extractDomain(processedEmail)
			if !strings.EqualFold(emailDomain, opts.Domain) {
				continue
			}
		}

		// Create processed address with sources and add to accumulator
		processedAddr := Address{
			Email:    processedEmail,
			Name:     addr.Name,
			Methods:  addr.Methods,
			Verified: addr.Verified,
			Sources:  addr.Sources, // Preserve existing sources mapping
		}
		accumulator.addWithMethods(processedAddr)
	}

	return &Result{
		Username:  r.Username,
		Addresses: accumulator.toSlice(),
	}
}

// isGitHubNoreplyEmail checks if an email is a GitHub user noreply address that should be preserved.
func isGitHubNoreplyEmail(email string) bool {
	lowerEmail := strings.ToLower(email)
	return strings.HasSuffix(lowerEmail, "@users.noreply.github.com")
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

	// Normalize Unicode characters (e.g., umlauts ö → o, ä → a)
	user = normalizeUnicode(user)
	domain = normalizeUnicode(domain)

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
	// Guesses contains email address guesses with confidence scores, ordered by confidence.
	Guesses []Address
	// FoundAddresses contains the addresses that were found during lookup.
	FoundAddresses []Address
}

// validateDomain validates a domain name for security.
func validateDomain(domain string) error {
	if domain == "" {
		return nil // Empty domain is allowed for some operations
	}

	if len(domain) > 253 {
		return errors.New("domain too long (max 253 characters)")
	}

	// Basic domain format validation
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$`)
	if !domainRegex.MatchString(domain) {
		return errors.New("domain contains invalid characters")
	}

	// Security checks
	if strings.Contains(domain, "..") {
		return errors.New("domain cannot contain consecutive dots")
	}

	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return errors.New("domain cannot start or end with a dot")
	}

	return nil
}

// Guess provides intelligent email address guessing for a GitHub user within a specific domain.
// It first performs a lookup to find existing addresses, then applies precedence rules to find
// the most likely email address for the given domain.
func (lu *Lookup) Guess(ctx context.Context, username, organization string, opts GuessOptions) (*GuessResult, error) {
	if opts.Domain == "" {
		return nil, errors.New("domain is required for guessing")
	}

	// Validate inputs for security
	if err := validateGitHubUsername(username); err != nil {
		return nil, fmt.Errorf("invalid username: %w", err)
	}

	if err := validateOrganization(organization); err != nil {
		return nil, fmt.Errorf("invalid organization: %w", err)
	}

	if err := validateDomain(opts.Domain); err != nil {
		return nil, fmt.Errorf("invalid domain: %w", err)
	}

	lu.logger.Info("guessing email address",
		"username", username,
		"organization", organization,
		"domain", opts.Domain,
	)

	// Store current user context for validation
	lu.currentUsername = username
	lu.currentUserNames = []string{} // Will be populated from addresses

	// First, perform a regular lookup to get all available addresses
	result, err := lu.Lookup(ctx, username, organization)
	if err != nil {
		return nil, fmt.Errorf("lookup failed: %w", err)
	}

	// Extract known names from the found addresses for validation
	for _, addr := range result.Addresses {
		if addr.Name != "" {
			lu.currentUserNames = append(lu.currentUserNames, addr.Name)
		}
	}

	guessResult := &GuessResult{
		Username:       username,
		Guesses:        []Address{},
		FoundAddresses: result.Addresses,
	}

	// Apply precedence rules to find addresses in the target domain
	targetDomain := strings.ToLower(opts.Domain)

	// Always generate intelligent guesses using original addresses
	// (not normalized, so we can properly identify and skip GitHub noreply addresses)
	guesses := lu.generateIntelligentGuesses(ctx, username, result.Addresses, targetDomain)

	// Validate ONLY the generated guesses against GitHub issues and PRs
	// (Do not search for arbitrary domain emails - that leads to unrelated coworkers being returned)
	validatedGuesses := lu.validateGuessesWithGitHub(ctx, guesses)
	guessResult.Guesses = validatedGuesses

	return guessResult, nil
}

// generateIntelligentGuesses creates email guesses based on existing patterns and user info.
func (lu *Lookup) generateIntelligentGuesses(_ context.Context, username string, addresses []Address, targetDomain string) []Address {
	// Track guesses by email to combine confidence scores and sources
	guessMap := make(map[string]*Address)

	// Track addresses we already found to avoid duplicating them as guesses
	foundEmails := make(map[string]bool)
	for _, addr := range addresses {
		foundEmails[strings.ToLower(addr.Email)] = true
	}

	// Helper function to add or combine guesses
	addGuess := func(email string, confidence int, pattern string, sources map[string]string) {
		if foundEmails[strings.ToLower(email)] {
			lu.logger.Debug("skipping guess, email already found via GitHub search",
				"email", email, "pattern", pattern, "confidence", confidence)
			return // Skip if we already found this email
		}

		if existing, exists := guessMap[email]; exists {
			// Combine confidence scores (additive, capped at 100)
			oldConfidence := existing.Confidence
			combinedConfidence := existing.Confidence + confidence
			if combinedConfidence > 100 {
				combinedConfidence = 100
			}
			existing.Confidence = combinedConfidence

			lu.logger.Debug("combining guess scores",
				"email", email, "old_confidence", oldConfidence,
				"new_contribution", confidence, "combined_confidence", combinedConfidence,
				"old_pattern", existing.Pattern, "new_pattern", pattern)

			// Combine patterns
			existing.Pattern = existing.Pattern + "+" + pattern

			// Merge sources
			if existing.Sources == nil {
				existing.Sources = make(map[string]string)
			}
			for key, value := range sources {
				existing.Sources[key] = value
			}
		} else {
			// New guess
			lu.logger.Debug("adding new guess",
				"email", email, "confidence", confidence, "pattern", pattern, "sources", sources)
			guessMap[email] = &Address{
				Email:      email,
				Confidence: confidence,
				Pattern:    pattern,
				Sources:    make(map[string]string),
			}
			for key, value := range sources {
				guessMap[email].Sources[key] = value
			}
		}
	}

	// Strategy 1 (HIGHEST PRIORITY): Use GitHub username @ domain (HIGH confidence for exact matches)
	if username != "" {
		// Primary: Try the exact username first (highest confidence)
		if isValidEmailPrefix(username) {
			guess := username + "@" + targetDomain
			addGuess(guess, 35, "github_username_exact", map[string]string{"source_username": username})
		}

		// Secondary: If username contains a dash, try the part before the first dash
		if dashIndex := strings.Index(username, "-"); dashIndex != -1 {
			usernamePrefix := username[:dashIndex]
			if usernamePrefix != "" && isValidEmailPrefix(usernamePrefix) {
				guess := usernamePrefix + "@" + targetDomain
				addGuess(guess, 25, "github_username_prefix", map[string]string{"source_username": username})
			}
		}
	}

	// Strategy 2: Use unique normalized prefixes from other domains (50% confidence)
	for _, addr := range addresses {
		email := addr.Email
		if !strings.EqualFold(extractDomain(email), targetDomain) {
			// Skip GitHub noreply addresses - their prefixes are just user IDs, not meaningful email prefixes
			if isGitHubNoreplyEmail(email) {
				continue
			}

			// Extract prefix (local part before @)
			parts := strings.SplitN(email, "@", 2)
			if len(parts) == 2 && parts[0] != "" {
				prefix := parts[0]
				// Skip prefixes that end with common domain extensions (likely invalid)
				if strings.HasSuffix(prefix, ".dev") || strings.HasSuffix(prefix, ".com") ||
					strings.HasSuffix(prefix, ".org") || strings.HasSuffix(prefix, ".net") ||
					strings.HasSuffix(prefix, ".io") {
					continue
				}
				// Skip generic prefixes that are unlikely to be personal emails
				genericPrefixes := []string{
					"mail", "info", "admin", "support", "contact", "hello", "help",
					"noreply", "no-reply", "donotreply", "team", "sales", "marketing",
					"office", "business", "general", "enquiries", "inquiries",
				}
				isGeneric := false
				for _, generic := range genericPrefixes {
					if strings.EqualFold(prefix, generic) {
						isGeneric = true
						break
					}
				}
				if isGeneric {
					continue
				}
				guess := prefix + "@" + targetDomain
				addGuess(guess, 25, "same_prefix_as_other_domain", map[string]string{"source_email": email})
			}
		}
	}

	// Strategy 2 & 3: Use names from addresses (populated by lookup methods)
	// Deduplicate names to avoid combining the same pattern multiple times
	seenNames := make(map[string]bool)
	for _, addr := range addresses {
		if addr.Name != "" && !seenNames[addr.Name] {
			seenNames[addr.Name] = true
			nameGuesses := generateNameBasedGuesses(addr.Name, targetDomain)
			for _, guess := range nameGuesses {
				addGuess(guess.Email, guess.Confidence, guess.Pattern, guess.Sources)
			}
		}
	}

	// Strategy 3b: Smart username parsing - try to detect firstname.lastname pattern
	if username != "" {
		// Collect known names from addresses to use for intelligent splitting
		var knownNames []string
		for _, addr := range addresses {
			if addr.Name != "" {
				knownNames = append(knownNames, addr.Name)
			}
		}

		smartGuesses := parseUsernameForNames(username, targetDomain, knownNames...)
		for _, guess := range smartGuesses {
			addGuess(guess.Email, guess.Confidence, guess.Pattern, guess.Sources)
		}
	}

	// Convert guessMap to slice
	var guesses []Address
	for _, guess := range guessMap {
		guesses = append(guesses, *guess)
	}

	// Sort guesses by confidence score (highest first)
	sort.Slice(guesses, func(i, j int) bool {
		return guesses[i].Confidence > guesses[j].Confidence
	})

	return guesses
}

// isValidEmailPrefix checks if a string can be used as an email prefix (local part).
func isValidEmailPrefix(prefix string) bool {
	if prefix == "" {
		return false
	}

	// Basic validation for email prefix
	// Cannot start or end with dot, no consecutive dots
	if strings.HasPrefix(prefix, ".") || strings.HasSuffix(prefix, ".") || strings.Contains(prefix, "..") {
		return false
	}

	// Check for invalid characters (basic check)
	for _, r := range prefix {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '.' && r != '_' && r != '-' && r != '+' {
			return false
		}
	}

	return true
}

// generateNameBasedGuesses creates email guesses from a real name.
func generateNameBasedGuesses(realName, domain string) []Address {
	if realName == "" {
		return nil
	}

	// Normalize Unicode characters and clean the name
	normalizedName := normalizeUnicode(realName)
	parts := strings.Fields(normalizedName)

	// Handle single names
	if len(parts) == 1 {
		firstName := strings.ToLower(parts[0])
		guess := firstName + "@" + domain
		return []Address{{
			Email:      guess,
			Confidence: 20,
			Pattern:    "single_name",
			Sources:    map[string]string{"source_name": realName},
		}}
	}

	if len(parts) < 2 {
		return nil
	}

	var guesses []Address

	// Skip names that start with single-letter initials followed by periods
	// e.g., "D. Can Celasun" should use "Can" as first name, not "D."
	firstNameIndex := 0
	for i, part := range parts {
		cleanPart := strings.TrimSpace(part)
		// Check if this is a single letter followed by a period (initial)
		if len(cleanPart) <= 2 && strings.HasSuffix(cleanPart, ".") {
			continue // Skip this initial
		}
		firstNameIndex = i
		break
	}

	var firstName, lastName string
	// If all parts are initials, use the first one without the period
	if firstNameIndex >= len(parts)-1 {
		firstName = strings.ToLower(strings.TrimSuffix(parts[0], "."))
		lastName = strings.ToLower(parts[len(parts)-1])
	} else {
		firstName = strings.ToLower(parts[firstNameIndex])
		lastName = strings.ToLower(parts[len(parts)-1]) // Use last part as surname
	}

	// Validate that we have proper name components (no dots at the end)
	firstName = strings.TrimSuffix(firstName, ".")
	lastName = strings.TrimSuffix(lastName, ".")

	// Skip if we ended up with empty or single-character names
	if len(firstName) < 2 || len(lastName) < 2 {
		return nil
	}

	// firstname.lastname@domain (55% confidence) - most common at tech startups
	guess1 := firstName + "." + lastName + "@" + domain
	guesses = append(guesses, Address{
		Email:      guess1,
		Confidence: 55,
		Pattern:    "first.last",
		Sources:    map[string]string{"source_name": realName},
	})

	// firstname@domain (45% confidence) - very common for founders/early employees
	guess4 := firstName + "@" + domain
	guesses = append(guesses, Address{
		Email:      guess4,
		Confidence: 45,
		Pattern:    "first",
		Sources:    map[string]string{"source_name": realName},
	})

	// firstletterlastname@domain (35% confidence) - common abbreviated format
	if len(firstName) > 1 {
		guess3 := string(firstName[0]) + lastName + "@" + domain
		guesses = append(guesses, Address{
			Email:      guess3,
			Confidence: 35,
			Pattern:    "flast",
			Sources:    map[string]string{"source_name": realName},
		})
	}

	// lastname@domain (25% confidence) - occasionally used for distinctive last names
	if lastName != firstName { // Avoid duplicates for single names
		guess5 := lastName + "@" + domain
		guesses = append(guesses, Address{
			Email:      guess5,
			Confidence: 25,
			Pattern:    "last",
			Sources:    map[string]string{"source_name": realName},
		})
	}

	// firstinitiallastinitial@domain (20% confidence) - less common but still used
	if len(firstName) >= 1 && len(lastName) >= 1 {
		guess6 := string(firstName[0]) + string(lastName[0]) + "@" + domain
		guesses = append(guesses, Address{
			Email:      guess6,
			Confidence: 20,
			Pattern:    "initials",
			Sources:    map[string]string{"source_name": realName},
		})
	}

	// firstnamelastname@domain (15% confidence) - least common, mostly legacy systems
	guess2 := firstName + lastName + "@" + domain
	guesses = append(guesses, Address{
		Email:      guess2,
		Confidence: 15,
		Pattern:    "firstlast",
		Sources:    map[string]string{"source_name": realName},
	})

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

// calculateConfidenceAndPattern determines confidence score and pattern based on discovery methods and verification status.
func calculateConfidenceAndPattern(methods []string, verified bool, sources map[string]string) (confidence int, pattern string) {
	if verified {
		if len(methods) > 1 {
			return 100, "verified_multi_method"
		}
		return 100, "verified_address"
	}

	multiMethod := len(methods) > 1

	// Check for highest priority methods first
	if containsMethod(methods, "SAML Identity") {
		if multiMethod {
			return 98, "saml_identity_multi_method"
		}
		return 100, "saml_identity"
	}

	if containsMethod(methods, "Org Verified Domains") {
		if multiMethod {
			return 98, "org_verified_domains_multi_method"
		}
		return 100, "org_verified_domains"
	}

	if containsMethod(methods, "Org Members API") {
		if multiMethod {
			return 98, "org_member_multi_method"
		}
		return 95, "org_member"
	}

	if containsMethod(methods, "Public API") {
		if multiMethod {
			return 98, "public_api_multi_method"
		}
		return 95, "public_api"
	}

	if containsMethod(methods, "Git Commits") {
		baseConfidence := 95 // Increased from 85 - git commits are strong evidence
		pattern := "git_commits"
		if multiMethod {
			baseConfidence = 99 // Increased from 98 - multiple methods is nearly certain
			pattern = "git_commits_multi_method"
		}

		// Apply age-based reduction for commits (but less aggressive)
		if ageMonthsStr, exists := sources["commits_age_months"]; exists {
			if months, err := strconv.Atoi(ageMonthsStr); err == nil && months > 0 {
				reduction := months * 2 // 2% per month (reduced from 3% - git commits are strong evidence)
				adjustedConfidence := baseConfidence - reduction
				if adjustedConfidence < 85 { // Higher floor for git commits (was 55)
					adjustedConfidence = 85
				}
				return adjustedConfidence, pattern
			}
		}

		return baseConfidence, pattern
	}

	// Default fallback
	return 50, "unknown_method"
}

// validateGuessesWithGitHub validates email guesses by searching GitHub issues and PRs.
func (lu *Lookup) validateGuessesWithGitHub(ctx context.Context, guesses []Address) []Address {
	if len(guesses) == 0 {
		return guesses
	}

	lu.logger.Debug("validating guesses with GitHub GraphQL", "count", len(guesses))

	var validatedGuesses []Address
	var unvalidatedGuesses []Address

	for _, guess := range guesses {
		// Search for the guessed email in issues and PRs
		validatedGuess := lu.searchEmailInGitHub(ctx, guess)

		if validatedGuess.Confidence > 0 {
			validatedGuesses = append(validatedGuesses, validatedGuess)
		} else {
			// Keep original guess for scaling later (unvalidated guesses will be scaled to 5-20% range)
			unvalidatedGuesses = append(unvalidatedGuesses, guess)
			lu.logger.Debug("unvalidated guess kept for scaling", "email", guess.Email, "original_confidence", guess.Confidence)
		}
	}

	// Check if we have any high-confidence results (>80%)
	hasHighConfidence := false
	for _, guess := range validatedGuesses {
		if guess.Confidence > 80 {
			hasHighConfidence = true
			break
		}
	}

	// If we have high-confidence results, only return those
	if hasHighConfidence {
		var highConfidenceGuesses []Address
		for _, guess := range validatedGuesses {
			if guess.Confidence > 80 {
				highConfidenceGuesses = append(highConfidenceGuesses, guess)
			}
		}
		lu.logger.Debug("showing only high-confidence results", "count", len(highConfidenceGuesses))
		return highConfidenceGuesses
	}

	// Otherwise, return all guesses (validated + unvalidated with scaled confidence)
	scaledUnvalidatedGuesses := lu.scaleUnvalidatedConfidence(unvalidatedGuesses)
	allGuesses := append(validatedGuesses, scaledUnvalidatedGuesses...)
	lu.logger.Debug("showing all results (no high-confidence found)",
		"validated", len(validatedGuesses),
		"unvalidated", len(scaledUnvalidatedGuesses),
		"total", len(allGuesses))
	return allGuesses
}

// scaleUnvalidatedConfidence assigns realistic probability scores to unvalidated guesses
// based on actual email pattern frequency at tech startups.
func (lu *Lookup) scaleUnvalidatedConfidence(unvalidatedGuesses []Address) []Address {
	if len(unvalidatedGuesses) == 0 {
		return unvalidatedGuesses
	}

	// Create a copy of the guesses to avoid modifying the original slice
	scaledGuesses := make([]Address, len(unvalidatedGuesses))
	copy(scaledGuesses, unvalidatedGuesses)

	// Assign probability scores based on real-world email pattern frequency at tech startups
	for i := range scaledGuesses {
		originalConfidence := scaledGuesses[i].Confidence
		var probabilityScore int

		// Assign scores based on original confidence ordering (higher original = more common pattern)
		switch originalConfidence {
		case 55: // firstname.lastname@domain - most common pattern
			probabilityScore = 35
		case 45: // firstname@domain - common for founders/small companies
			probabilityScore = 25
		case 35: // firstletterlastname@domain - abbreviated format
			probabilityScore = 20
		case 25: // lastname@domain - occasionally used
			probabilityScore = 12
		case 20: // firstinitiallastinitial@domain - less common
			probabilityScore = 5
		case 15: // firstnamelastname@domain - least common, legacy
			probabilityScore = 3
		default:
			// Fallback for any unexpected values
			probabilityScore = 10
		}

		lu.logger.Debug("assigning probability score to unvalidated guess",
			"email", scaledGuesses[i].Email,
			"original_confidence", originalConfidence,
			"probability_score", probabilityScore)

		scaledGuesses[i].Confidence = probabilityScore
	}

	return scaledGuesses
}

// searchEmailInGitHub searches for an email address in GitHub issues and PRs using GraphQL.
func (lu *Lookup) searchEmailInGitHub(ctx context.Context, guess Address) Address {
	// Create a copy of the guess to modify
	validatedGuess := guess

	// Skip GitHub search for very short email prefixes (less than 2 characters)
	// GitHub's search doesn't work well with single characters
	atIndex := strings.Index(guess.Email, "@")
	if atIndex != -1 && atIndex < 2 {
		lu.logger.Debug("skipping GitHub search for short prefix", "email", guess.Email, "prefix_length", atIndex)
		return validatedGuess
	}

	// Use GraphQL to search for the email in issues and PRs
	src := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: lu.token})
	httpClient := oauth2.NewClient(ctx, src)
	client := githubv4.NewClient(httpClient)

	// GraphQL query to search issues and PRs and get their content for validation
	var query struct {
		Search struct {
			IssueCount int
			Edges      []struct {
				Node struct {
					Typename string `graphql:"__typename"`
					Issue    struct {
						Number     int
						Title      string
						Body       string
						Repository struct {
							Name  string
							Owner struct {
								Login string
							}
						}
					} `graphql:"... on Issue"`
					PullRequest struct {
						Number     int
						Title      string
						Body       string
						Repository struct {
							Name  string
							Owner struct {
								Login string
							}
						}
					} `graphql:"... on PullRequest"`
				}
			}
		} `graphql:"search(query: $query, type: ISSUE, first: 10)"`
	}

	// Search for the email address in issues and PRs only
	// Commits are not supported in GitHub's search API with GraphQL
	searchQuery := fmt.Sprintf(`%q type:issue,pr`, guess.Email)
	variables := map[string]any{
		"query": githubv4.String(searchQuery),
	}

	lu.logger.Debug("email validation: executing GraphQL query",
		"email", guess.Email,
		"query", searchQuery)

	err := client.Query(ctx, &query, variables)
	if err != nil {
		lu.logger.Debug("GitHub GraphQL search failed", "email", guess.Email, "error", err)
		return validatedGuess
	}

	// Validate that the email actually appears in the content of issues/PRs
	var validatedIssueMatches, validatedPRMatches int
	for _, edge := range query.Search.Edges {
		node := edge.Node
		var content, itemType, repoOwner, repoName, itemURL string
		var number int

		switch node.Typename {
		case "Issue":
			content = node.Issue.Title + " " + node.Issue.Body
			itemType = "issue"
			number = node.Issue.Number
			repoOwner = node.Issue.Repository.Owner.Login
			repoName = node.Issue.Repository.Name
			itemURL = fmt.Sprintf("https://github.com/%s/%s/issues/%d", repoOwner, repoName, number)
		case "PullRequest":
			content = node.PullRequest.Title + " " + node.PullRequest.Body
			itemType = "pr"
			number = node.PullRequest.Number
			repoOwner = node.PullRequest.Repository.Owner.Login
			repoName = node.PullRequest.Repository.Name
			itemURL = fmt.Sprintf("https://github.com/%s/%s/pull/%d", repoOwner, repoName, number)
		}

		// Case-insensitive search for the exact email in the content (not substring)
		// Use word boundaries to avoid matching lewandowski@google.com inside klewandowski@google.com
		contentLower := strings.ToLower(content)
		emailLower := strings.ToLower(guess.Email)

		// Look for the email with word boundaries (space, start/end of string, or common delimiters)
		emailFound := false
		if contentLower == emailLower {
			emailFound = true // Exact match
		} else {
			// Check for email surrounded by word boundaries
			for i := 0; i <= len(contentLower)-len(emailLower); i++ {
				if contentLower[i:i+len(emailLower)] == emailLower {
					// Check character before (if exists)
					beforeOK := i == 0 || !isEmailChar(rune(contentLower[i-1]))
					// Check character after (if exists)
					afterOK := i+len(emailLower) == len(contentLower) || !isEmailChar(rune(contentLower[i+len(emailLower)]))
					if beforeOK && afterOK {
						emailFound = true
						break
					}
				}
			}
		}

		if emailFound {
			// Check if this is a last-name-only email that needs additional validation
			emailPrefix := strings.Split(guess.Email, "@")[0]
			isLastNameOnlyEmail := false

			// Check against user's known names to see if this is a last-name-only email
			for _, name := range lu.currentUserNames {
				if name == "" {
					continue
				}
				nameParts := strings.Fields(name)
				if len(nameParts) > 1 {
					lastName := strings.ToLower(nameParts[len(nameParts)-1])
					if strings.EqualFold(emailPrefix, lastName) {
						isLastNameOnlyEmail = true

						// For last-name-only emails, require additional evidence (first name or username)
						firstName := strings.ToLower(nameParts[0])
						username := strings.ToLower(lu.currentUsername)
						contentLower := strings.ToLower(content)

						// Check for exact matches first
						exactMatch := strings.Contains(contentLower, firstName) || strings.Contains(contentLower, username)
						nicknameMatch := false

						// Check for nickname/shortened name variations if no exact match
						if !exactMatch && len(firstName) > 3 {
							for i := 3; i <= len(firstName); i++ {
								prefix := firstName[:i]
								if strings.Contains(contentLower, prefix) {
									nicknameMatch = true
									lu.logger.Debug("email validation: last-name-only email validated with nickname context",
										"email", guess.Email, "last_name", lastName, "first_name", firstName, "prefix", prefix, "username", username,
										"type", itemType, "number", number, "url", itemURL)
									break
								}
							}
						}

						if !exactMatch && !nicknameMatch {
							lu.logger.Debug("email validation: last-name-only email found but no first name/username context",
								"email", guess.Email, "last_name", lastName, "first_name", firstName, "username", username,
								"type", itemType, "number", number, "url", itemURL)
							goto nextNode // Skip this match - not enough context
						} else if exactMatch {
							lu.logger.Debug("email validation: last-name-only email validated with exact context",
								"email", guess.Email, "last_name", lastName, "first_name", firstName, "username", username,
								"type", itemType, "number", number, "url", itemURL)
						}
						break
					}
				}
			}

			if itemType == "issue" {
				validatedIssueMatches++
			} else {
				validatedPRMatches++
			}
			lu.logger.Debug("email validation: found email in content",
				"email", guess.Email,
				"type", itemType,
				"number", number,
				"url", itemURL,
				"is_last_name_only", isLastNameOnlyEmail)
		} else {
			lu.logger.Debug("email validation: email not found in content",
				"email", guess.Email,
				"type", itemType,
				"number", number,
				"url", itemURL)
		}
	nextNode:
	}

	// Also search through recent commits we already fetched
	commitMatches := lu.searchRecentCommitsForEmail(guess.Email)

	// Additionally search GitHub's commit API directly for this specific email
	if commitMatches == 0 {
		found, orgs := lu.searchEmailInCommits(ctx, guess.Email)
		if found {
			commitMatches = 1 // Found via direct commit search
			lu.logger.Debug("found email via direct commit search", "email", guess.Email, "orgs", orgs)
			// Store organization info in sources
			if len(orgs) > 0 {
				if validatedGuess.Sources == nil {
					validatedGuess.Sources = make(map[string]string)
				}
				validatedGuess.Sources["found_in_orgs"] = strings.Join(orgs, ", ")
			}
		}
	}

	totalMatches := validatedIssueMatches + validatedPRMatches + commitMatches

	// Always log the search result (even if 0 matches) with breakdown
	lu.logger.Debug("email validation: GitHub search completed",
		"email", guess.Email,
		"issue_matches", validatedIssueMatches,
		"pr_matches", validatedPRMatches,
		"commit_matches", commitMatches,
		"total_matches", totalMatches)

	if totalMatches > 0 {
		// Calculate confidence based on validation methods using standardized values
		newConfidence := calculateValidationConfidence(validatedIssueMatches, validatedPRMatches, commitMatches)

		validatedGuess.Confidence = newConfidence

		// Add sources information
		if validatedGuess.Sources == nil {
			validatedGuess.Sources = make(map[string]string)
		}
		validatedGuess.Sources["github_search"] = guess.Email

		// Update methods and pattern to indicate validation type
		var validationType, methodType string
		if validatedIssueMatches > 0 && validatedPRMatches > 0 {
			validationType = "github_issues_prs_validated"
			methodType = "github_issues_prs"
		} else if validatedIssueMatches > 0 {
			validationType = "github_issues_validated"
			methodType = "github_issues"
		} else if validatedPRMatches > 0 {
			validationType = "github_prs_validated"
			methodType = "github_prs"
		} else {
			validationType = "github_commits_validated" // Only commit matches
			methodType = "github_commits"
		}

		// Add the specific method type
		validatedGuess.Methods = append(validatedGuess.Methods, methodType)

		if validatedGuess.Pattern != "" {
			validatedGuess.Pattern += "_" + validationType
		} else {
			validatedGuess.Pattern = validationType
		}
	} else {
		// Special case: If this is an exact GitHub username match (e.g., tstromberg@google.com for user tstromberg)
		// and we found commits (even if validation failed), still include it with reduced confidence
		emailPrefix := strings.Split(validatedGuess.Email, "@")[0]
		if strings.EqualFold(emailPrefix, lu.currentUsername) && commitMatches > 0 {
			validatedGuess.Confidence = 70 // Moderate confidence for username match with commits found
			validatedGuess.Pattern += "_username_commits_found"
			if validatedGuess.Sources == nil {
				validatedGuess.Sources = make(map[string]string)
			}
			validatedGuess.Sources["github_commits_found"] = fmt.Sprintf("%d commits found", commitMatches)
			validatedGuess.Methods = append(validatedGuess.Methods, "github_commits")
		} else {
			// No validation found - set confidence to 0 to indicate this is unvalidated
			validatedGuess.Confidence = 0
			validatedGuess.Pattern += "_unvalidated"
		}
	}

	return validatedGuess
}

// searchRecentCommitsForEmail searches for an email address in the recent commits we already fetched.
// It searches both commit messages (for signatures) and commit metadata (for author/committer emails).
func (lu *Lookup) searchRecentCommitsForEmail(email string) int {
	matches := 0

	// Search commit messages for email signatures (like "Signed-off-by:")
	// Use regex to match exact email addresses with word boundaries
	emailPattern := `\b` + regexp.QuoteMeta(email) + `\b`
	emailRegex, err := regexp.Compile(`(?i)` + emailPattern) // Case-insensitive
	if err != nil {
		lu.logger.Warn("invalid email pattern for regex", "email", email, "error", err)
		return 0
	}

	for _, message := range lu.commitMessages {
		if emailRegex.MatchString(message) {
			matches++
			// Log the commit message that contained the email (truncated for readability)
			truncatedMessage := message
			if len(truncatedMessage) > 200 {
				truncatedMessage = truncatedMessage[:200] + "..."
			}
			lu.logger.Debug("found email in commit message",
				"email", email,
				"message", truncatedMessage)
		}
	}

	// Also search recent commit author/committer emails that were already fetched
	// These are stored in lu.recentCommitEmails during lookupViaCommits
	for recentEmail := range lu.recentCommitEmails {
		if strings.EqualFold(recentEmail, email) {
			matches++
			break // Only count once per unique author email
		}
	}

	return matches
}

// normalizeUnicode converts Unicode characters to their ASCII equivalents for email addresses.
// Examples: Ö → O, é → e, ñ → n, ł → l, ø → o, etc.
func normalizeUnicode(input string) string {
	// Fast path: if string is already ASCII-lowercase, return as-is
	asciiLowercase := true
	for _, r := range input {
		if r > 127 || (r < 'a' || r > 'z') && r != ' ' {
			asciiLowercase = false
			break
		}
	}
	if asciiLowercase {
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

// searchDomainEmailsInUserContent searches for email addresses in the target domain
// that appear in issues/PRs authored by the user OR mentioning the user's name.
func (lu *Lookup) searchDomainEmailsInUserContent(ctx context.Context, username, targetDomain string, existingAddresses []Address) []Address {
	lu.logger.Debug("ENTERING searchDomainEmailsInUserContent",
		"username", username,
		"targetDomain", targetDomain,
		"existingAddresses", len(existingAddresses))
	var foundEmails []Address

	// Extract user's real name from existing addresses
	var firstName, lastName string
	for _, addr := range existingAddresses {
		if addr.Name != "" {
			nameParts := strings.Fields(strings.TrimSpace(addr.Name))
			if len(nameParts) >= 2 {
				firstName = strings.ToLower(nameParts[0])
				lastName = strings.ToLower(nameParts[len(nameParts)-1])
				break
			} else if len(nameParts) == 1 {
				// Single name - use it as firstName and username as lastName
				firstName = strings.ToLower(nameParts[0])
				lastName = strings.ToLower(username)
				break
			}
		}
	}

	lu.logger.Debug("extracted user name", "firstName", firstName, "lastName", lastName)

	// Generate email guesses for validation
	var emailGuesses []string
	if firstName != "" && lastName != "" {
		// Generate all possible email combinations for this domain
		emailGuesses = []string{
			firstName + "." + lastName + "@" + targetDomain,
			firstName + lastName + "@" + targetDomain,
			lastName + "." + firstName + "@" + targetDomain,
			string(firstName[0]) + lastName + "@" + targetDomain,
			firstName + string(lastName[0]) + "@" + targetDomain,
		}
		if len(firstName) > 1 {
			emailGuesses = append(emailGuesses, firstName[:2]+lastName+"@"+targetDomain)
		}
		if len(lastName) > 1 {
			emailGuesses = append(emailGuesses, firstName+lastName[:2]+"@"+targetDomain)
		}
	}
	lu.logger.Debug("generated email guesses", "count", len(emailGuesses), "guesses", emailGuesses)

	// Create GraphQL client
	src := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: lu.token})
	httpClient := oauth2.NewClient(ctx, src)
	client := githubv4.NewClient(httpClient)

	// Search for Issues and PRs that contain the target domain with user-specific terms
	lu.logger.Debug("searching domain content for emails", "username", username, "targetDomain", targetDomain)
	domainEmails := lu.searchDomainContent(ctx, client, username, targetDomain, firstName, lastName)
	lu.logger.Debug("domain email search completed", "found_emails_count", len(domainEmails))
	foundEmails = append(foundEmails, domainEmails...)

	// Search for comments authored by the user that contain the target domain
	lu.logger.Debug("searching user-authored comments for domain emails", "username", username, "targetDomain", targetDomain)
	commentEmails := lu.searchUserComments(ctx, client, username, targetDomain, firstName, lastName, emailGuesses)
	lu.logger.Debug("comment email search completed", "found_emails_count", len(commentEmails))
	foundEmails = append(foundEmails, commentEmails...)

	return foundEmails
}

// searchDomainContent searches for domain emails in issues/PRs that contain the target domain and user-specific terms.
func (lu *Lookup) searchDomainContent(ctx context.Context, client *githubv4.Client, username, targetDomain, firstName, lastName string) []Address {
	var foundEmails []Address

	// Search for issues and PRs that contain the target domain
	var query struct {
		Search struct {
			Edges []struct {
				Node struct {
					Typename string `graphql:"__typename"`
					Issue    struct {
						Number int
						Title  string
						Body   string
						Author struct {
							Login string
						}
						Repository struct {
							Name  string
							Owner struct {
								Login string
							}
						}
					} `graphql:"... on Issue"`
					PullRequest struct {
						Number int
						Title  string
						Body   string
						Author struct {
							Login string
						}
						Repository struct {
							Name  string
							Owner struct {
								Login string
							}
						}
					} `graphql:"... on PullRequest"`
				}
			}
		} `graphql:"search(query: $searchQuery, type: ISSUE, first: 50)"`
	}

	// Build targeted search queries - we'll try multiple approaches
	var searchQueries []string

	// Strategy 1: Search for full name in quotes with domain
	if firstName != "" && lastName != "" {
		fullName := fmt.Sprintf("%s %s", firstName, lastName)
		searchQueries = append(searchQueries, fmt.Sprintf(`%q @%s type:issue,pr`, fullName, targetDomain))
	}

	// Strategy 2: Search for specific email guesses we're considering
	// Generate the email guesses we would make for this user
	var emailGuesses []string
	if firstName != "" && lastName != "" {
		emailGuesses = append(emailGuesses,
			firstName+"."+lastName+"@"+targetDomain,        // evan.gibler@domain
			firstName+lastName+"@"+targetDomain,            // evangibler@domain
			string(firstName[0])+lastName+"@"+targetDomain, // egibler@domain
		)
	}
	if username != "" {
		emailGuesses = append(emailGuesses, username+"@"+targetDomain) // egibs@domain
	}

	// Create OR query for email guesses
	if len(emailGuesses) > 0 {
		quotedEmails := make([]string, len(emailGuesses))
		for i, email := range emailGuesses {
			quotedEmails[i] = fmt.Sprintf(`%q`, email)
		}
		searchQueries = append(searchQueries, fmt.Sprintf(`(%s) type:issue,pr`, strings.Join(quotedEmails, " OR ")))
	}

	// If no targeted searches available, skip
	if len(searchQueries) == 0 {
		lu.logger.Debug("domain search: skipping - no targeted search terms available",
			"username", username,
			"firstName", firstName,
			"lastName", lastName)
		return foundEmails
	}

	// Use the first available search strategy
	searchQuery := searchQueries[0]

	variables := map[string]any{
		"searchQuery": githubv4.String(searchQuery),
	}

	lu.logger.Debug("domain search: executing targeted GraphQL query for content",
		"username", username,
		"targetDomain", targetDomain,
		"firstName", firstName,
		"lastName", lastName,
		"query", searchQuery)

	err := client.Query(ctx, &query, variables)
	if err != nil {
		lu.logger.Debug("failed to search user authored content", "error", err, "username", username)
		return foundEmails
	}

	lu.logger.Debug("GraphQL search completed", "found_results", len(query.Search.Edges))
	foundEmails = lu.extractDomainEmailsFromContent(query.Search.Edges, username, targetDomain, firstName, lastName, emailGuesses)
	return foundEmails
}

// searchUserComments searches for domain emails in comments authored by the user.
func (lu *Lookup) searchUserComments(ctx context.Context, client *githubv4.Client, username string, targetDomain string, _ string, lastName string, emailGuesses []string) []Address {
	var foundEmails []Address

	// Search for issues that have comments by the user containing the target domain
	var commentsQuery struct {
		Search struct {
			Edges []struct {
				Node struct {
					Typename string `graphql:"__typename"`
					Issue    struct {
						Number   int
						Title    string
						Comments struct {
							Nodes []struct {
								Body   string
								Author struct {
									Login string
								}
							}
						} `graphql:"comments(first: 100)"`
					} `graphql:"... on Issue"`
					PullRequest struct {
						Number   int
						Title    string
						Comments struct {
							Nodes []struct {
								Body   string
								Author struct {
									Login string
								}
							}
						} `graphql:"comments(first: 100)"`
					} `graphql:"... on PullRequest"`
				}
			}
		} `graphql:"search(query: $searchQuery, type: ISSUE, first: 50)"`
	}

	// Build targeted comment search that looks for user's comments containing domain emails
	// This is more focused than the broad domain search
	searchQuery := fmt.Sprintf(`commenter:%s @%s type:issue,pr`, username, targetDomain)

	variables := map[string]any{
		"searchQuery": githubv4.String(searchQuery),
	}

	lu.logger.Debug("comment search: executing targeted GraphQL query for user comments",
		"username", username,
		"targetDomain", targetDomain,
		"query", searchQuery)

	err := client.Query(ctx, &commentsQuery, variables)
	if err != nil {
		lu.logger.Debug("failed to search user comments", "error", err, "username", username)
		return foundEmails
	}

	lu.logger.Debug("comment search completed", "found_results", len(commentsQuery.Search.Edges))

	// Extract emails from comments
	foundEmails = lu.extractEmailsFromCommentResults(commentsQuery.Search.Edges, username, targetDomain)
	return foundEmails
}

// extractEmailsFromCommentResults extracts domain emails from issue/PR comment search results.
func (lu *Lookup) extractEmailsFromCommentResults(edges []struct {
	Node struct {
		Typename string `graphql:"__typename"`
		Issue    struct {
			Number   int
			Title    string
			Comments struct {
				Nodes []struct {
					Body   string
					Author struct {
						Login string
					}
				}
			} `graphql:"comments(first: 100)"`
		} `graphql:"... on Issue"`
		PullRequest struct {
			Number   int
			Title    string
			Comments struct {
				Nodes []struct {
					Body   string
					Author struct {
						Login string
					}
				}
			} `graphql:"comments(first: 100)"`
		} `graphql:"... on PullRequest"`
	}
}, username, targetDomain string,
) []Address {
	var foundEmails []Address

	// Email regex to find email addresses in content
	emailRegex := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	seenEmails := make(map[string]bool)

	lu.logger.Debug("processing comment search results", "total_edges", len(edges), "targetDomain", targetDomain)

	for i, edge := range edges {
		node := edge.Node
		var itemNumber int
		var itemType string
		var comments []struct {
			Body   string
			Author struct {
				Login string
			}
		}

		switch node.Typename {
		case "Issue":
			itemNumber = node.Issue.Number
			itemType = "issue"
			comments = node.Issue.Comments.Nodes
		case "PullRequest":
			itemNumber = node.PullRequest.Number
			itemType = "pr"
			comments = node.PullRequest.Comments.Nodes
		}

		lu.logger.Debug("processing item for comments",
			"index", i,
			"type", itemType,
			"number", itemNumber,
			"comment_count", len(comments),
		)

		for j, comment := range comments {
			authorLogin := comment.Author.Login
			content := comment.Body

			lu.logger.Debug("processing comment",
				"comment_index", j,
				"item_type", itemType,
				"item_number", itemNumber,
				"author", authorLogin,
				"content_length", len(content),
			)

			// Only process comments authored by the target user
			if !strings.EqualFold(authorLogin, username) {
				lu.logger.Debug("skipping comment - author mismatch", "expected_author", username, "actual_author", authorLogin)
				continue
			}

			// Find all email addresses in the comment content
			emails := emailRegex.FindAllString(content, -1)
			lu.logger.Debug("extracted emails from comment",
				"item_type", itemType,
				"item_number", itemNumber,
				"all_emails_found", emails,
				"target_domain", targetDomain,
			)

			for _, email := range emails {
				email = strings.ToLower(email)

				// Check if email is in target domain
				if !strings.HasSuffix(email, "@"+strings.ToLower(targetDomain)) {
					lu.logger.Debug("skipping email - domain mismatch", "email", email, "target_domain", targetDomain)
					continue
				}

				// Skip if we've already seen this email
				if seenEmails[email] {
					lu.logger.Debug("skipping email - already seen", "email", email)
					continue
				}

				// Validate email format
				if !isValidEmail(email) {
					lu.logger.Debug("skipping email - invalid format", "email", email)
					continue
				}

				lu.logger.Debug("found valid domain email in comment", "email", email, "item_type", itemType, "item_number", itemNumber)

				// Apply heuristics to determine confidence
				baseConfidence := 50 // TODO: Fix function call later

				// Add bonus for user-authored comments (high confidence since user wrote it)
				confidence := baseConfidence + 25 // Higher bonus for comments since user definitely wrote it
				lu.logger.Debug("applying comment authorship bonus",
					"email", email,
					"base_confidence", baseConfidence,
					"final_confidence", confidence)

				if confidence > 0 {
					seenEmails[email] = true
					patternName := "domain_email_from_comment"

					foundEmails = append(foundEmails, Address{
						Email:      email,
						Confidence: confidence,
						Pattern:    patternName,
						Verified:   false,
						Methods:    []string{"github_comment_content"},
						Sources:    map[string]string{"source_content": fmt.Sprintf("comment on %s #%d (authored)", itemType, itemNumber)},
					})

					lu.logger.Debug("comment search: found email in comment",
						"email", email,
						"username", username,
						"item_type", itemType,
						"item_number", itemNumber,
						"confidence", confidence)
				}
			}
		}
	}

	return foundEmails
}

// extractDomainEmailsFromContent extracts domain emails from GraphQL search results.
func (lu *Lookup) extractDomainEmailsFromContent(edges []struct {
	Node struct {
		Typename string `graphql:"__typename"`
		Issue    struct {
			Number int
			Title  string
			Body   string
			Author struct {
				Login string
			}
			Repository struct {
				Name  string
				Owner struct {
					Login string
				}
			}
		} `graphql:"... on Issue"`
		PullRequest struct {
			Number int
			Title  string
			Body   string
			Author struct {
				Login string
			}
			Repository struct {
				Name  string
				Owner struct {
					Login string
				}
			}
		} `graphql:"... on PullRequest"`
	}
}, username, targetDomain, _ string, lastName string, emailGuesses []string,
) []Address {
	var foundEmails []Address

	// Email regex to find email addresses in content
	emailRegex := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	seenEmails := make(map[string]bool)

	lu.logger.Debug("processing search results", "total_edges", len(edges), "targetDomain", targetDomain)

	for i, edge := range edges {
		node := edge.Node
		var content, itemType, repoOwner, repoName, itemURL string
		var number int
		var authorLogin string

		switch node.Typename {
		case "Issue":
			content = node.Issue.Title + " " + node.Issue.Body
			itemType = "issue"
			number = node.Issue.Number
			authorLogin = node.Issue.Author.Login
			repoOwner = node.Issue.Repository.Owner.Login
			repoName = node.Issue.Repository.Name
			itemURL = fmt.Sprintf("https://github.com/%s/%s/issues/%d", repoOwner, repoName, number)
		case "PullRequest":
			content = node.PullRequest.Title + " " + node.PullRequest.Body
			itemType = "pr"
			number = node.PullRequest.Number
			authorLogin = node.PullRequest.Author.Login
			repoOwner = node.PullRequest.Repository.Owner.Login
			repoName = node.PullRequest.Repository.Name
			itemURL = fmt.Sprintf("https://github.com/%s/%s/pull/%d", repoOwner, repoName, number)
		}

		lu.logger.Debug("processing search result",
			"index", i,
			"type", itemType,
			"number", number,
			"author", authorLogin,
			"content_length", len(content),
		)

		// Check if this content was authored by the target user (for confidence bonus)
		isAuthoredByUser := strings.EqualFold(authorLogin, username)
		lu.logger.Debug("processing content", "authored_by_user", isAuthoredByUser, "author", authorLogin, "target_user", username)

		// Find all email addresses in the content
		emails := emailRegex.FindAllString(content, -1)
		lu.logger.Debug("extracted emails from content",
			"itemType", itemType,
			"number", number,
			"all_emails_found", emails,
			"target_domain", targetDomain,
		)

		for _, email := range emails {
			email = strings.ToLower(email)

			// Check if email is in target domain
			if !strings.HasSuffix(email, "@"+strings.ToLower(targetDomain)) {
				lu.logger.Debug("skipping email - domain mismatch", "email", email, "target_domain", targetDomain)
				continue
			}

			// Skip if we've already seen this email
			if seenEmails[email] {
				lu.logger.Debug("skipping email - already seen", "email", email)
				continue
			}

			// Validate email format
			if !isValidEmail(email) {
				lu.logger.Debug("skipping email - invalid format", "email", email)
				continue
			}

			lu.logger.Debug("found valid domain email", "email", email, "itemType", itemType, "number", number)

			// Apply heuristics to determine confidence
			baseConfidence := 40 // TODO: Fix function call later

			// Add bonus for user-authored content (higher confidence)
			confidence := baseConfidence
			if isAuthoredByUser {
				confidence += 20 // Bonus for user-authored content
				lu.logger.Debug("applying authorship bonus", "email", email, "base_confidence", baseConfidence, "final_confidence", confidence)
			}

			if confidence > 0 {
				seenEmails[email] = true
				patternName := fmt.Sprintf("domain_email_from_%s", itemType)

				foundEmails = append(foundEmails, Address{
					Email:      email,
					Confidence: confidence,
					Pattern:    patternName,
					Verified:   false,
					Methods:    []string{fmt.Sprintf("github_%s_content", itemType)},
					Sources:    map[string]string{"source_content": fmt.Sprintf("%s #%d (%s)", itemType, number, map[bool]string{true: "authored", false: "mentioned"}[isAuthoredByUser])},
				})

				lu.logger.Debug("domain search: found email in content",
					"email", email,
					"username", username,
					"type", itemType,
					"number", number,
					"url", itemURL,
					"authored_by_user", isAuthoredByUser,
					"confidence", confidence)
			}
		}
	}

	return foundEmails
}

// calculateDomainEmailConfidence applies heuristics to determine confidence level
// for domain emails found in user's issues/PRs.
func (*Lookup) calculateDomainEmailConfidence(email, username string, firstName, lastName string, emailGuesses []string) int {
	// Extract local part (prefix before @)
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return 0
	}
	localPart := strings.ToLower(parts[0])
	usernameLC := strings.ToLower(username)

	// HIGHEST PRIORITY: Check if this email matches one of our guesses exactly
	for _, guess := range emailGuesses {
		guessParts := strings.SplitN(strings.ToLower(guess), "@", 2)
		if len(guessParts) == 2 && guessParts[0] == localPart {
			return 95 // Very high confidence - matches our intelligent guess
		}
	}

	// HIGH PRIORITY: Exact username match
	if localPart == usernameLC {
		return 85 // Very high confidence
	}

	// HIGH PRIORITY: Contains username as substring
	if strings.Contains(localPart, usernameLC) {
		return 70 // High confidence
	}

	// HIGH PRIORITY: Check for name-based patterns if we have names
	if firstName != "" && lastName != "" {
		firstNameLC := strings.ToLower(firstName)
		lastNameLC := strings.ToLower(lastName)

		// firstname.lastname pattern
		if localPart == firstNameLC+"."+lastNameLC {
			return 90 // Very high - standard professional format
		}

		// firstnamelastname pattern
		if localPart == firstNameLC+lastNameLC {
			return 85 // Very high
		}

		// first letter + lastname pattern
		if firstNameLC != "" && localPart == string(firstNameLC[0])+lastNameLC {
			return 80 // High
		}

		// Contains both first and last name parts
		if strings.Contains(localPart, firstNameLC) && strings.Contains(localPart, lastNameLC) {
			return 75 // High
		}
	}

	// MEDIUM PRIORITY: Short prefix heuristics (4 chars or less)
	if len(localPart) <= 4 {
		// Check first letter match with first name if available
		if firstName != "" && localPart != "" {
			if strings.EqualFold(string(localPart[0]), string(firstName[0])) {
				return 65 // Medium-high confidence for short prefix matching first letter
			}
		}

		// Check first letter match with username
		if usernameLC != "" && localPart != "" {
			firstLetter := localPart[0:1]
			usernameFirstLetter := usernameLC[0:1]
			if firstLetter == usernameFirstLetter {
				return 60 // Medium confidence
			}
		}
	}

	// LOW PRIORITY: General pattern matches
	if usernameLC != "" && len(localPart) >= 1 {
		// Check if email contains any part of the username
		for i := 1; i <= len(usernameLC) && i <= 4; i++ {
			usernamePrefix := usernameLC[0:i]
			if strings.Contains(localPart, usernamePrefix) {
				return 58 // Partial username match
			}
		}
	}

	// Default low confidence for any domain email found in user's content
	// Still valuable but less likely to be the user's email
	return 35
}

// parseUsernameForNames attempts to parse a username into likely first/last name combinations.
func parseUsernameForNames(username, targetDomain string, knownNames ...string) []Address {
	var guesses []Address

	// Skip very short usernames
	if len(username) < 5 {
		return guesses
	}

	usernameLower := strings.ToLower(username)

	// First priority: Use known names from user profile
	for _, knownName := range knownNames {
		if knownName == "" {
			continue
		}
		knownNameLower := strings.ToLower(strings.TrimSpace(knownName))
		if strings.HasPrefix(usernameLower, knownNameLower) && len(usernameLower) > len(knownNameLower) {
			// Extract potential last name
			lastName := usernameLower[len(knownNameLower):]

			// Skip if lastname is too short or invalid
			if len(lastName) < 3 || !isValidEmailPrefix(lastName) {
				continue
			}

			// Generate firstname.lastname guess with higher confidence since it's based on known name
			email := knownNameLower + "." + lastName + "@" + targetDomain
			guesses = append(guesses, Address{
				Email:      email,
				Confidence: 45, // Higher confidence for profile-based parsing
				Pattern:    "profile_parsed_username",
				Sources:    map[string]string{"source_username": username, "known_name": knownName, "parsed_first": knownNameLower, "parsed_last": lastName},
			})

			return guesses // Return immediately on profile-based match
		}
	}

	// Fallback: Known common first names that might appear in usernames
	commonFirstNames := []string{
		"amy", "john", "jane", "mike", "sarah", "david", "mary", "chris", "alex", "anna", "emma", "james", "robert", "michael", "william", "elizabeth", "jennifer", "linda", "jessica", "ashley", "emily", "karen", "lisa", "nancy", "betty", "dorothy", "sandra", "maria",
		"brian", "kevin", "jason", "matthew", "daniel", "steven", "andrew", "joshua", "kenneth", "paul", "mark", "donald", "richard", "charles", "thomas", "christopher", "ryan", "nicholas", "anthony", "eric", "jonathan", "justin", "tyler", "aaron", "jose", "adam", "henry", "douglas", "nathan", "peter", "noah", "christian", "javier", "benjamin", "samuel", "frank", "gregory", "raymond", "alexander", "patrick", "jack", "dennis", "jerry", "tyler", "jose", "henry", "douglas", "zack", "zackary", "zach", "zachary",
		"susan", "margaret", "carol", "ruth", "helen", "deborah", "sharon", "michelle", "laura", "sarah", "kimberly", "debra", "dorothy", "amy", "angela", "helen", "brenda", "emma", "olivia", "cynthia", "marie", "janet", "catherine", "frances", "christine", "samantha", "deborah", "rachel", "carolyn", "janet", "virginia", "maria", "heather", "diane", "julie", "joyce", "victoria", "kelly", "christina", "joan", "evelyn", "lauren", "judith", "megan", "cheryl", "andrea", "hannah", "jacqueline", "martha", "gloria", "teresa", "sara", "janice", "marie", "julia", "heather", "diane", "ruth", "julie", "joyce", "virginia",
	}

	// Try to find first name at the beginning of username
	for _, firstName := range commonFirstNames {
		if strings.HasPrefix(usernameLower, firstName) && len(usernameLower) > len(firstName) {
			// Extract potential last name
			lastName := usernameLower[len(firstName):]

			// Skip if lastname is too short or invalid
			if len(lastName) < 3 || !isValidEmailPrefix(lastName) {
				continue
			}

			// Generate firstname.lastname guess
			email := firstName + "." + lastName + "@" + targetDomain
			guesses = append(guesses, Address{
				Email:      email,
				Confidence: 35,
				Pattern:    "parsed_username",
				Sources:    map[string]string{"source_username": username, "parsed_first": firstName, "parsed_last": lastName},
			})

			return guesses // Return immediately on first match
		}
	}

	// Try to find first name at the END of username (like "crosleyjack")
	for _, firstName := range commonFirstNames {
		if strings.HasSuffix(usernameLower, firstName) && len(usernameLower) > len(firstName) {
			// Extract potential last name (everything before the first name)
			lastName := usernameLower[:len(usernameLower)-len(firstName)]

			// Skip if lastname is too short or invalid
			if len(lastName) < 3 || !isValidEmailPrefix(lastName) {
				continue
			}

			// Generate firstname.lastname guess
			email := firstName + "." + lastName + "@" + targetDomain
			guesses = append(guesses, Address{
				Email:      email,
				Confidence: 35,
				Pattern:    "parsed_username_suffix",
				Sources:    map[string]string{"source_username": username, "parsed_first": firstName, "parsed_last": lastName},
			})

			return guesses // Return immediately on first match
		}
	}

	return guesses
}

// calculateValidationConfidence calculates confidence based on validation methods used.
func calculateValidationConfidence(issueMatches, prMatches, commitMatches int) int {
	confidence := 0

	// Add confidence for each validation method found
	if issueMatches > 0 {
		confidence += ConfidenceIssues
	}
	if prMatches > 0 {
		confidence += ConfidencePRs
	}
	if commitMatches > 0 {
		confidence += ConfidenceCommits
	}

	// Cap at 100%
	if confidence > 100 {
		confidence = 100
	}

	return confidence
}

// isEmailChar returns true if the character is valid in an email address
// Based on RFC 5322 for email address characters.
func isEmailChar(c rune) bool {
	// Letters and digits
	if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
		return true
	}

	// Special characters allowed in email addresses (RFC 5322)
	switch c {
	case '@', '.', '-', '_', '+', '=', '!', '#', '$', '%', '&', '\'', '*', '/', '?', '^', '`', '{', '|', '}', '~':
		return true
	}

	return false
}
