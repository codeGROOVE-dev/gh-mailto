package ghmailto

import (
	"context"
	"log/slog"
	"sort"
	"strings"
	"sync"
)

// Address represents an email address found for a GitHub user.
type Address struct {
	// Email is the email address.
	Email string
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
func (a *addressAccumulator) add(addr Address) {
	email := addr.Email
	method := addr.Methods[0] // New addresses come with single method

	if existing, ok := a.addresses[email]; ok {
		// Once an address is verified by any method, it stays verified
		if addr.Verified {
			existing.Verified = true
		}
		// Track this discovery method
		if _, exists := a.methodSet[email][method]; !exists {
			a.methodSet[email][method] = struct{}{}
		}
	} else {
		// First time seeing this email
		a.addresses[email] = &Address{
			Email:    email,
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
