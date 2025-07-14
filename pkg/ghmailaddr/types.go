package ghmailaddr

import (
	"context"
	"log/slog"
	"sort"
	"sync"
)

// Address represents an email address found for a GitHub user.
type Address struct {
	// Email is the email address.
	Email string
	// Verified indicates whether the email address has been verified by GitHub.
	Verified bool
	// Methods contains the sorted list of discovery methods that found this address.
	Methods []string
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
	token  string
	logger *slog.Logger
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

func newAddressAccumulator() *addressAccumulator {
	return &addressAccumulator{
		addresses: make(map[string]*Address),
		methodSet: make(map[string]map[string]struct{}),
	}
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

// toSlice converts the accumulated addresses to a slice with sorted method lists
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
		name string
		fn   func(context.Context, string, string) ([]Address, error)
	}
	
	methods := []methodInfo{
		{"Public API", lu.lookupViaPublicAPI},
		{"Git Commits", lu.lookupViaCommits},
		{"SAML Identity", lu.lookupViaSAMLIdentity},
		{"Org Verified Domains", lu.lookupViaOrgVerifiedDomains},
		{"Org Members API", lu.lookupViaOrgMembers},
	}

	accumulator := newAddressAccumulator()
	
	// Execute methods in parallel
	type methodResult struct {
		name      string
		addresses []Address
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