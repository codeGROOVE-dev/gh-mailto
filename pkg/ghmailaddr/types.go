package ghmailaddr

import (
	"context"
	"log/slog"
	"sort"
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
	return func(l *Lookup) {
		l.logger = logger
	}
}

// New creates a new Lookup instance with the given GitHub token.
// The token should have appropriate permissions to access organization data.
func New(token string, opts ...Option) *Lookup {
	l := &Lookup{
		token:  token,
		logger: slog.Default(),
	}
	for _, opt := range opts {
		opt(l)
	}
	return l
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
func (l *Lookup) Lookup(ctx context.Context, username, organization string) (*Result, error) {
	l.logger.Info("looking up email addresses",
		"username", username,
		"organization", organization,
	)

	result := &Result{
		Username: username,
		// Addresses will be nil if no addresses found, which is fine
	}

	// Define lookup methods
	methods := []func(context.Context, string, string) ([]Address, error){
		l.lookupViaPublicAPI,
		l.lookupViaCommits,
		l.lookupViaSAMLIdentity,
		l.lookupViaOrgVerifiedDomains,
		l.lookupViaOrgMembers,
	}

	accumulator := newAddressAccumulator()
	for _, method := range methods {
		addresses, err := method(ctx, username, organization)
		if err != nil {
			l.logger.Error("lookup method failed", "error", err)
			continue
		}
		for _, addr := range addresses {
			accumulator.add(addr)
		}
	}

	result.Addresses = accumulator.toSlice()

	l.logger.Info("lookup completed",
		"username", username,
		"addressesFound", len(result.Addresses),
	)

	return result, nil
}