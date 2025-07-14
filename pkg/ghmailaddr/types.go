package ghmailaddr

import (
	"context"
	"log/slog"
	"sort"
)

// Address represents an email address found for a GitHub user.
type Address struct {
	Email    string
	Verified bool
	Methods  []string // Sorted list of discovery methods
}

// Result contains the email addresses found for a GitHub user.
type Result struct {
	Username  string
	Addresses []Address
}

// Lookup provides email address lookup for GitHub users.
type Lookup struct {
	token  string
	logger *slog.Logger
}

// Option configures a Lookup.
type Option func(*Lookup)

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) Option {
	return func(l *Lookup) {
		l.logger = logger
	}
}

// New creates a new Lookup instance.
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

// Lookup performs email address lookup for the given GitHub username within an organization.
func (l *Lookup) Lookup(ctx context.Context, username, organization string) (*Result, error) {
	l.logger.Info("looking up email addresses",
		"username", username,
		"organization", organization,
	)

	result := &Result{
		Username:  username,
		Addresses: []Address{},
	}

	// Define lookup methods
	methods := []func(context.Context, string, string) ([]Address, error){
		l.lookupViaPublicAPI,
		l.lookupViaCommits,
		l.lookupViaSAMLIdentity,
		l.lookupViaOrgVerifiedDomains,
		l.lookupViaOrgMembers,
	}

	addressMap := make(map[string]*Address)
	for _, method := range methods {
		addresses, err := method(ctx, username, organization)
		if err != nil {
			l.logger.Error("lookup method failed", "error", err)
			continue
		}
		for _, addr := range addresses {
			if existing, ok := addressMap[addr.Email]; ok {
				// Keep the verified flag if any method found it verified
				if addr.Verified {
					existing.Verified = true
				}
				// Append the method if not already present
				methodExists := false
				for _, m := range existing.Methods {
					if m == addr.Methods[0] {
						methodExists = true
						break
					}
				}
				if !methodExists {
					existing.Methods = append(existing.Methods, addr.Methods[0])
				}
			} else {
				// Create new address entry
				addressMap[addr.Email] = &Address{
					Email:    addr.Email,
					Verified: addr.Verified,
					Methods:  []string{addr.Methods[0]},
				}
			}
		}
	}

	// Convert map to slice and sort methods
	for _, addr := range addressMap {
		// Sort methods alphabetically
		sortedMethods := make([]string, len(addr.Methods))
		copy(sortedMethods, addr.Methods)
		sort.Strings(sortedMethods)
		addr.Methods = sortedMethods
		result.Addresses = append(result.Addresses, *addr)
	}

	l.logger.Info("lookup completed",
		"username", username,
		"addressesFound", len(result.Addresses),
	)

	return result, nil
}