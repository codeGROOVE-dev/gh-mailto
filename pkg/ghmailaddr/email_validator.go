package ghmailaddr

import (
	"net/mail"
	"strings"
)

// isValidEmail performs robust email validation.
func isValidEmail(email string) bool {
	// Basic check for empty string
	if email == "" {
		return false
	}

	// Check for common invalid patterns
	if strings.Contains(email, "..") || strings.HasPrefix(email, ".") || strings.HasSuffix(email, ".") {
		return false
	}

	// Exclude noreply addresses
	if strings.Contains(strings.ToLower(email), "noreply") {
		return false
	}

	// Use Go's built-in email parser for validation
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return false
	}

	// Extract the actual email from the parsed address
	actualEmail := addr.Address

	// Ensure it has exactly one @ symbol
	parts := strings.Split(actualEmail, "@")
	if len(parts) != 2 {
		return false
	}

	localPart, domain := parts[0], parts[1]

	const maxLocalLength = 64
	const maxDomainLength = 255
	const maxLabelLength = 63

	// Validate local part
	if localPart == "" || len(localPart) > maxLocalLength {
		return false
	}

	// Validate domain
	if domain == "" || len(domain) > maxDomainLength {
		return false
	}

	// Domain must have at least one dot
	if !strings.Contains(domain, ".") {
		return false
	}

	// Check for valid domain parts
	domainParts := strings.Split(domain, ".")
	for _, part := range domainParts {
		if part == "" || len(part) > maxLabelLength {
			return false
		}
	}

	return true
}
