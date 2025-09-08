# gh-mailto

A command-line tool and Go library for discovering email addresses associated with GitHub users within organizations. It combines multiple discovery methods to find both verified and unverified email addresses.

GitHub only returns verified email addresses within Enterprise organizations when you have appropriate permissions. This tool uses that verified data when available and supplements it with additional discovery methods when needed.

## Installation

```bash
go install github.com/codeGROOVE-dev/gh-mailto/cmd/gh-mailto@latest
gh auth login  # GitHub CLI authentication required
```

## Usage

Find all email addresses for a user in an organization:
```bash
gh-mailto --user username --org organization
```

Filter to a specific domain and generate intelligent guesses:
```bash
gh-mailto --user username --org organization --domain example.com --guess
```

Normalize addresses and show detailed discovery methods:
```bash
gh-mailto --user username --org organization --normalize --verbose
```

### Go Library

```go
import ghmailto "github.com/codeGROOVE-dev/gh-mailto/pkg/gh-mailto"

lookup := ghmailto.New(githubToken)
result, err := lookup.Lookup(ctx, "username", "organization")

for _, addr := range result.Addresses {
    fmt.Printf("%s (verified: %t, methods: %v)\n",
        addr.Email, addr.Verified, addr.Methods)
}

// optionally generate domain-specific guesses
guesses, err := lookup.Guess(ctx, "username", "organization",
    ghmailto.GuessOptions{Domain: "example.com"})
```

## Discovery Methods

The tool runs multiple discovery methods in parallel, prioritizing verified sources over unverified ones:

**Verified:** SAML identity providers (Enterprise), organization verified domain emails
**Unverified:** Public profiles, git commit history, organization member API data

## Email Guessing (optional)

The (optional) "guess" feature analyzes discovered patterns and generates intelligent guesses for the target domain using common corporate formats like firstname.lastname@domain.com and variations.

## Requirements

- Go 1.24 or later
- GitHub CLI authenticated (`gh auth login`)
- Token permissions: `read:user` and `read:org` (additional org permissions enable more methods)

## License

Apache 2.0
