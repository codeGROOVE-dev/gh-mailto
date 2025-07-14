# gh2addrs

A Go library and command-line tool that attempts to find email addresses associated with GitHub users within an organization using multiple methods.

**Important Note**: This library is designed for legitimate organizational use cases where you have appropriate API permissions to access organization data. It is NOT useful for attempting to spam or stalk GitHub users, as most methods require organization-level access permissions that random users do not have.

## Features

- Multiple email discovery methods:
  - Public API (user profile)
  - Recent commits in organization repositories
  - SAML identity provider (verified)
  - Organization verified domain emails (verified)
  - Organization member listings
- Email deduplication with preference for verified addresses
- Comprehensive logging for debugging
- Simple API with minimal dependencies
- Command-line tool with GitHub CLI integration

## Installation

```bash
go install github.com/ready-to-review/gh2addrs/cmd/gh2addrs@latest
```

## Command Line Usage

The tool integrates with GitHub CLI (`gh`) for authentication:

```bash
# Basic usage (uses 'gh auth token' automatically)
gh2addrs --user octocat --org github

# With explicit token
gh2addrs --user octocat --org github --token ghp_xxxxx

# Verbose output showing methods used
gh2addrs --user octocat --org github -v

# With custom timeout
gh2addrs --user octocat --org github --timeout 60s
```

## Library Usage

```go
package main

import (
    "context"
    "fmt"
    "log/slog"
    
    "github.com/ready-to-review/gh2addrs/pkg/emailfinder"
)

func main() {
    // Create finder with token
    finder := emailfinder.New("ghp_your_github_token")
    
    // Or with custom logger
    logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
        Level: slog.LevelDebug,
    }))
    finder := emailfinder.New("ghp_your_github_token", 
        emailfinder.WithLogger(logger))
    
    // Find emails
    ctx := context.Background()
    result, err := finder.Find(ctx, "octocat", "github")
    if err != nil {
        log.Fatal(err)
    }
    
    // Process results
    for _, email := range result.Emails {
        verified := ""
        if email.Verified {
            verified = " (verified)"
        }
        fmt.Printf("%s%s - found via %s\n", 
            email.Address, verified, email.Method)
    }
}
```

## Methods

The library tries the following methods in order:

1. **Public API**: Checks the user's public profile for email
2. **Commits**: Examines recent commits in organization repositories
3. **SAML Identity**: Uses GraphQL to check SAML identity provider (requires org admin access)
4. **Organization Verified Domains**: Uses GraphQL to get verified domain emails
5. **Organization Members**: Lists organization members (requires appropriate permissions)

## Requirements

- Go 1.21 or later
- GitHub personal access token with appropriate scopes:
  - `read:user` - for public profile information
  - `repo` - for accessing repository commits
  - `read:org` - for organization member information
  - `admin:org` (optional) - for SAML identity access

## Testing

Run the test suite:

```bash
go test ./...
```

Run with coverage:

```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Security Considerations

- The library requires a GitHub token with appropriate permissions
- Email addresses found via commits are marked as unverified
- SAML and organization domain emails are marked as verified
- The tool filters out GitHub noreply addresses
- All API requests use HTTPS
- Tokens are never logged

## License

MIT