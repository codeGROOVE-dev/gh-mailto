# gh2addrs

Find email addresses for GitHub users within your organization.

> **Note**: Requires organization-level permissions. Not useful for spam/stalking.

## Install

```bash
go install github.com/ready-to-review/gh2addrs/cmd/gh2addrs@latest
```

## Usage

### CLI

```bash
# Uses 'gh auth token' automatically
gh2addrs --user octocat --org github

# Show discovery methods  
gh2addrs --user octocat --org github -v

# JSON output
gh2addrs --user octocat --org github --json
```

### Library

```go
import "github.com/ready-to-review/gh2addrs/pkg/ghmailaddr"

lookup := ghmailaddr.New(token)
result, err := lookup.Lookup(ctx, "octocat", "github")

for _, addr := range result.Addresses {
    fmt.Printf("%s (verified: %v) via %v\n", 
        addr.Email, addr.Verified, addr.Methods)
}
```

## Discovery Methods

- Public profile email
- Git commit history
- SAML identity (verified)
- Organization verified domains
- Organization member API

## Requirements

- Go 1.21+
- GitHub token with `read:user`, `repo`, `read:org` scopes
- Optional: `admin:org` for SAML access

## License

MIT