# gh-mailto

Find email addresses for GitHub users via multiple methods

**NOTE**: GitHub onlys return verified e-mail addresses within an Enterprise org, and only if you have permissions to see them. This library will use that data if available, and
unverified sources if that data is unavailable.

## Install

```bash
go install github.com/codeGROOVE-dev/gh-mailto/cmd/gh-mailto@latest
```

## Usage

### CLI

```bash
# Uses 'gh auth token' automatically
gh-mailto --user octocat --org github

# Show discovery methods
gh-mailto --user octocat --org github -v

# JSON output
gh-mailto --user octocat --org github --json
```

### Library

```go
import "github.com/codeGROOVE-dev/gh-mailto/pkg/gh-mailto"

lookup := ghmailto.New(token)
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
- Optional: `read:org` for SAML access

## License

Apache 2.0
