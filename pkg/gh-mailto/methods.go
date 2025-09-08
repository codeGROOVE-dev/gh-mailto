package ghmailto

import (
	"context"
	"fmt"
	"net/http"

	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
)

const (
	methodPublicAPI    = "public_api"
	methodCommits      = "commits"
	methodSAMLIdentity = "saml_identity"
	methodOrgDomains   = "org_verified_domains"
	methodOrgMembers   = "org_members"
)

// lookupViaPublicAPI uses the GitHub REST API to find public email addresses.
func (lu *Lookup) lookupViaPublicAPI(ctx context.Context, username, _ string) ([]Address, error) {
	lu.logger.Debug("trying public API method", "username", username)

	var user struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}

	url := fmt.Sprintf("https://api.github.com/users/%s", username)
	if err := lu.doJSONRequest(ctx, "GET", url, nil, &user); err != nil {
		return nil, fmt.Errorf("fetching user data: %w", err)
	}

	var addresses []Address
	if user.Email != "" && isValidEmail(user.Email) {
		addresses = append(addresses, Address{
			Email:    user.Email,
			Name:     user.Name,
			Verified: false,
			Methods:  []string{methodPublicAPI},
		})
		lu.logger.Debug("found address via public API",
			"address", user.Email,
			"verified", false,
		)
	}

	return addresses, nil
}

// lookupViaCommits examines recent commits by the user in the organization using GitHub search API.
func (lu *Lookup) lookupViaCommits(ctx context.Context, username, organization string) ([]Address, error) {
	lu.logger.Debug("trying commits method",
		"username", username,
		"organization", organization,
	)

	// Use GitHub search commits API to find user's commits in the organization directly
	// This is much more efficient than searching repos first then querying each repo
	searchURL := fmt.Sprintf("https://api.github.com/search/commits?q=org:%s+author:%s&sort=committer-date&order=desc&per_page=100",
		organization, username)

	var searchResult struct {
		Items []struct {
			Commit struct {
				Author struct {
					Email string `json:"email"`
					Name  string `json:"name"`
				} `json:"author"`
			} `json:"commit"`
			Repository struct {
				Name string `json:"name"`
			} `json:"repository"`
		} `json:"items"`
	}

	if err := lu.doJSONRequestWithAccept(ctx, "GET", searchURL, http.NoBody, &searchResult, "application/vnd.github.cloak-preview"); err != nil {
		return nil, fmt.Errorf("searching commits: %w", err)
	}

	addressMap := make(map[string]bool)
	var addresses []Address

	// Process found commits
	for _, item := range searchResult.Items {
		email := item.Commit.Author.Email
		name := item.Commit.Author.Name
		if email != "" && !addressMap[email] && isValidEmail(email) {
			addressMap[email] = true
			addresses = append(addresses, Address{
				Email:    email,
				Name:     name,
				Verified: false,
				Methods:  []string{methodCommits},
			})
			lu.logger.Debug("found address via commits",
				"address", email,
				"repo", item.Repository.Name,
				"verified", false,
			)
		}
	}

	return addresses, nil
}

// lookupViaSAMLIdentity uses GraphQL to find SAML identity email.
func (lu *Lookup) lookupViaSAMLIdentity(ctx context.Context, username, organization string) ([]Address, error) {
	lu.logger.Debug("trying SAML identity method",
		"username", username,
		"organization", organization,
	)

	src := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: lu.token},
	)
	httpClient := oauth2.NewClient(ctx, src)
	client := githubv4.NewClient(httpClient)

	var query struct {
		Organization struct {
			SamlIdentityProvider struct {
				ExternalIdentities struct {
					Nodes []struct {
						User struct {
							Login string
							Name  string
						}
						SamlIdentity struct {
							NameID string
						}
					}
				} `graphql:"externalIdentities(first: $limit, login: $username)"`
			}
		} `graphql:"organization(login: $org)"`
	}

	variables := map[string]any{
		"org":      githubv4.String(organization),
		"username": githubv4.String(username),
		"limit":    githubv4.Int(100),
	}

	err := client.Query(ctx, &query, variables)
	if err != nil {
		return nil, err
	}

	// Log the raw GraphQL response
	lu.logger.Debug("raw GraphQL response - SAML identity",
		"username", username,
		"organization", organization,
		"query_result", fmt.Sprintf("%+v", query),
	)

	var addresses []Address
	for _, node := range query.Organization.SamlIdentityProvider.ExternalIdentities.Nodes {
		if node.User.Login == username && isValidEmail(node.SamlIdentity.NameID) {
			addresses = append(addresses, Address{
				Email:    node.SamlIdentity.NameID,
				Name:     node.User.Name,
				Verified: true,
				Methods:  []string{methodSAMLIdentity},
			})
			lu.logger.Debug("found address via SAML identity",
				"address", node.SamlIdentity.NameID,
				"verified", true,
			)
		}
	}

	return addresses, nil
}

// lookupViaOrgVerifiedDomains uses GraphQL to find organization verified domain emails.
func (lu *Lookup) lookupViaOrgVerifiedDomains(ctx context.Context, username, organization string) ([]Address, error) {
	lu.logger.Debug("trying org verified domains method",
		"username", username,
		"organization", organization,
	)

	src := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: lu.token},
	)
	httpClient := oauth2.NewClient(ctx, src)
	client := githubv4.NewClient(httpClient)

	var query struct {
		User struct {
			Name                             string   `graphql:"name"`
			OrganizationVerifiedDomainEmails []string `graphql:"organizationVerifiedDomainEmails(login: $org)"`
		} `graphql:"user(login: $username)"`
	}

	variables := map[string]any{
		"username": githubv4.String(username),
		"org":      githubv4.String(organization),
	}

	err := client.Query(ctx, &query, variables)
	if err != nil {
		return nil, err
	}

	// Log the raw GraphQL response
	lu.logger.Debug("raw GraphQL response - org verified domains",
		"username", username,
		"organization", organization,
		"query_result", fmt.Sprintf("%+v", query),
	)

	var addresses []Address
	for _, email := range query.User.OrganizationVerifiedDomainEmails {
		if isValidEmail(email) {
			addresses = append(addresses, Address{
				Email:    email,
				Name:     query.User.Name,
				Verified: true,
				Methods:  []string{methodOrgDomains},
			})
			lu.logger.Debug("found address via org verified domains",
				"address", email,
				"verified", true,
			)
		}
	}

	return addresses, nil
}

// lookupViaOrgMembers lists organization members and checks if we can get their emails.
func (lu *Lookup) lookupViaOrgMembers(ctx context.Context, username, organization string) ([]Address, error) {
	lu.logger.Debug("trying org members method",
		"username", username,
		"organization", organization,
	)

	// This requires admin access to the org
	// First check if user is a member
	memberURL := fmt.Sprintf("https://api.github.com/orgs/%s/members/%s", organization, username)
	resp, err := lu.doRequest(ctx, "GET", memberURL, nil)
	if err != nil {
		return nil, fmt.Errorf("checking membership: %w", err)
	}
	_ = resp.Body.Close() //nolint:errcheck // Best effort cleanup

	// If user is not a member, skip
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	// Try to get member details with email
	membersURL := fmt.Sprintf("https://api.github.com/orgs/%s/members", organization)
	var members []struct {
		Login string `json:"login"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}

	if err := lu.doJSONRequest(ctx, "GET", membersURL, nil, &members); err != nil {
		return nil, fmt.Errorf("fetching members: %w", err)
	}

	var addresses []Address
	for _, member := range members {
		if member.Login == username && member.Email != "" && isValidEmail(member.Email) {
			addresses = append(addresses, Address{
				Email:    member.Email,
				Name:     member.Name,
				Verified: false,
				Methods:  []string{methodOrgMembers},
			})
			lu.logger.Debug("found address via org members",
				"address", member.Email,
				"verified", false,
			)
		}
	}

	return addresses, nil
}
