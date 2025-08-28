package ghmailaddr

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

	// usernameKey is the common key for username in GraphQL variables.
	usernameKey = "username"
)

// lookupViaPublicAPI uses the GitHub REST API to find public email addresses.
func (lu *Lookup) lookupViaPublicAPI(ctx context.Context, username, _ string) ([]Address, error) {
	lu.logger.Debug("trying public API method", "username", username)

	var user struct {
		Email string `json:"email"`
	}

	url := fmt.Sprintf("https://api.github.com/users/%s", username)
	if err := lu.doJSONRequest(ctx, "GET", url, nil, &user); err != nil {
		return nil, fmt.Errorf("fetching user data: %w", err)
	}

	var addresses []Address
	if user.Email != "" && isValidEmail(user.Email) {
		addresses = append(addresses, Address{
			Email:    user.Email,
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

// lookupViaCommits examines recent commits by the user in the organization.
func (lu *Lookup) lookupViaCommits(ctx context.Context, username, organization string) ([]Address, error) {
	lu.logger.Debug("trying commits method",
		"username", username,
		"organization", organization,
	)

	// Search for repos in the organization
	searchURL := fmt.Sprintf("https://api.github.com/search/repositories?q=org:%s&sort=updated&per_page=%d",
		organization, maxReposToSearch)

	var searchResult struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}

	if err := lu.doJSONRequest(ctx, "GET", searchURL, nil, &searchResult); err != nil {
		return nil, fmt.Errorf("searching repositories: %w", err)
	}

	addressMap := make(map[string]bool)
	var addresses []Address

	// Check commits in each repo
	for _, repo := range searchResult.Items {
		commitsURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits?author=%s&per_page=%d",
			organization, repo.Name, username, maxCommitsPerRepo)

		var commits []struct {
			Commit struct {
				Author struct {
					Email string `json:"email"`
				} `json:"author"`
			} `json:"commit"`
		}

		if err := lu.doJSONRequest(ctx, "GET", commitsURL, nil, &commits); err != nil {
			lu.logger.Debug("failed to fetch commits",
				"repo", repo.Name,
				"error", err,
			)
			continue
		}

		for _, commit := range commits {
			email := commit.Commit.Author.Email
			if email != "" && !addressMap[email] && isValidEmail(email) {
				addressMap[email] = true
				addresses = append(addresses, Address{
					Email:    email,
					Verified: false,
					Methods:  []string{methodCommits},
				})
				lu.logger.Debug("found address via commits",
					"address", email,
					"repo", repo.Name,
					"verified", false,
				)
			}
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
		"org":       githubv4.String(organization),
		usernameKey: githubv4.String(username),
		"limit":     githubv4.Int(maxSAMLIdentities),
	}

	err := client.Query(ctx, &query, variables)
	if err != nil {
		return nil, err
	}

	var addresses []Address
	for _, node := range query.Organization.SamlIdentityProvider.ExternalIdentities.Nodes {
		if node.User.Login == username && isValidEmail(node.SamlIdentity.NameID) {
			addresses = append(addresses, Address{
				Email:    node.SamlIdentity.NameID,
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
			OrganizationVerifiedDomainEmails []string `graphql:"organizationVerifiedDomainEmails(login: $org)"`
		} `graphql:"user(login: $username)"`
	}

	variables := map[string]any{
		usernameKey: githubv4.String(username),
		"org":       githubv4.String(organization),
	}

	err := client.Query(ctx, &query, variables)
	if err != nil {
		return nil, err
	}

	var addresses []Address
	for _, email := range query.User.OrganizationVerifiedDomainEmails {
		if isValidEmail(email) {
			addresses = append(addresses, Address{
				Email:    email,
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
	}

	if err := lu.doJSONRequest(ctx, "GET", membersURL, nil, &members); err != nil {
		return nil, fmt.Errorf("fetching members: %w", err)
	}

	var addresses []Address
	for _, member := range members {
		if member.Login == username && member.Email != "" && isValidEmail(member.Email) {
			addresses = append(addresses, Address{
				Email:    member.Email,
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
