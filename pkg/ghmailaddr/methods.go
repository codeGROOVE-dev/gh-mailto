package ghmailaddr

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

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
func (l *Lookup) lookupViaPublicAPI(ctx context.Context, username, _ string) ([]Address, error) {
	l.logger.Debug("trying public API method", "username", username)

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.github.com/users/%s", username), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+l.token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var user struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}

	var addresses []Address
	if user.Email != "" {
		addresses = append(addresses, Address{
			Email:    user.Email,
			Verified: false,
			Methods:  []string{methodPublicAPI},
		})
		l.logger.Debug("found address via public API",
			"address", user.Email,
			"verified", false,
		)
	}

	return addresses, nil
}

// lookupViaCommits examines recent commits by the user in the organization.
func (l *Lookup) lookupViaCommits(ctx context.Context, username, organization string) ([]Address, error) {
	l.logger.Debug("trying commits method",
		"username", username,
		"organization", organization,
	)

	// Search for repos in the organization
	searchURL := fmt.Sprintf("https://api.github.com/search/repositories?q=org:%s&sort=updated&per_page=20", organization)
	req, err := http.NewRequestWithContext(ctx, "GET", searchURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+l.token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var searchResult struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&searchResult); err != nil {
		return nil, err
	}

	addressMap := make(map[string]bool)
	var addresses []Address

	// Check commits in each repo
	for _, repo := range searchResult.Items {
		commitsURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits?author=%s&per_page=10",
			organization, repo.Name, username)

		req, err := http.NewRequestWithContext(ctx, "GET", commitsURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer "+l.token)
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		var commits []struct {
			Commit struct {
				Author struct {
					Email string `json:"email"`
				} `json:"author"`
			} `json:"commit"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&commits); err != nil {
			continue
		}

		for _, commit := range commits {
			email := commit.Commit.Author.Email
			if email != "" && !addressMap[email] && !strings.Contains(email, "noreply.github.com") {
				addressMap[email] = true
				addresses = append(addresses, Address{
					Email:    email,
					Verified: false,
					Methods:  []string{methodCommits},
				})
				l.logger.Debug("found address via commits",
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
func (l *Lookup) lookupViaSAMLIdentity(ctx context.Context, username, organization string) ([]Address, error) {
	l.logger.Debug("trying SAML identity method",
		"username", username,
		"organization", organization,
	)

	src := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: l.token},
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
							NameId string
						}
					}
				} `graphql:"externalIdentities(first: 100, login: $username)"`
			}
		} `graphql:"organization(login: $org)"`
	}

	variables := map[string]interface{}{
		"org":      githubv4.String(organization),
		"username": githubv4.String(username),
	}

	err := client.Query(ctx, &query, variables)
	if err != nil {
		return nil, err
	}

	var addresses []Address
	for _, node := range query.Organization.SamlIdentityProvider.ExternalIdentities.Nodes {
		if node.User.Login == username && isEmail(node.SamlIdentity.NameId) {
			addresses = append(addresses, Address{
				Email:    node.SamlIdentity.NameId,
				Verified: true,
				Methods:  []string{methodSAMLIdentity},
			})
			l.logger.Debug("found address via SAML identity",
				"address", node.SamlIdentity.NameId,
				"verified", true,
			)
		}
	}

	return addresses, nil
}

// lookupViaOrgVerifiedDomains uses GraphQL to find organization verified domain emails.
func (l *Lookup) lookupViaOrgVerifiedDomains(ctx context.Context, username, organization string) ([]Address, error) {
	l.logger.Debug("trying org verified domains method",
		"username", username,
		"organization", organization,
	)

	src := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: l.token},
	)
	httpClient := oauth2.NewClient(ctx, src)
	client := githubv4.NewClient(httpClient)

	var query struct {
		User struct {
			OrganizationVerifiedDomainEmails []string `graphql:"organizationVerifiedDomainEmails(login: $org)"`
		} `graphql:"user(login: $username)"`
	}

	variables := map[string]interface{}{
		"username": githubv4.String(username),
		"org":      githubv4.String(organization),
	}

	err := client.Query(ctx, &query, variables)
	if err != nil {
		return nil, err
	}

	var addresses []Address
	for _, email := range query.User.OrganizationVerifiedDomainEmails {
		addresses = append(addresses, Address{
			Email:    email,
			Verified: true,
			Methods:  []string{methodOrgDomains},
		})
		l.logger.Debug("found address via org verified domains",
			"address", email,
			"verified", true,
		)
	}

	return addresses, nil
}

// lookupViaOrgMembers lists organization members and checks if we can get their emails.
func (l *Lookup) lookupViaOrgMembers(ctx context.Context, username, organization string) ([]Address, error) {
	l.logger.Debug("trying org members method",
		"username", username,
		"organization", organization,
	)

	// This requires admin access to the org
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("https://api.github.com/orgs/%s/members/%s", organization, username), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+l.token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// If user is not a member, skip
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	// Try to get member details with email
	req, err = http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("https://api.github.com/orgs/%s/members", organization), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+l.token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var members []struct {
		Login string `json:"login"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(body, &members); err != nil {
		return nil, err
	}

	var addresses []Address
	for _, member := range members {
		if member.Login == username && member.Email != "" {
			addresses = append(addresses, Address{
				Email:    member.Email,
				Verified: false,
				Methods:  []string{methodOrgMembers},
			})
			l.logger.Debug("found address via org members",
				"address", member.Email,
				"verified", false,
			)
		}
	}

	return addresses, nil
}

// isEmail performs basic email validation.
func isEmail(s string) bool {
	parts := strings.Split(s, "@")
	if len(parts) != 2 {
		return false
	}
	if len(parts[0]) == 0 || len(parts[1]) == 0 {
		return false
	}
	return strings.Contains(parts[1], ".")
}