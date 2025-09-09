package ghmailto

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

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
	lu.logger.Debug("starting public API lookup", "username", username)

	var user struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}

	apiURL := fmt.Sprintf("https://api.github.com/users/%s", url.PathEscape(username))
	lu.logger.Debug("making public API request", "url", apiURL)
	if err := lu.doJSONRequestWithAccept(ctx, "GET", apiURL, nil, &user, "application/vnd.github.v3+json"); err != nil {
		lu.logger.Warn("public API request failed", "error", err, "username", username)
		return nil, fmt.Errorf("fetching user data: %w", err)
	}

	lu.logger.Debug("GitHub profile API response", "username", username, "name", user.Name, "email", user.Email)

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
			"name", user.Name,
			"verified", false,
		)
	} else {
		lu.logger.Debug("no valid email found in public API", "email", user.Email, "username", username)

		// Even if no email, capture the name for guessing purposes
		if user.Name != "" {
			addresses = append(addresses, Address{
				Email:    "", // No email, but we have name data
				Name:     user.Name,
				Verified: false,
				Methods:  []string{methodPublicAPI},
			})
		}
	}

	return addresses, nil
}

// lookupViaCommits examines recent commits by the user using GitHub search API.
// It searches both by author and by specific email addresses to find historical commits.
func (lu *Lookup) lookupViaCommits(ctx context.Context, username, organization string) ([]Address, error) {
	lu.logger.Debug("starting commits lookup",
		"username", username,
		"organization", organization,
	)

	// Build search query - prefer org-specific search but fall back to user search
	var searchURL string
	if organization != "" {
		// Use GitHub search commits API to find user's commits in the organization directly
		searchURL = fmt.Sprintf("https://api.github.com/search/commits?q=org:%s+author:%s&sort=committer-date&order=desc&per_page=100",
			url.QueryEscape(organization), url.QueryEscape(username))
	} else {
		// Search user's public commits across all repositories
		searchURL = fmt.Sprintf("https://api.github.com/search/commits?q=author:%s&sort=committer-date&order=desc&per_page=100",
			url.QueryEscape(username))
	}

	var searchResult struct {
		Items []struct {
			Commit struct {
				Author struct {
					Email string `json:"email"`
					Name  string `json:"name"`
					Date  string `json:"date"`
				} `json:"author"`
				Message string `json:"message"`
			} `json:"commit"`
			Repository struct {
				Name string `json:"name"`
			} `json:"repository"`
		} `json:"items"`
	}

	lu.logger.Debug("making commits search request", "url", searchURL)
	if err := lu.doJSONRequestWithAccept(ctx, "GET", searchURL, http.NoBody, &searchResult, "application/vnd.github.cloak-preview"); err != nil {
		lu.logger.Warn("commits search failed", "error", err, "username", username, "organization", organization)
		return nil, fmt.Errorf("searching commits: %w", err)
	}

	// Track the most recent commit date for each email address
	emailToMostRecent := make(map[string]time.Time)
	emailToName := make(map[string]string)

	// Clear and populate commit messages for validation
	lu.commitMessages = make([]string, 0, len(searchResult.Items))

	// Clear and populate commit emails for validation
	lu.recentCommitEmails = make(map[string]bool)

	lu.logger.Debug("processing commit search results", "found_commits", len(searchResult.Items))

	// Process found commits to find the most recent date for each email
	for _, item := range searchResult.Items {
		email := item.Commit.Author.Email
		name := item.Commit.Author.Name
		dateStr := item.Commit.Author.Date
		message := item.Commit.Message

		// Store commit message for later validation
		if message != "" {
			lu.commitMessages = append(lu.commitMessages, message)
		}

		// Store commit author email for later validation
		if email != "" && isValidEmail(email) {
			lu.recentCommitEmails[email] = true
		}

		if email == "" || !isValidEmail(email) {
			continue
		}

		// Parse the commit date
		commitDate, err := time.Parse(time.RFC3339, dateStr)
		if err != nil {
			lu.logger.Debug("failed to parse commit date", "date", dateStr, "error", err)
			continue
		}

		// Track the most recent commit date for this email
		if existingDate, exists := emailToMostRecent[email]; !exists || commitDate.After(existingDate) {
			emailToMostRecent[email] = commitDate
			emailToName[email] = name
		}
	}

	// Create addresses with age-adjusted confidence
	var addresses []Address
	for email, mostRecentDate := range emailToMostRecent {
		// Calculate age in months
		monthsOld := int(time.Since(mostRecentDate).Hours() / (24 * 30))

		addresses = append(addresses, Address{
			Email:    email,
			Name:     emailToName[email],
			Verified: false,
			Methods:  []string{methodCommits},
			// Store the age in months as metadata for confidence calculation
			Sources: map[string]string{
				"commits_age_months": strconv.Itoa(monthsOld),
			},
		})

		lu.logger.Debug("found address via commits",
			"address", email,
			"name", emailToName[email],
			"most_recent_commit", mostRecentDate.Format("2006-01-02"),
			"age_months", monthsOld,
			"verified", false,
		)
	}

	return addresses, nil
}

// lookupViaSAMLIdentity uses GraphQL to find SAML identity email.
func (lu *Lookup) lookupViaSAMLIdentity(ctx context.Context, username, organization string) ([]Address, error) {
	lu.logger.Debug("starting SAML identity lookup",
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

	// Log response metadata only - never log detailed response for security
	lu.logger.Debug("SAML identity query completed",
		"username", username,
		"organization", organization,
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

	// Log response metadata only - never log detailed response for security
	lu.logger.Debug("org verified domains query completed",
		"username", username,
		"organization", organization,
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
	memberURL := fmt.Sprintf("https://api.github.com/orgs/%s/members/%s", url.PathEscape(organization), url.PathEscape(username))
	resp, err := lu.doRequestWithAccept(ctx, "GET", memberURL, nil, "application/vnd.github.v3+json")
	if err != nil {
		return nil, fmt.Errorf("checking membership: %w", err)
	}
	_ = resp.Body.Close() //nolint:errcheck // Best effort cleanup

	// If user is not a member, skip
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	// Try to get member details with email
	membersURL := fmt.Sprintf("https://api.github.com/orgs/%s/members", url.PathEscape(organization))
	var members []struct {
		Login string `json:"login"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}

	if err := lu.doJSONRequestWithAccept(ctx, "GET", membersURL, nil, &members, "application/vnd.github.v3+json"); err != nil {
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

// searchEmailInCommits searches for a specific email address in commit history using GitHub search API.
// Returns true if the email is found in any commits related to the user (authored by them, mention their username, or mention their last name).
// GitHub's search API finds the email anywhere in the commit (message, patch, etc.), not just in author metadata.
// Also returns organization information for found commits.
func (lu *Lookup) searchEmailInCommits(ctx context.Context, email string) (found bool, orgs []string) {
	// Use GitHub search API to find commits containing the specific email (quoted to prevent GitHub interpretation)
	searchURL := fmt.Sprintf("https://api.github.com/search/commits?q=%s&per_page=5",
		url.QueryEscape(`"`+email+`"`))

	var searchResult struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			Repository struct {
				Name  string `json:"name"`
				Owner struct {
					Login string `json:"login"`
				} `json:"owner"`
			} `json:"repository"`
			Commit struct {
				Author struct {
					Email string `json:"email"`
					Name  string `json:"name"`
				} `json:"author"`
				Committer struct {
					Email string `json:"email"`
					Name  string `json:"name"`
				} `json:"committer"`
				Message string `json:"message"`
			} `json:"commit"`
			Author struct {
				Login string `json:"login"`
			} `json:"author"`
		} `json:"items"`
	}

	lu.logger.Debug("searching for email in commits", "email", email, "url", searchURL)

	if err := lu.doJSONRequestWithAccept(ctx, "GET", searchURL, nil, &searchResult, "application/vnd.github.cloak-preview"); err != nil {
		lu.logger.Debug("commit search failed", "email", email, "error", err)
		return false, nil
	}

	// Search for commits related to the user
	var foundOrgs []string
	orgsSeen := make(map[string]bool)

	for _, item := range searchResult.Items {
		// Collect organization info
		orgName := item.Repository.Owner.Login
		if orgName != "" && !orgsSeen[orgName] {
			foundOrgs = append(foundOrgs, orgName)
			orgsSeen[orgName] = true
		}

		// GitHub search finds commits containing the email anywhere (message, patch, etc.)
		// We just need to validate that this commit is related to the user we're looking up
		if lu.isCommitRelatedToUser(item, email) {
			lu.logger.Debug("commit search completed", "email", email, "found", true,
				"total_count", searchResult.TotalCount, "user_related", true, "orgs", foundOrgs)
			return true, foundOrgs
		}
		lu.logger.Debug("commit found but not related to user", "email", email,
			"commit_author", item.Commit.Author.Name, "github_author", item.Author.Login, "repository", orgName+"/"+item.Repository.Name)
	}

	// No user-related commits found
	lu.logger.Debug("commit search completed", "email", email, "found", false,
		"total_count", searchResult.TotalCount,
		"reason", "no user-related commits found")

	return false, foundOrgs
}

// isCommitRelatedToUser checks if a commit is related to the user we're looking up.
// It validates that the commit is either:
// 1. Authored by the GitHub user directly.
// 2. Contains the user's GitHub username in the commit message.
// 3. Contains the user's last name (from known names) in the commit message or author name.
func (lu *Lookup) isCommitRelatedToUser(item struct {
	Repository struct {
		Name  string `json:"name"`
		Owner struct {
			Login string `json:"login"`
		} `json:"owner"`
	} `json:"repository"`
	Commit struct {
		Author struct {
			Email string `json:"email"`
			Name  string `json:"name"`
		} `json:"author"`
		Committer struct {
			Email string `json:"email"`
			Name  string `json:"name"`
		} `json:"committer"`
		Message string `json:"message"`
	} `json:"commit"`
	Author struct {
		Login string `json:"login"`
	} `json:"author"`
}, email string,
) bool {
	// Check 1: Is the commit authored by the GitHub user?
	if item.Author.Login == lu.currentUsername {
		lu.logger.Debug("commit related to user via GitHub authorship",
			"email", email, "github_author", item.Author.Login)
		return true
	}

	// Check 1.5: Does the email prefix match the GitHub username?
	// This handles cases like tstromberg@google.com for user tstromberg
	emailPrefix := strings.Split(email, "@")[0]
	if strings.EqualFold(emailPrefix, lu.currentUsername) {
		lu.logger.Debug("commit related to user via email prefix matching username",
			"email", email, "email_prefix", emailPrefix, "username", lu.currentUsername)
		return true
	}

	// Check 2: Does the commit message mention the user's GitHub username?
	message := strings.ToLower(item.Commit.Message)
	username := strings.ToLower(lu.currentUsername)
	if strings.Contains(message, username) {
		lu.logger.Debug("commit related to user via username mention in message",
			"email", email, "username", lu.currentUsername)
		return true
	}

	// Check 3: Does the commit contain the user's last name?
	for _, name := range lu.currentUserNames {
		if name == "" {
			continue
		}

		// Extract last name (assume space-separated names, take the last part)
		nameParts := strings.Fields(name)
		if len(nameParts) > 1 {
			lastName := strings.ToLower(nameParts[len(nameParts)-1])

			// Check if last name appears in commit author name
			authorName := strings.ToLower(item.Commit.Author.Name)
			if strings.Contains(authorName, lastName) {
				lu.logger.Debug("commit related to user via last name in author",
					"email", email, "last_name", lastName, "commit_author", item.Commit.Author.Name)
				return true
			}

			// Check if last name appears in commit message
			if strings.Contains(message, lastName) {
				lu.logger.Debug("commit related to user via last name in message",
					"email", email, "last_name", lastName)
				return true
			}
		}
	}

	// No relation found
	lu.logger.Debug("commit not related to user",
		"email", email,
		"commit_author", item.Commit.Author.Name,
		"github_author", item.Author.Login,
		"expected_username", lu.currentUsername,
		"expected_names", lu.currentUserNames)
	return false
}
