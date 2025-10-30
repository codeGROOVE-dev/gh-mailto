package ghmailto

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"sync"
	"time"
)

// OrgIdentityCache caches all user identities for an organization.
// This enables efficient bidirectional lookups (GitHub ↔ Email).
type OrgIdentityCache struct {
	Organization     string
	CachedAt         time.Time
	Identities       []OrgIdentity
	EmailToGitHub    map[string]string // Normalized email → GitHub username
	GitHubToEmail    map[string]string // GitHub username → primary email
	TotalMembers     int
	SAMLCount        int
	VerifiedCount    int
	PublicEmailCount int
}

// OrgIdentity represents a single user's identity in the organization.
type OrgIdentity struct {
	GitHubUsername string
	Emails         []string
	PrimaryEmail   string
	Source         string // "saml", "verified_domain", "public_profile", "org_member"
	Verified       bool
}

// OrgCacheService manages organization-wide identity caches.
type OrgCacheService struct {
	mu     sync.RWMutex
	caches map[string]*OrgIdentityCache // org → cache
	lookup *Lookup
	ttl    time.Duration
}

// NewOrgCacheService creates a new org cache service.
func NewOrgCacheService(githubToken string) *OrgCacheService {
	return &OrgCacheService{
		caches: make(map[string]*OrgIdentityCache),
		lookup: New(githubToken),
		ttl:    24 * time.Hour, // Cache for 24 hours
	}
}

// OrgCache retrieves or builds the identity cache for an organization.
func (s *OrgCacheService) OrgCache(ctx context.Context, organization string) (*OrgIdentityCache, error) {
	// Check cache first
	s.mu.RLock()
	if cache, exists := s.caches[organization]; exists {
		if time.Since(cache.CachedAt) < s.ttl {
			s.mu.RUnlock()
			slog.Debug("using cached org identities",
				"org", organization,
				"total_identities", len(cache.Identities),
				"age_hours", time.Since(cache.CachedAt).Hours())
			return cache, nil
		}
	}
	s.mu.RUnlock()

	// Build cache
	slog.Info("building org identity cache",
		"org", organization)

	cache, err := s.buildOrgCache(ctx, organization)
	if err != nil {
		return nil, fmt.Errorf("failed to build org cache: %w", err)
	}

	// Store in cache
	s.mu.Lock()
	s.caches[organization] = cache
	s.mu.Unlock()

	slog.Info("org identity cache built",
		"org", organization,
		"total_identities", len(cache.Identities),
		"saml_count", cache.SAMLCount,
		"verified_count", cache.VerifiedCount,
		"public_email_count", cache.PublicEmailCount)

	return cache, nil
}

// buildOrgCache builds the complete identity cache for an organization.
func (s *OrgCacheService) buildOrgCache(ctx context.Context, organization string) (*OrgIdentityCache, error) {
	cache := &OrgIdentityCache{
		Organization:  organization,
		CachedAt:      time.Now(),
		EmailToGitHub: make(map[string]string),
		GitHubToEmail: make(map[string]string),
	}

	// Step 1: Get all SAML identities (highest confidence)
	slog.Info("searching for SAML identities", "org", organization)
	samlIdentities, err := s.fetchAllSAMLIdentities(ctx, organization)
	if err != nil {
		slog.Warn("failed to fetch SAML identities", "org", organization, "error", err)
	} else {
		cache.Identities = append(cache.Identities, samlIdentities...)
		cache.SAMLCount = len(samlIdentities)
		slog.Info("SAML identity search complete", "org", organization, "found", len(samlIdentities))
	}

	// Step 2: Get all verified domain emails (high confidence)
	slog.Info("searching for verified domain emails", "org", organization)
	verifiedIdentities, err := s.fetchAllVerifiedDomainIdentities(ctx, organization)
	if err != nil {
		slog.Warn("failed to fetch verified domain identities", "org", organization, "error", err)
	} else {
		cache.Identities = append(cache.Identities, verifiedIdentities...)
		cache.VerifiedCount = len(verifiedIdentities)
		slog.Info("verified domain search complete", "org", organization, "found", len(verifiedIdentities))
	}

	// Step 3: Get public emails for all org members (fallback)
	slog.Info("searching for public profile emails", "org", organization)
	publicIdentities, err := s.fetchAllMemberPublicEmails(ctx, organization)
	if err != nil {
		slog.Warn("failed to fetch member public emails", "org", organization, "error", err)
	} else {
		cache.Identities = append(cache.Identities, publicIdentities...)
		cache.PublicEmailCount = len(publicIdentities)
		slog.Info("public profile search complete", "org", organization, "found", len(publicIdentities))
	}

	cache.TotalMembers = len(cache.Identities)

	// Build bidirectional indexes
	for i := range cache.Identities {
		identity := &cache.Identities[i]

		// GitHub → Email (use primary email)
		if identity.PrimaryEmail != "" {
			cache.GitHubToEmail[identity.GitHubUsername] = identity.PrimaryEmail
		}

		// Email → GitHub (normalize emails)
		for _, email := range identity.Emails {
			normalized := normalizeEmail(email)
			// Prefer SAML/verified sources over public profiles
			if _, exists := cache.EmailToGitHub[normalized]; exists {
				// Keep existing if it's from a better source
				continue
			}
			cache.EmailToGitHub[normalized] = identity.GitHubUsername
		}
	}

	return cache, nil
}

// fetchAllSAMLIdentities fetches all SAML identities for the organization.
func (s *OrgCacheService) fetchAllSAMLIdentities(ctx context.Context, organization string) ([]OrgIdentity, error) {
	var identities []OrgIdentity
	var cursor *string

	graphqlURL := fmt.Sprintf("%s/graphql", s.lookup.baseURL)

	for {
		// Build GraphQL query string directly
		graphqlQuery := `
query($org: String!, $cursor: String) {
  organization(login: $org) {
    samlIdentityProvider {
      externalIdentities(first: 100, after: $cursor) {
        nodes {
          user {
            login
            name
          }
          samlIdentity {
            nameId
          }
        }
        pageInfo {
          hasNextPage
          endCursor
        }
      }
    }
  }
}`

		// Prepare GraphQL request payload
		payload := map[string]any{
			"query": graphqlQuery,
			"variables": map[string]any{
				"org":    organization,
				"cursor": cursor,
			},
		}

		// Execute GraphQL request
		var response struct {
			Data struct {
				Organization struct {
					SamlIdentityProvider struct {
						ExternalIdentities struct {
							Nodes []struct {
								User struct {
									Login string `json:"login"`
									Name  string `json:"name"`
								} `json:"user"`
								SamlIdentity struct {
									NameID string `json:"nameId"`
								} `json:"samlIdentity"`
							} `json:"nodes"`
							PageInfo struct {
								HasNextPage bool   `json:"hasNextPage"`
								EndCursor   string `json:"endCursor"`
							} `json:"pageInfo"`
						} `json:"externalIdentities"`
					} `json:"samlIdentityProvider"`
				} `json:"organization"`
			} `json:"data"`
			Errors []struct {
				Message string `json:"message"`
			} `json:"errors"`
		}

		err := s.lookup.doJSONPost(ctx, graphqlURL, payload, &response)
		if err != nil {
			return identities, err
		}

		if len(response.Errors) > 0 {
			return identities, fmt.Errorf("GraphQL errors: %v", response.Errors)
		}

		for _, node := range response.Data.Organization.SamlIdentityProvider.ExternalIdentities.Nodes {
			if node.SamlIdentity.NameID != "" && isValidEmail(node.SamlIdentity.NameID) {
				identities = append(identities, OrgIdentity{
					GitHubUsername: node.User.Login,
					Emails:         []string{node.SamlIdentity.NameID},
					PrimaryEmail:   node.SamlIdentity.NameID,
					Source:         "saml",
					Verified:       true,
				})
			}
		}

		if !response.Data.Organization.SamlIdentityProvider.ExternalIdentities.PageInfo.HasNextPage {
			break
		}
		endCursor := response.Data.Organization.SamlIdentityProvider.ExternalIdentities.PageInfo.EndCursor
		cursor = &endCursor
	}

	slog.Debug("fetched SAML identities",
		"org", organization,
		"count", len(identities))

	return identities, nil
}

// fetchAllVerifiedDomainIdentities fetches verified domain emails for all org members.
func (s *OrgCacheService) fetchAllVerifiedDomainIdentities(ctx context.Context, organization string) ([]OrgIdentity, error) {
	// First, get all org members
	members, err := s.fetchAllOrgMembers(ctx, organization)
	if err != nil {
		return nil, err
	}

	var identities []OrgIdentity
	graphqlURL := fmt.Sprintf("%s/graphql", s.lookup.baseURL)

	// Batch process members (GitHub allows up to 100 nodes in a single GraphQL query)
	batchSize := 50 // Conservative batch size
	for i := 0; i < len(members); i += batchSize {
		end := i + batchSize
		if end > len(members) {
			end = len(members)
		}
		batch := members[i:end]

		// Build GraphQL query with aliases for each user
		// This is complex, so we'll do individual queries for now (can optimize later)
		for _, username := range batch {
			// Build GraphQL query string directly
			graphqlQuery := `
query($username: String!, $org: String!) {
  user(login: $username) {
    login
    name
    organizationVerifiedDomainEmails(login: $org)
  }
}`

			// Prepare GraphQL request payload
			payload := map[string]any{
				"query": graphqlQuery,
				"variables": map[string]any{
					"username": username,
					"org":      organization,
				},
			}

			// Execute GraphQL request
			var response struct {
				Data struct {
					User struct {
						Login                            string   `json:"login"`
						Name                             string   `json:"name"`
						OrganizationVerifiedDomainEmails []string `json:"organizationVerifiedDomainEmails"`
					} `json:"user"`
				} `json:"data"`
				Errors []struct {
					Message string `json:"message"`
				} `json:"errors"`
			}

			err := s.lookup.doJSONPost(ctx, graphqlURL, payload, &response)
			if err != nil {
				slog.Debug("failed to fetch verified emails for user",
					"username", username,
					"error", err)
				continue
			}

			if len(response.Errors) > 0 {
				slog.Debug("GraphQL errors for user",
					"username", username,
					"errors", response.Errors)
				continue
			}

			if len(response.Data.User.OrganizationVerifiedDomainEmails) > 0 {
				identities = append(identities, OrgIdentity{
					GitHubUsername: username,
					Emails:         response.Data.User.OrganizationVerifiedDomainEmails,
					PrimaryEmail:   response.Data.User.OrganizationVerifiedDomainEmails[0],
					Source:         "verified_domain",
					Verified:       true,
				})
			}
		}
	}

	slog.Debug("fetched verified domain identities",
		"org", organization,
		"count", len(identities))

	return identities, nil
}

// fetchAllMemberPublicEmails fetches public emails for all org members.
func (s *OrgCacheService) fetchAllMemberPublicEmails(ctx context.Context, organization string) ([]OrgIdentity, error) {
	members, err := s.fetchAllOrgMembers(ctx, organization)
	if err != nil {
		return nil, err
	}

	var identities []OrgIdentity

	// Fetch public profile for each member
	for _, username := range members {
		var user struct {
			Email string `json:"email"`
			Name  string `json:"name"`
		}

		apiURL := fmt.Sprintf("%s/users/%s", s.lookup.baseURL, url.PathEscape(username))
		if err := s.lookup.doJSONRequestWithAccept(ctx, apiURL, nil, &user, "application/vnd.github.v3+json"); err != nil {
			slog.Debug("failed to fetch public profile for user",
				"username", username,
				"error", err)
			continue
		}

		if user.Email != "" && isValidEmail(user.Email) {
			identities = append(identities, OrgIdentity{
				GitHubUsername: username,
				Emails:         []string{user.Email},
				PrimaryEmail:   user.Email,
				Source:         "public_profile",
				Verified:       false,
			})
		}
	}

	slog.Debug("fetched public email identities",
		"org", organization,
		"count", len(identities))

	return identities, nil
}

// fetchAllOrgMembers fetches all member usernames for an organization.
func (s *OrgCacheService) fetchAllOrgMembers(ctx context.Context, organization string) ([]string, error) {
	var members []string
	page := 1
	perPage := 100

	for {
		membersURL := fmt.Sprintf("%s/orgs/%s/members?page=%d&per_page=%d",
			s.lookup.baseURL, url.PathEscape(organization), page, perPage)

		var pageMembers []struct {
			Login string `json:"login"`
		}

		if err := s.lookup.doJSONRequestWithAccept(ctx, membersURL, nil, &pageMembers, "application/vnd.github.v3+json"); err != nil {
			// Check if it's a 404 (org not found or no access)
			if err.Error() == "request failed: 404" {
				return nil, fmt.Errorf("organization not found or no access: %s", organization)
			}
			return nil, fmt.Errorf("fetching org members: %w", err)
		}

		if len(pageMembers) == 0 {
			break
		}

		for _, member := range pageMembers {
			members = append(members, member.Login)
		}

		// If we got fewer than perPage results, we're done
		if len(pageMembers) < perPage {
			break
		}

		page++
	}

	slog.Debug("fetched org members",
		"org", organization,
		"count", len(members))

	return members, nil
}

// InvalidateOrg clears the cache for a specific organization.
func (s *OrgCacheService) InvalidateOrg(organization string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.caches, organization)
	slog.Info("invalidated org identity cache", "org", organization)
}

// LookupUsername returns the GitHub username for an email address.
func (c *OrgIdentityCache) LookupUsername(email string) (string, bool) {
	normalized := normalizeEmail(email)
	username, exists := c.EmailToGitHub[normalized]
	return username, exists
}

// LookupEmail returns the primary email for a GitHub username.
func (c *OrgIdentityCache) LookupEmail(username string) (string, bool) {
	email, exists := c.GitHubToEmail[username]
	return email, exists
}
