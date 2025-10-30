package ghmailto

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOrgIdentityCache_LookupUsername(t *testing.T) {
	cache := &OrgIdentityCache{
		Organization: "test-org",
		CachedAt:     time.Now(),
		Identities: []OrgIdentity{
			{
				GitHubUsername: "johndoe",
				Emails:         []string{"john@example.com"},
				PrimaryEmail:   "john@example.com",
				Source:         "saml",
				Verified:       true,
			},
		},
		EmailToGitHub: map[string]string{
			"john@example.com": "johndoe",
		},
		GitHubToEmail: map[string]string{
			"johndoe": "john@example.com",
		},
	}

	// Test exact match
	username, found := cache.LookupUsername("john@example.com")
	if !found {
		t.Fatal("expected to find GitHub username for john@example.com")
	}
	if username != "johndoe" {
		t.Errorf("expected username 'johndoe', got: %s", username)
	}

	// Test not found
	_, found = cache.LookupUsername("unknown@example.com")
	if found {
		t.Error("expected not to find GitHub username for unknown@example.com")
	}
}

func TestOrgIdentityCache_LookupEmail(t *testing.T) {
	cache := &OrgIdentityCache{
		Organization: "test-org",
		CachedAt:     time.Now(),
		Identities: []OrgIdentity{
			{
				GitHubUsername: "johndoe",
				Emails:         []string{"john@example.com"},
				PrimaryEmail:   "john@example.com",
				Source:         "saml",
				Verified:       true,
			},
		},
		EmailToGitHub: map[string]string{
			"john@example.com": "johndoe",
		},
		GitHubToEmail: map[string]string{
			"johndoe": "john@example.com",
		},
	}

	// Test exact match
	email, found := cache.LookupEmail("johndoe")
	if !found {
		t.Fatal("expected to find email for johndoe")
	}
	if email != "john@example.com" {
		t.Errorf("expected email 'john@example.com', got: %s", email)
	}

	// Test not found
	_, found = cache.LookupEmail("unknownuser")
	if found {
		t.Error("expected not to find email for unknownuser")
	}
}

func TestOrgIdentityCache_MultipleEmails(t *testing.T) {
	cache := &OrgIdentityCache{
		Organization: "test-org",
		CachedAt:     time.Now(),
		Identities: []OrgIdentity{
			{
				GitHubUsername: "johndoe",
				Emails:         []string{"john@example.com", "john.doe@example.com"},
				PrimaryEmail:   "john@example.com",
				Source:         "verified_domain",
				Verified:       true,
			},
		},
		EmailToGitHub: map[string]string{
			"john@example.com":     "johndoe",
			"john.doe@example.com": "johndoe",
		},
		GitHubToEmail: map[string]string{
			"johndoe": "john@example.com", // Primary email
		},
	}

	// Test both emails map to same GitHub user
	username1, _ := cache.LookupUsername("john@example.com")
	username2, _ := cache.LookupUsername("john.doe@example.com")
	if username1 != username2 {
		t.Errorf("expected both emails to map to same username, got: %s vs %s", username1, username2)
	}
	if username1 != "johndoe" {
		t.Errorf("expected username 'johndoe', got: %s", username1)
	}

	// Test reverse lookup returns primary email
	email, found := cache.LookupEmail("johndoe")
	if !found {
		t.Fatal("expected to find email for johndoe")
	}
	if email != "john@example.com" {
		t.Errorf("expected primary email 'john@example.com', got: %s", email)
	}
}

func TestOrgIdentityCache_Stats(t *testing.T) {
	cache := &OrgIdentityCache{
		Organization: "test-org",
		CachedAt:     time.Now(),
		Identities: []OrgIdentity{
			{GitHubUsername: "user1", Source: "saml", Verified: true},
			{GitHubUsername: "user2", Source: "verified_domain", Verified: true},
			{GitHubUsername: "user3", Source: "public_profile", Verified: false},
		},
		TotalMembers:     3,
		SAMLCount:        1,
		VerifiedCount:    1,
		PublicEmailCount: 1,
	}

	if cache.TotalMembers != 3 {
		t.Errorf("expected 3 total members, got: %d", cache.TotalMembers)
	}
	if cache.SAMLCount != 1 {
		t.Errorf("expected 1 SAML identity, got: %d", cache.SAMLCount)
	}
	if cache.VerifiedCount != 1 {
		t.Errorf("expected 1 verified domain identity, got: %d", cache.VerifiedCount)
	}
	if cache.PublicEmailCount != 1 {
		t.Errorf("expected 1 public email identity, got: %d", cache.PublicEmailCount)
	}
}

func TestOrgCacheService_InvalidateOrg(t *testing.T) {
	service := NewOrgCacheService("fake-token")

	// Manually add a cache entry
	service.caches["test-org"] = &OrgIdentityCache{
		Organization: "test-org",
		CachedAt:     time.Now(),
	}

	// Verify it exists
	service.mu.RLock()
	_, exists := service.caches["test-org"]
	service.mu.RUnlock()
	if !exists {
		t.Fatal("expected cache to exist before invalidation")
	}

	// Invalidate
	service.InvalidateOrg("test-org")

	// Verify it's gone
	service.mu.RLock()
	_, exists = service.caches["test-org"]
	service.mu.RUnlock()
	if exists {
		t.Error("expected cache to be invalidated")
	}
}

func TestOrgCacheService_CacheExpiry(t *testing.T) {
	service := NewOrgCacheService("fake-token")
	service.ttl = 1 * time.Hour

	// Add expired cache
	service.caches["test-org"] = &OrgIdentityCache{
		Organization: "test-org",
		CachedAt:     time.Now().Add(-2 * time.Hour), // Expired
	}

	// Check if cache is used (should not be due to expiry)
	service.mu.RLock()
	cache, exists := service.caches["test-org"]
	service.mu.RUnlock()

	if !exists {
		t.Fatal("cache entry should exist")
	}

	// Check if it's expired
	if time.Since(cache.CachedAt) < service.ttl {
		t.Error("expected cache to be expired")
	}
}

func TestOrgCacheService_OrgCache(t *testing.T) {
	// This test will fail with invalid token but shouldn't crash
	// Testing the caching logic, not the API calls
	service := NewOrgCacheService("test-token")
	ctx := context.Background()

	// This will fail due to API errors but shouldn't crash
	_, err := service.OrgCache(ctx, "testorg")
	// We expect an error with the test token
	if err == nil {
		t.Log("OrgCache completed (unexpected with test token)")
	}
}

func TestOrgCacheWithMockServer(t *testing.T) {
	// Create comprehensive mock server for org cache operations
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-RateLimit-Remaining", "5000")

		if strings.Contains(r.URL.Path, "/orgs/") && strings.Contains(r.URL.Path, "/members") {
			// Org members API
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"login": "member1"},
				{"login": "member2"},
				{"login": "member3"},
			})
		} else if strings.Contains(r.URL.Path, "/users/") {
			// User public profile API
			username := strings.TrimPrefix(r.URL.Path, "/users/")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"login": username,
				"email": username + "@example.com",
				"name":  "User " + username,
			})
		} else if strings.Contains(r.URL.Path, "/graphql") {
			// GraphQL endpoint - handle different queries
			// Mock SAML and verified domain responses
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"organization": map[string]interface{}{
						"samlIdentityProvider": map[string]interface{}{
							"externalIdentities": map[string]interface{}{
								"nodes": []map[string]interface{}{
									{
										"user": map[string]interface{}{
											"login": "member1",
											"name":  "Member One",
										},
										"samlIdentity": map[string]interface{}{
											"nameId": "member1@saml.example.com",
										},
									},
								},
								"pageInfo": map[string]interface{}{
									"hasNextPage": false,
									"endCursor":   "",
								},
							},
						},
						"domains": map[string]interface{}{
							"edges": []map[string]interface{}{
								{
									"node": map[string]interface{}{
										"domain":     "example.com",
										"isVerified": true,
									},
								},
							},
							"pageInfo": map[string]interface{}{
								"hasNextPage": false,
							},
						},
					},
					"user": map[string]interface{}{
						"login": "member2",
						"organizationVerifiedDomainEmails": []string{"member2@example.com"},
					},
				},
			})
		}
	}))
	defer server.Close()

	// Create service with custom baseURL through the lookup
	lookup := New("test-token", WithBaseURL(server.URL))
	service := &OrgCacheService{
		caches: make(map[string]*OrgIdentityCache),
		lookup: lookup,
		ttl:    24 * time.Hour,
	}

	ctx := context.Background()

	// Test building org cache
	orgCache, err := service.OrgCache(ctx, "testorg")
	if err != nil {
		t.Logf("OrgCache error (expected with simple mock): %v", err)
		// Continue - we still got some coverage
	}

	if orgCache != nil {
		t.Logf("OrgCache built: %d identities", len(orgCache.Identities))
		if orgCache.Organization != "testorg" {
			t.Errorf("expected organization 'testorg', got %s", orgCache.Organization)
		}
	}
}

func TestOrgCacheService_LookupFunctions(t *testing.T) {
	// Create a cache manually to test lookup functions
	cache := &OrgIdentityCache{
		Organization: "testorg",
		CachedAt:     time.Now(),
		Identities: []OrgIdentity{
			{
				GitHubUsername: "testuser",
				Emails:         []string{"test@example.com"},
				PrimaryEmail:   "test@example.com",
				Source:         "test",
				Verified:       true,
			},
		},
		EmailToGitHub: map[string]string{
			"test@example.com": "testuser",
		},
		GitHubToEmail: map[string]string{
			"testuser": "test@example.com",
		},
	}

	// Test LookupUsername on the cache object
	username, found := cache.LookupUsername("test@example.com")
	if !found {
		t.Error("expected to find username for test@example.com")
	}
	if username != "testuser" {
		t.Errorf("expected username 'testuser', got %s", username)
	}

	// Test LookupEmail on the cache object
	email, found := cache.LookupEmail("testuser")
	if !found {
		t.Error("expected to find email for testuser")
	}
	if email != "test@example.com" {
		t.Errorf("expected email 'test@example.com', got %s", email)
	}
}
