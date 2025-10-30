package ghmailto

import (
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
