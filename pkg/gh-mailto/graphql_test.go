package ghmailto

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Comprehensive tests for GraphQL functions now that they use httptest

func TestSearchEmailInGitHubIssuesPRsComprehensive(t *testing.T) {
	tests := []struct {
		name           string
		email          string
		mockResponse   map[string]interface{}
		expectMatches  bool
		expectIssues   int
		expectPRs      int
	}{
		{
			name:  "email found in issues",
			email: "test@example.com",
			mockResponse: map[string]interface{}{
				"data": map[string]interface{}{
					"search": map[string]interface{}{
						"issueCount": 2,
						"edges": []map[string]interface{}{
							{
								"node": map[string]interface{}{
									"__typename": "Issue",
									"number":     123,
									"title":      "Bug with test@example.com",
									"body":       "Please contact test@example.com",
									"repository": map[string]interface{}{
										"name":  "repo1",
										"owner": map[string]interface{}{"login": "org1"},
									},
								},
							},
							{
								"node": map[string]interface{}{
									"__typename": "Issue",
									"number":     456,
									"title":      "Another issue",
									"body":       "Email: test@example.com",
									"repository": map[string]interface{}{
										"name":  "repo2",
										"owner": map[string]interface{}{"login": "org1"},
									},
								},
							},
						},
					},
				},
			},
			expectMatches: true,
			expectIssues:  2,
			expectPRs:     0,
		},
		{
			name:  "email found in PRs",
			email: "dev@example.com",
			mockResponse: map[string]interface{}{
				"data": map[string]interface{}{
					"search": map[string]interface{}{
						"issueCount": 1,
						"edges": []map[string]interface{}{
							{
								"node": map[string]interface{}{
									"__typename": "PullRequest",
									"number":     789,
									"title":      "Feature by dev@example.com",
									"body":       "Implemented by dev@example.com",
									"repository": map[string]interface{}{
										"name":  "repo3",
										"owner": map[string]interface{}{"login": "org2"},
									},
								},
							},
						},
					},
				},
			},
			expectMatches: true,
			expectIssues:  0,
			expectPRs:     1,
		},
		{
			name:  "no matches - email not in content",
			email: "notfound@example.com",
			mockResponse: map[string]interface{}{
				"data": map[string]interface{}{
					"search": map[string]interface{}{
						"issueCount": 1,
						"edges": []map[string]interface{}{
							{
								"node": map[string]interface{}{
									"__typename": "Issue",
									"number":     100,
									"title":      "Some issue",
									"body":       "No email here",
									"repository": map[string]interface{}{
										"name":  "repo",
										"owner": map[string]interface{}{"login": "org"},
									},
								},
							},
						},
					},
				},
			},
			expectMatches: false,
			expectIssues:  0,
			expectPRs:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-RateLimit-Remaining", "5000")

				if strings.Contains(r.URL.Path, "/graphql") {
					json.NewEncoder(w).Encode(tt.mockResponse)
				}
			}))
			defer server.Close()

			lookup := New("test-token", WithBaseURL(server.URL))
			lookup.currentUsername = "testuser"
			ctx := context.Background()

			guess := Address{
				Email:      tt.email,
				Confidence: 50,
			}

			result := lookup.searchEmailInGitHubIssuesPRs(ctx, guess)

			if tt.expectMatches {
				if result.Confidence <= guess.Confidence {
					t.Errorf("expected confidence boost, got %d", result.Confidence)
				}
			}
		})
	}
}

func TestExecuteBatchedGraphQLQueryMultipleEmails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-RateLimit-Remaining", "5000")

		if strings.Contains(r.URL.Path, "/graphql") {
			// Return results for multiple emails
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"search": map[string]interface{}{
						"issueCount": 3,
						"edges": []map[string]interface{}{
							{
								"node": map[string]interface{}{
									"__typename": "Issue",
									"number":     1,
									"title":      "Contains email1@example.com",
									"body":       "Email: email1@example.com",
									"repository": map[string]interface{}{
										"name":  "repo1",
										"owner": map[string]interface{}{"login": "org1"},
									},
								},
							},
							{
								"node": map[string]interface{}{
									"__typename": "PullRequest",
									"number":     2,
									"title":      "Contains email2@example.com",
									"body":       "By email2@example.com",
									"repository": map[string]interface{}{
										"name":  "repo2",
										"owner": map[string]interface{}{"login": "org1"},
									},
								},
							},
							{
								"node": map[string]interface{}{
									"__typename": "Issue",
									"number":     3,
									"title":      "Contains both",
									"body":       "email1@example.com and email2@example.com",
									"repository": map[string]interface{}{
										"name":  "repo3",
										"owner": map[string]interface{}{"login": "org1"},
									},
								},
							},
						},
					},
				},
			})
		}
	}))
	defer server.Close()

	lookup := New("test-token", WithBaseURL(server.URL))
	ctx := context.Background()

	emails := []string{"email1@example.com", "email2@example.com", "email3@example.com"}
	results := lookup.executeBatchedGraphQLQuery(ctx, "test query", emails)

	// Should find results for email1 and email2
	if len(results) < 2 {
		t.Errorf("expected at least 2 results, got %d", len(results))
	}

	// email1 should have matches
	if addr, ok := results["email1@example.com"]; ok {
		if addr.Confidence == 0 {
			t.Error("expected non-zero confidence for email1")
		}
	} else {
		t.Error("expected to find email1@example.com in results")
	}
}

func TestLookupViaSAMLIdentityWithMock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-RateLimit-Remaining", "5000")

		if strings.Contains(r.URL.Path, "/graphql") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"organization": map[string]interface{}{
						"samlIdentityProvider": map[string]interface{}{
							"externalIdentities": map[string]interface{}{
								"nodes": []map[string]interface{}{
									{
										"user": map[string]interface{}{
											"login": "testuser",
											"name":  "Test User",
										},
										"samlIdentity": map[string]interface{}{
											"nameId": "testuser@company.com",
										},
									},
								},
							},
						},
					},
				},
			})
		}
	}))
	defer server.Close()

	lookup := New("test-token", WithBaseURL(server.URL))
	ctx := context.Background()

	addresses, err := lookup.lookupViaSAMLIdentity(ctx, "testuser", "testorg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(addresses) != 1 {
		t.Fatalf("expected 1 address, got %d", len(addresses))
	}

	if addresses[0].Email != "testuser@company.com" {
		t.Errorf("expected testuser@company.com, got %s", addresses[0].Email)
	}

	if !addresses[0].Verified {
		t.Error("expected SAML address to be verified")
	}
}

func TestLookupViaOrgVerifiedDomainsWithMock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-RateLimit-Remaining", "5000")

		if strings.Contains(r.URL.Path, "/graphql") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"user": map[string]interface{}{
						"name": "Test User",
						"organizationVerifiedDomainEmails": []string{
							"test@verified.com",
							"test@company.com",
						},
					},
				},
			})
		}
	}))
	defer server.Close()

	lookup := New("test-token", WithBaseURL(server.URL))
	ctx := context.Background()

	addresses, err := lookup.lookupViaOrgVerifiedDomains(ctx, "testuser", "testorg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(addresses) != 2 {
		t.Fatalf("expected 2 addresses, got %d", len(addresses))
	}

	for _, addr := range addresses {
		if !addr.Verified {
			t.Error("expected verified domain addresses to be marked as verified")
		}
	}
}

func TestGraphQLErrorHandling(t *testing.T) {
	tests := []struct {
		name         string
		mockResponse map[string]interface{}
		expectError  bool
	}{
		{
			name: "GraphQL errors in response",
			mockResponse: map[string]interface{}{
				"errors": []map[string]interface{}{
					{"message": "Rate limit exceeded"},
				},
			},
			expectError: true,
		},
		{
			name: "HTTP 500 error",
			mockResponse: map[string]interface{}{
				"error": "Internal server error",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.name == "HTTP 500 error" {
					w.WriteHeader(http.StatusInternalServerError)
				} else {
					w.Header().Set("Content-Type", "application/json")
				}
				json.NewEncoder(w).Encode(tt.mockResponse)
			}))
			defer server.Close()

			lookup := New("test-token", WithBaseURL(server.URL))
			ctx := context.Background()

			_, err := lookup.lookupViaSAMLIdentity(ctx, "testuser", "testorg")
			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}
		})
	}
}

func TestDoJSONPostRetry(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			// Fail first 2 attempts
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		// Succeed on 3rd attempt
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"success": true,
			},
		})
	}))
	defer server.Close()

	lookup := New("test-token", WithBaseURL(server.URL))
	ctx := context.Background()

	payload := map[string]interface{}{
		"query": "test",
	}

	var result struct {
		Data struct {
			Success bool `json:"success"`
		} `json:"data"`
	}

	graphqlURL := server.URL + "/graphql"
	err := lookup.doJSONPost(ctx, graphqlURL, payload, &result)

	if err != nil {
		t.Fatalf("expected retry to succeed, got error: %v", err)
	}

	if attempts < 3 {
		t.Errorf("expected at least 3 attempts, got %d", attempts)
	}

	if !result.Data.Success {
		t.Error("expected successful response")
	}
}

func TestSearchEmailInGitHubShortPrefix(t *testing.T) {
	lookup := New("test-token")
	ctx := context.Background()

	// Test with very short email prefix (should be skipped)
	guess := Address{
		Email:      "a@example.com",
		Confidence: 50,
	}

	result := lookup.searchEmailInGitHub(ctx, guess)

	// Should return unchanged since prefix is too short
	if result.Confidence != guess.Confidence {
		t.Errorf("expected confidence unchanged for short prefix, got %d", result.Confidence)
	}
}

func TestIsCommitRelatedToUserVariations(t *testing.T) {
	lookup := New("test-token")
	lookup.currentUsername = "testuser"

	tests := []struct {
		name           string
		email          string
		commitMsg      string
		repoOwner      string
		repoName       string
		authorLogin    string
		expectRelated  bool
	}{
		{
			name:          "commit by current user",
			email:         "testuser@example.com",
			commitMsg:     "Fix bug",
			repoOwner:     "testuser",
			repoName:      "myrepo",
			authorLogin:   "testuser",
			expectRelated: true,
		},
		{
			name:          "signed-off by current user",
			email:         "user@example.com",
			commitMsg:     "Feature\n\nSigned-off-by: testuser <test@example.com>",
			repoOwner:     "otheruser",
			repoName:      "repo",
			authorLogin:   "otheruser",
			expectRelated: true,
		},
		{
			name:          "co-authored by current user",
			email:         "team@example.com",
			commitMsg:     "Collaboration\n\nCo-authored-by: testuser <test@example.com>",
			repoOwner:     "team",
			repoName:      "project",
			authorLogin:   "teammember",
			expectRelated: true,
		},
		{
			name:          "mentions current user",
			email:         "someone@example.com",
			commitMsg:     "Thanks to @testuser for the fix",
			repoOwner:     "someone",
			repoName:      "repo",
			authorLogin:   "someone",
			expectRelated: true,
		},
		{
			name:          "not related - different user entirely",
			email:         "stranger@different.com",
			commitMsg:     "Random commit about something else",
			repoOwner:     "stranger",
			repoName:      "strangerrepo",
			authorLogin:   "stranger",
			expectRelated: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			item := struct {
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
			}{
				Repository: struct {
					Name  string `json:"name"`
					Owner struct {
						Login string `json:"login"`
					} `json:"owner"`
				}{
					Name: tt.repoName,
					Owner: struct {
						Login string `json:"login"`
					}{
						Login: tt.repoOwner,
					},
				},
				Commit: struct {
					Author struct {
						Email string `json:"email"`
						Name  string `json:"name"`
					} `json:"author"`
					Committer struct {
						Email string `json:"email"`
						Name  string `json:"name"`
					} `json:"committer"`
					Message string `json:"message"`
				}{
					Message: tt.commitMsg,
				},
				Author: struct {
					Login string `json:"login"`
				}{
					Login: tt.authorLogin,
				},
			}

			related := lookup.isCommitRelatedToUser(item, tt.email)
			if related != tt.expectRelated {
				t.Errorf("expected %v, got %v for commit: %s (email: %s)", tt.expectRelated, related, tt.commitMsg, tt.email)
			}
		})
	}
}
