package ghmailaddr

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

func TestIsEmail(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"user@example.com", true},
		{"test.user@sub.example.com", true},
		{"invalid", false},
		{"@example.com", false},
		{"user@", false},
		{"user@example", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isEmail(tt.input)
			if got != tt.want {
				t.Errorf("isEmail(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestLookupOptions(t *testing.T) {
	customLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	
	lookup := New("test-token", WithLogger(customLogger))
	
	if lookup.token != "test-token" {
		t.Errorf("expected token test-token, got %s", lookup.token)
	}
	
	if lookup.logger != customLogger {
		t.Error("expected custom logger to be set")
	}
}

func TestAddressStructure(t *testing.T) {
	addr := Address{
		Email:    "test@example.com",
		Verified: true,
		Methods:  []string{"test_method"},
	}
	
	if addr.Email != "test@example.com" {
		t.Errorf("expected email test@example.com, got %s", addr.Email)
	}
	
	if !addr.Verified {
		t.Error("expected address to be verified")
	}
	
	if len(addr.Methods) != 1 || addr.Methods[0] != "test_method" {
		t.Errorf("expected methods [test_method], got %v", addr.Methods)
	}
}

func TestResultStructure(t *testing.T) {
	result := Result{
		Username: "testuser",
		Addresses: []Address{
			{
				Email:    "test1@example.com",
				Verified: true,
				Methods:  []string{"method1"},
			},
			{
				Email:    "test2@example.com",
				Verified: false,
				Methods:  []string{"method2"},
			},
		},
	}
	
	if result.Username != "testuser" {
		t.Errorf("expected username testuser, got %s", result.Username)
	}
	
	if len(result.Addresses) != 2 {
		t.Errorf("expected 2 addresses, got %d", len(result.Addresses))
	}
	
	if result.Addresses[0].Email != "test1@example.com" {
		t.Errorf("expected first email test1@example.com, got %s", result.Addresses[0].Email)
	}
	
	if !result.Addresses[0].Verified {
		t.Error("expected first address to be verified")
	}
	
	if result.Addresses[1].Verified {
		t.Error("expected second address to be unverified")
	}
}

func TestContextCancellation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	lookup := New("test-token", WithLogger(logger))
	
	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	
	// This should handle the cancelled context gracefully
	result, err := lookup.Lookup(ctx, "testuser", "testorg")
	
	// We expect it to return quickly with an empty result (methods will fail due to cancelled context)
	if err != nil {
		t.Logf("Got expected error from cancelled context: %v", err)
	}
	
	if result == nil {
		t.Error("expected non-nil result even with cancelled context")
	} else if result.Username != "testuser" {
		t.Errorf("expected username to be set to testuser, got %s", result.Username)
	}
}

func TestMethodConstants(t *testing.T) {
	// Test that method constants are defined
	methods := []string{
		methodPublicAPI,
		methodCommits,
		methodSAMLIdentity,
		methodOrgDomains,
		methodOrgMembers,
	}
	
	expected := []string{
		"public_api",
		"commits",
		"saml_identity",
		"org_verified_domains",
		"org_members",
	}
	
	for i, method := range methods {
		if method != expected[i] {
			t.Errorf("expected method constant %s, got %s", expected[i], method)
		}
	}
}