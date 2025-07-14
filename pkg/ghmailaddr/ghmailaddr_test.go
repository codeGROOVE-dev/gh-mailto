package ghmailaddr

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

func TestIsValidEmail(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid email", "user@example.com", true},
		{"valid with subdomain", "test.user@sub.example.com", true},
		{"valid with plus", "user+tag@example.com", true},
		{"valid with dots", "first.last@example.com", true},
		{"invalid - no @", "invalid", false},
		{"invalid - no local", "@example.com", false},
		{"invalid - no domain", "user@", false},
		{"invalid - no TLD", "user@example", false},
		{"invalid - empty", "", false},
		{"invalid - noreply", "noreply@github.com", false},
		{"invalid - double dots", "user..name@example.com", false},
		{"invalid - starts with dot", ".user@example.com", false},
		{"invalid - ends with dot", "user.@example.com", false},
		{"invalid - space", "user name@example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidEmail(tt.input)
			if got != tt.want {
				t.Errorf("isValidEmail(%q) = %v, want %v", tt.input, got, tt.want)
			}
			// Test backward compatibility
			got2 := isEmail(tt.input)
			if got2 != tt.want {
				t.Errorf("isEmail(%q) = %v, want %v", tt.input, got2, tt.want)
			}
		})
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

