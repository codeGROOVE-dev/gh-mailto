package ghmailto

import (
	"testing"
)

func TestCommitsLimitOption(t *testing.T) {
	tests := []struct {
		name          string
		limit         int
		expectedLimit int
	}{
		{
			name:          "valid limit 20",
			limit:         20,
			expectedLimit: 20,
		},
		{
			name:          "valid limit 50",
			limit:         50,
			expectedLimit: 50,
		},
		{
			name:          "valid limit 100",
			limit:         100,
			expectedLimit: 100,
		},
		{
			name:          "invalid limit 0",
			limit:         0,
			expectedLimit: 100, // should default to 100
		},
		{
			name:          "invalid limit 200",
			limit:         200,
			expectedLimit: 100, // should default to 100
		},
		{
			name:          "invalid limit -10",
			limit:         -10,
			expectedLimit: 100, // should default to 100
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lookup := New("fake-token", WithCommitsLimit(tt.limit))
			if lookup.commitsLimit != tt.expectedLimit {
				t.Errorf("WithCommitsLimit(%d) = %d, want %d", tt.limit, lookup.commitsLimit, tt.expectedLimit)
			}
		})
	}
}

func TestDefaultCommitsLimit(t *testing.T) {
	lookup := New("fake-token")
	if lookup.commitsLimit != 100 {
		t.Errorf("default commitsLimit = %d, want 100", lookup.commitsLimit)
	}
}
