package util

import (
	"reflect"
	"testing"
)

func TestMissing(t *testing.T) {
	tests := []struct {
		name     string
		haystack []string
		needle   []string
		expected []string
	}{
		{
			name:     "No Missing Elements",
			haystack: []string{"apple", "banana", "cherry"},
			needle:   []string{"cherry", "apple"},
			expected: nil,
		},
		{
			name:     "Some Missing Elements",
			haystack: []string{"apple", "banana", "cherry"},
			needle:   []string{"apple", "fig"},
			expected: []string{"fig"},
		},
		{
			name:     "Empty Haystack",
			haystack: []string{},
			needle:   []string{"date", "fig", "grape"},
			expected: []string{"date", "fig", "grape"},
		},
		{
			name:     "Empty Needle",
			haystack: []string{"apple", "banana", "cherry"},
			needle:   []string{},
			expected: nil,
		},
		{
			name:     "Empty Both",
			haystack: []string{},
			needle:   []string{},
			expected: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := Missing(test.haystack, test.needle)
			if !reflect.DeepEqual(result, test.expected) {
				t.Errorf("Expected %v, but got %v", test.expected, result)
			}
		})
	}
}
