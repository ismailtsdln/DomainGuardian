package fingerprints

import (
	"testing"

	"github.com/ismailtsdln/DomainGuardian/internal/models"
)

func TestMatch(t *testing.T) {
	fe := NewEngine()
	fe.Fingerprints = []models.Fingerprint{
		{
			Service:          "GitHub Pages",
			CNAMEPatterns:    []string{"github.io"},
			HTTPStatus:       404,
			BodyContains:     []string{"There isn't a GitHub Pages site here"},
			TakeoverPossible: true,
		},
	}

	tests := []struct {
		name     string
		result   *models.Result
		expected bool
	}{
		{
			name: "Exact Match",
			result: &models.Result{
				CNAMEs:     []string{"user.github.io"},
				HTTPStatus: 404,
				Evidence:   "There isn't a GitHub Pages site here",
			},
			expected: true,
		},
		{
			name: "Status Mismatch",
			result: &models.Result{
				CNAMEs:     []string{"user.github.io"},
				HTTPStatus: 200,
				Evidence:   "There isn't a GitHub Pages site here",
			},
			expected: false,
		},
		{
			name: "Body Mismatch",
			result: &models.Result{
				CNAMEs:     []string{"user.github.io"},
				HTTPStatus: 404,
				Evidence:   "Some other content",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := fe.Match(tt.result)
			if (match != nil) != tt.expected {
				t.Errorf("Match() = %v, expected %v", match != nil, tt.expected)
			}
		})
	}
}
