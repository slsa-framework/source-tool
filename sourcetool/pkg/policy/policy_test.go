package policy

import (
	"testing"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/gh_control"
)

func TestHelloWorld(t *testing.T) {
	// A simple placeholder test
	if false {
		t.Errorf("Hello world test failed!")
	}
}

func TestGetPolicyPath(t *testing.T) {
	tests := []struct {
		name       string
		connection *gh_control.GitHubConnection
		expected   string
	}{
		{
			name: "valid connection",
			connection: &gh_control.GitHubConnection{
				Owner: "test-owner",
				Repo:  "test-repo",
			},
			expected: "policy/github.com/test-owner/test-repo/source-policy.json",
		},
		{
			name: "another connection",
			connection: &gh_control.GitHubConnection{
				Owner: "another-owner",
				Repo:  "another-repo",
			},
			expected: "policy/github.com/another-owner/another-repo/source-policy.json",
		},
		{
			name: "empty owner",
			connection: &gh_control.GitHubConnection{
				Owner: "",
				Repo:  "test-repo",
			},
			expected: "policy/github.com//test-repo/source-policy.json",
		},
		{
			name: "empty repo",
			connection: &gh_control.GitHubConnection{
				Owner: "test-owner",
				Repo:  "",
			},
			expected: "policy/github.com/test-owner//source-policy.json",
		},
		{
			name: "empty owner and repo",
			connection: &gh_control.GitHubConnection{
				Owner: "",
				Repo:  "",
			},
			expected: "policy/github.com///source-policy.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getPolicyPath(tt.connection)
			if got != tt.expected {
				t.Errorf("getPolicyPath() = %v, want %v", got, tt.expected)
			}
		})
	}
}
