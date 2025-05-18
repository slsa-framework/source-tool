package policy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect" // Ensure reflect is imported
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v69/github" // Use v69
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/gh_control"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/slsa_types"
)

// createTempPolicyFile creates a temporary file with the given policy data.
// If policyData is a RepoPolicy, it's marshalled to JSON.
// If policyData is a string, it's written directly.
func createTempPolicyFile(t *testing.T, policyData interface{}) string {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "test-policy-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp policy file: %v", err)
	}
	defer tmpFile.Close()

	switch data := policyData.(type) {
	case RepoPolicy:
		jsonData, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			t.Fatalf("Failed to marshal RepoPolicy: %v", err)
		}
		if _, err := tmpFile.Write(jsonData); err != nil {
			t.Fatalf("Failed to write JSON to temp file: %v", err)
		}
	case string:
		if _, err := tmpFile.WriteString(data); err != nil {
			t.Fatalf("Failed to write string to temp file: %v", err)
		}
	default:
		t.Fatalf("Unsupported policyData type: %T", policyData)
	}
	return tmpFile.Name()
}

// validateMockServerRequestPath checks if the incoming request to the mock server
// has the expected path for fetching a policy file.
func validateMockServerRequestPath(t *testing.T, r *http.Request, expectedPolicyOwner, expectedPolicyRepo, expectedPolicyBranch string) {
	t.Helper()
	// This ghConn is only for generating the policy file path segment based on the target repo's details
	tempGhConn := &gh_control.GitHubConnection{Owner: expectedPolicyOwner, Repo: expectedPolicyRepo, Branch: expectedPolicyBranch}
	policyFilePathSegment := getPolicyPath(tempGhConn) // getPolicyPath is an existing function in the policy package

	// Construct the full expected API path suffix for the GetContents call
	// sourcePolicyRepoOwner and sourcePolicyRepo are constants defined in policy_test.go (and policy.go)
	// representing the repo that *hosts* the policy files.
	expectedAPICallPathSuffix := fmt.Sprintf("/repos/%s/%s/contents/%s", sourcePolicyRepoOwner, sourcePolicyRepo, policyFilePathSegment)

	if !strings.HasSuffix(r.URL.Path, expectedAPICallPathSuffix) {
		t.Errorf("Mock server request path = %q, want suffix %q for policy target %s/%s (branch %s)",
			r.URL.Path, expectedAPICallPathSuffix, expectedPolicyOwner, expectedPolicyRepo, expectedPolicyBranch)
	}
}

// setupMockGitHubTestEnv creates a mock GitHub environment for testing.
// It takes a handler function to simulate GitHub API responses.
// It returns a GitHubConnection configured to use the mock server and the server itself.
func setupMockGitHubTestEnv(t *testing.T, targetOwner string, targetRepo string, targetBranch string, handler http.HandlerFunc) (*gh_control.GitHubConnection, *httptest.Server) {
	t.Helper()

	server := httptest.NewServer(handler)

	httpClient := server.Client()
	ghClient := github.NewClient(httpClient)

	baseURL, err := url.Parse(server.URL + "/")
	if err != nil {
		server.Close() // Close the server if URL parsing fails
		t.Fatalf("Failed to parse mock server URL: %v", err)
	}
	ghClient.BaseURL = baseURL

	ghConn := &gh_control.GitHubConnection{
		Owner:  targetOwner,
		Repo:   targetRepo,
		Branch: targetBranch,
		Client: ghClient,
	}
	return ghConn, server
}

// assertProtectedBranchEquals compares two ProtectedBranch structs for equality,
// optionally ignoring the 'Since' field. It provides a detailed error message
// if they are not equal.
func assertProtectedBranchEquals(t *testing.T, got *ProtectedBranch, expected ProtectedBranch, ignoreSince bool, customMessage string) {
	t.Helper()

	if got == nil {
		// If we expected a non-zero struct but got nil, it's a failure.
		// A more sophisticated check could see if 'expected' is a zero-value struct,
		// implying that a nil 'got' might be acceptable. However, for this helper,
		// we assume if 'expected' is provided, 'got' should be non-nil.
		if expected != (ProtectedBranch{}) {
			// Note: The original Fatalf message included customMessage formatting,
			// which is simplified here as customMessage is now just a string.
			// Consider if this part needs more sophisticated handling if customMessage is expected to be a format string.
			// For now, just appending it.
			fatalMsg := fmt.Sprintf("Expected a non-nil ProtectedBranch, but got nil. Expected: %+v.", expected)
			if customMessage != "" {
				fatalMsg = fmt.Sprintf("%s %s", customMessage, fatalMsg)
			}
			t.Fatalf(fatalMsg)
		}
		// If 'expected' is also a zero-value struct, then a nil 'got' is considered a match.
		return
	}

	actual := *got
	actualCopy := actual
	expectedCopy := expected
	sinceMatch := true

	if ignoreSince {
		actualCopy.Since = time.Time{}
		expectedCopy.Since = time.Time{}
	} else {
		// Explicitly compare Since fields using time.Equal for robustness
		if !actualCopy.Since.Equal(expectedCopy.Since) {
			sinceMatch = false
		}
		// Zero out Since fields after specific comparison (or if it was already ignored)
		// to ensure DeepEqual focuses on other fields.
		actualCopy.Since = time.Time{}
		expectedCopy.Since = time.Time{}
	}

	if !reflect.DeepEqual(actualCopy, expectedCopy) || !sinceMatch {
		var errorMessage strings.Builder
		if customMessage != "" {
			errorMessage.WriteString(customMessage)
			errorMessage.WriteString("\n")
		}
		errorMessage.WriteString(fmt.Sprintf("ProtectedBranch structs not equal:\nExpected: %+v\nGot:      %+v", expected, actual))
		if !sinceMatch {
			errorMessage.WriteString(fmt.Sprintf("\nSpecifically, 'Since' fields were not equal (Expected.Since: %v, Got.Since: %v)", expected.Since, actual.Since))
		}
		if ignoreSince && actual.Since != (time.Time{}) { // Add note only if Since was ignored AND original got.Since was not zero
			errorMessage.WriteString(fmt.Sprintf("\n(Note: 'Since' field was ignored in comparison as requested. Original Expected.Since: %v, Original Got.Since: %v)", expected.Since, actual.Since))
		}
		t.Errorf(errorMessage.String())
	}
}

// Constants for policy hosting repo, mirror what's in policy.go
const (
	sourcePolicyRepoOwner = "slsa-framework"
	sourcePolicyRepo      = "slsa-source-poc"
)

func TestGetBranchPolicy_Local_SpecificFound(t *testing.T) {
	fixedTime := time.Unix(1678886400, 0) // March 15, 2023 00:00:00 UTC

	tests := []struct {
		name             string
		branchName       string
		policyToCreate   RepoPolicy
		expectedBranch   ProtectedBranch
	}{
		{
			name:       "local policy exists with target branch",
			branchName: "feature",
			policyToCreate: RepoPolicy{
				ProtectedBranches: []ProtectedBranch{
					{Name: "feature", Since: fixedTime, TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel2, RequireReview: true, ImmutableTags: true},
					{Name: "main", Since: fixedTime, TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel1}, // Another branch to ensure correct one is picked
				},
			},
			expectedBranch: ProtectedBranch{
				Name:                  "feature",
				Since:                 fixedTime,
				TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel2,
				RequireReview:         true,
				ImmutableTags:         true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			ghConn := &gh_control.GitHubConnection{Owner: "any", Repo: "any", Branch: tt.branchName}
			p := &Policy{}

			policyFilePath := createTempPolicyFile(t, tt.policyToCreate)
			defer os.Remove(policyFilePath)
			p.UseLocalPolicy = policyFilePath

			gotBranch, gotPath, err := p.getBranchPolicy(ctx, ghConn)

			if err != nil {
				t.Fatalf("getBranchPolicy() error = %v, want nil", err)
			}
			if gotPath != policyFilePath {
				t.Errorf("getBranchPolicy() gotPath = %q, want %q (temp file path)", gotPath, policyFilePath)
			}
			if gotBranch == nil {
				// This check is important because tt.expectedBranch is non-zero in this test.
				// assertProtectedBranchEquals would also fatalf, but this gives a slightly more direct message.
				t.Fatalf("getBranchPolicy() gotBranch is nil, expected non-nil: %+v for test case %s", tt.expectedBranch, tt.name)
			}

			message := fmt.Sprintf("Mismatch in TestGetBranchPolicy_Local_SpecificFound for test case '%s', branch '%s'", tt.name, tt.branchName)
			assertProtectedBranchEquals(t, gotBranch, tt.expectedBranch, false, message)
		})
	}
}

func TestGetBranchPolicy_Local_DefaultCases(t *testing.T) {
	fixedTime := time.Unix(1678886400, 0) // March 15, 2023 00:00:00 UTC

	tests := []struct {
		name            string
		branchName      string
		policyToCreate  RepoPolicy
	}{
		{
			name:       "local policy exists, branch not found",
			branchName: "develop",
			policyToCreate: RepoPolicy{
				ProtectedBranches: []ProtectedBranch{
					{Name: "feature", Since: fixedTime, TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel2},
				},
			},
		},
		{
			name:            "local policy exists, ProtectedBranches nil",
			branchName:      "main",
			policyToCreate:  RepoPolicy{ProtectedBranches: nil},
		},
		{
			name:            "local policy exists, ProtectedBranches empty",
			branchName:      "main",
			policyToCreate:  RepoPolicy{ProtectedBranches: []ProtectedBranch{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			ghConn := &gh_control.GitHubConnection{Owner: "any", Repo: "any", Branch: tt.branchName}
			p := &Policy{}

			policyFilePath := createTempPolicyFile(t, tt.policyToCreate)
			defer os.Remove(policyFilePath)
			p.UseLocalPolicy = policyFilePath

			gotBranch, gotPath, err := p.getBranchPolicy(ctx, ghConn)

			if err != nil {
				t.Fatalf("getBranchPolicy() error = %v, want nil", err)
			}
			if gotPath != "DEFAULT" {
				t.Errorf("getBranchPolicy() gotPath = %q, want 'DEFAULT'", gotPath)
			}
			if gotBranch == nil {
				t.Fatalf("getBranchPolicy() gotBranch is nil, want default policy for branch %q", ghConn.Branch)
			}

			expectedDefaultBranch := ProtectedBranch{
				Name:                  ghConn.Branch, // ghConn.Branch is populated from tt.branchName
				TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel1,
				RequireReview:         false,
				ImmutableTags:         false,
				// Since is implicitly its zero value (time.Time{}), and will be ignored by the helper
			}
			message := fmt.Sprintf("Mismatch in TestGetBranchPolicy_Local_DefaultCases for test case '%s', branch '%s'", tt.name, tt.branchName)
			assertProtectedBranchEquals(t, gotBranch, expectedDefaultBranch, true, message)
		})
	}
}

func TestGetBranchPolicy_Local_ErrorCases(t *testing.T) {
	tests := []struct {
		name                   string
		branchName             string
		policyFileContent      interface{} // RepoPolicy or string for malformed
		useLocalPolicyPath     string      // "CREATE_TEMP", or specific path for non-existent
	}{
		{
			name:                   "local policy file is malformed JSON",
			branchName:             "main",
			policyFileContent:      "this is not valid json",
			useLocalPolicyPath:     "CREATE_TEMP",
		},
		{
			name:                   "local policy file does not exist",
			branchName:             "main",
			policyFileContent:      nil, // No file created for this case
			useLocalPolicyPath:     "/path/to/nonexistent/policy.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			ghConn := &gh_control.GitHubConnection{Owner: "any", Repo: "any", Branch: tt.branchName}
			p := &Policy{}
			var policyFilePath string

			if tt.useLocalPolicyPath == "CREATE_TEMP" {
				if tt.policyFileContent == nil {
					t.Fatal("policyFileContent cannot be nil when useLocalPolicyPath is CREATE_TEMP for error cases")
				}
				policyFilePath = createTempPolicyFile(t, tt.policyFileContent)
				defer os.Remove(policyFilePath) // Ensure cleanup even if test expects error
				p.UseLocalPolicy = policyFilePath
			} else {
				p.UseLocalPolicy = tt.useLocalPolicyPath // For non-existent file
			}

			gotBranch, gotPath, err := p.getBranchPolicy(ctx, ghConn)

			if err == nil {
				t.Errorf("getBranchPolicy() error = nil, want non-nil error")
			}
			if gotBranch != nil {
				t.Errorf("getBranchPolicy() gotBranch = %v, want nil", gotBranch)
			}
			if gotPath != "" {
				t.Errorf("getBranchPolicy() gotPath = %q, want \"\"", gotPath)
			}
		})
	}
}

func TestGetBranchPolicy_Remote_SpecificFound(t *testing.T) {
	fixedTime := time.Unix(1678886400, 0) // March 15, 2023 00:00:00 UTC
	mockHTMLURL := "https://github.example.com/policy.json"

	tests := []struct {
		name                 string
		targetOwner          string
		targetRepo           string
		targetBranch         string
		mockPolicyContent    RepoPolicy
		expectedBranch       ProtectedBranch
		// expectedPath is always mockHTMLURL for this test function
	}{
		{
			name:         "remote policy fetch success, branch found",
			targetOwner:  "test-owner",
			targetRepo:   "test-repo",
			targetBranch: "main",
			mockPolicyContent: RepoPolicy{
				ProtectedBranches: []ProtectedBranch{
					{Name: "main", Since: fixedTime, TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel3, RequireReview: true, ImmutableTags: true},
					{Name: "other", Since: fixedTime, TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel1}, // Ensure correct branch is picked
				},
			},
			expectedBranch: ProtectedBranch{
				Name:                  "main",
				Since:                 fixedTime,
				TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel3,
				RequireReview:         true,
				ImmutableTags:         true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			p := &Policy{UseLocalPolicy: ""}

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				validateMockServerRequestPath(t, r, tt.targetOwner, tt.targetRepo, tt.targetBranch)
				w.WriteHeader(http.StatusOK) // Always OK for this test function
				policyJSON, err := json.Marshal(tt.mockPolicyContent)
				if err != nil {
					t.Fatalf("Failed to marshal RepoPolicy for mock: %v", err)
				}
				encodedContent := base64.StdEncoding.EncodeToString(policyJSON)
				mockFileContent := &github.RepositoryContent{
					Type:    github.String("file"),
					Encoding: github.String("base64"),
					Content: github.String(encodedContent),
					HTMLURL: github.String(mockHTMLURL),
				}
				respData, err := json.Marshal(mockFileContent)
				if err != nil {
					t.Fatalf("Failed to marshal mock RepositoryContent: %v", err)
				}
				_, _ = w.Write(respData)
			})

			ghConn, mockServer := setupMockGitHubTestEnv(t, tt.targetOwner, tt.targetRepo, tt.targetBranch, handler)
			defer mockServer.Close()

			gotBranch, gotPath, err := p.getBranchPolicy(ctx, ghConn)

			if err != nil {
				t.Fatalf("getBranchPolicy() error = %v, want nil", err)
			}
			if gotPath != mockHTMLURL {
				t.Errorf("getBranchPolicy() gotPath = %q, want %q", gotPath, mockHTMLURL)
			}
			if gotBranch == nil {
				t.Fatalf("getBranchPolicy() gotBranch is nil, expected non-nil: %+v for test case %s", tt.expectedBranch, tt.name)
			}

			message := fmt.Sprintf("Mismatch in TestGetBranchPolicy_Remote_SpecificFound for test case '%s', branch '%s'", tt.name, tt.targetBranch)
			assertProtectedBranchEquals(t, gotBranch, tt.expectedBranch, false, message)
		})
	}
}

func TestGetBranchPolicy_Remote_DefaultCases(t *testing.T) {
	fixedTime := time.Unix(1678886400, 0) // March 15, 2023 00:00:00 UTC
	mockHTMLURL := "https://github.example.com/policy.json"

	tests := []struct {
		name                  string
		targetOwner           string
		targetRepo            string
		targetBranch          string
		mockHTTPStatus        int
		mockPolicyContent     *RepoPolicy // Pointer to allow nil for 404 case
		expectedPath          string
		// Default policy details are asserted directly in the test
	}{
		{
			name:         "remote policy fetch success, branch not found",
			targetOwner:  "test-owner",
			targetRepo:   "test-repo",
			targetBranch: "develop",
			mockHTTPStatus: http.StatusOK,
			mockPolicyContent: &RepoPolicy{
				ProtectedBranches: []ProtectedBranch{
					{Name: "main", Since: fixedTime, TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel3},
				},
			},
			expectedPath: "DEFAULT", // Changed from mockHTMLURL
		},
		{
			name:         "remote policy fetch success, empty protected branches",
			targetOwner:  "test-owner",
			targetRepo:   "test-repo",
			targetBranch: "main",
			mockHTTPStatus: http.StatusOK,
			mockPolicyContent: &RepoPolicy{ProtectedBranches: []ProtectedBranch{}},
			expectedPath: "DEFAULT", // Changed from mockHTMLURL
		},
		{
			name:         "remote policy fetch success, nil protected branches",
			targetOwner:  "test-owner",
			targetRepo:   "test-repo",
			targetBranch: "main",
			mockHTTPStatus: http.StatusOK,
			mockPolicyContent: &RepoPolicy{ProtectedBranches: nil},
			expectedPath: "DEFAULT", // Changed from mockHTMLURL
		},
		{
			name:         "remote policy API returns 404 Not Found",
			targetOwner:  "test-owner",
			targetRepo:   "test-repo",
			targetBranch: "main",
			mockHTTPStatus: http.StatusNotFound,
			mockPolicyContent: nil, // No policy content for 404
			expectedPath: "DEFAULT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			p := &Policy{UseLocalPolicy: ""}

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				validateMockServerRequestPath(t, r, tt.targetOwner, tt.targetRepo, tt.targetBranch)
				w.WriteHeader(tt.mockHTTPStatus)
				if tt.mockHTTPStatus == http.StatusOK && tt.mockPolicyContent != nil {
					policyJSON, err := json.Marshal(*tt.mockPolicyContent)
					if err != nil {
						t.Fatalf("Failed to marshal RepoPolicy for mock: %v", err)
					}
					encodedContent := base64.StdEncoding.EncodeToString(policyJSON)
					mockFileContent := &github.RepositoryContent{
						Type:    github.String("file"),
						Encoding: github.String("base64"),
						Content: github.String(encodedContent),
						HTMLURL: github.String(mockHTMLURL),
					}
					respData, err := json.Marshal(mockFileContent)
					if err != nil {
						t.Fatalf("Failed to marshal mock RepositoryContent: %v", err)
					}
					_, _ = w.Write(respData)
				}
			})

			ghConn, mockServer := setupMockGitHubTestEnv(t, tt.targetOwner, tt.targetRepo, tt.targetBranch, handler)
			defer mockServer.Close()

			gotBranch, gotPath, err := p.getBranchPolicy(ctx, ghConn)

			if err != nil {
				t.Fatalf("getBranchPolicy() error = %v, want nil", err)
			}
			if gotPath != tt.expectedPath {
				t.Errorf("getBranchPolicy() gotPath = %q, want %q", gotPath, tt.expectedPath)
			}
			if gotBranch == nil {
				t.Fatalf("getBranchPolicy() gotBranch is nil, want default policy for branch %q", ghConn.Branch)
			}

			expectedDefaultBranch := ProtectedBranch{
				Name:                  ghConn.Branch, // ghConn.Branch is populated from tt.targetBranch
				TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel1,
				RequireReview:         false,
				ImmutableTags:         false,
				// Since is implicitly its zero value (time.Time{}), and will be ignored by the helper
			}
			message := fmt.Sprintf("Mismatch in TestGetBranchPolicy_Remote_DefaultCases for test case '%s', branch '%s'", tt.name, tt.targetBranch)
			assertProtectedBranchEquals(t, gotBranch, expectedDefaultBranch, true, message)
		})
	}
}

func TestGetBranchPolicy_Remote_ServerError(t *testing.T) {
	ctx := context.Background()
	targetOwner := "test-owner"
	targetRepo := "test-repo"
	targetBranch := "main"

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		validateMockServerRequestPath(t, r, targetOwner, targetRepo, targetBranch)
		w.WriteHeader(http.StatusInternalServerError)
	})

	ghConn, mockServer := setupMockGitHubTestEnv(t, targetOwner, targetRepo, targetBranch, handler)
	defer mockServer.Close()

	pol := Policy{UseLocalPolicy: ""}
	// ghConn is now returned by setupMockGitHubTestEnv

	branch, path, err := pol.getBranchPolicy(ctx, ghConn)
	if err == nil {
		t.Errorf("Expected an error for server-side issues, got nil")
	}
	if branch != nil {
		t.Errorf("Expected branch to be nil on server error, got %v", branch)
	}
	if path != "" {
		t.Errorf("Expected path to be empty on server error, got %q", path)
	}
}

func TestGetBranchPolicy_Remote_MalformedJSON(t *testing.T) {
	mockHTMLURL := "https://github.example.com/policy.json" // Still needed for one case
	tests := []struct {
		name               string
		malformedOuterJSON bool // true if RepositoryContent JSON is bad
		badBase64Content   bool // true if RepoPolicy base64 content is bad
	}{
		{
			name:               "remote policy API returns malformed RepositoryContent JSON",
			malformedOuterJSON: true,
		},
		{
			name:             "remote policy content is malformed (bad base64 in RepositoryContent)",
			badBase64Content: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			targetOwner := "test-owner"
			targetRepo := "test-repo"
			targetBranch := "main"

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				validateMockServerRequestPath(t, r, targetOwner, targetRepo, targetBranch)
				w.WriteHeader(http.StatusOK) // Status is OK, but content is bad
				if tt.malformedOuterJSON {
					_, _ = w.Write([]byte("this is not valid RepositoryContent JSON"))
				} else if tt.badBase64Content {
					mockFileContent := &github.RepositoryContent{
						Type:     github.String("file"),
						Encoding: github.String("base64"),
						Content:  github.String("this-is-not-base64"),
						HTMLURL:  github.String(mockHTMLURL),
					}
					respData, err := json.Marshal(mockFileContent)
					if err != nil {
						t.Fatalf("Failed to marshal mock RepositoryContent: %v", err)
					}
					_, _ = w.Write(respData)
				}
			})

			ghConn, mockServer := setupMockGitHubTestEnv(t, targetOwner, targetRepo, targetBranch, handler)
			defer mockServer.Close()

			pol := Policy{UseLocalPolicy: ""}
			// ghConn is now returned by setupMockGitHubTestEnv

			branch, path, err := pol.getBranchPolicy(ctx, ghConn)
			if err == nil {
				t.Errorf("Expected an error for malformed JSON, got nil")
			}
			if branch != nil {
				t.Errorf("Expected branch to be nil on malformed JSON, got %v", branch)
			}
			if path != "" { // Path should be empty as we error out before using HTMLURL
				t.Errorf("Expected path to be empty on malformed JSON, got %q", path)
			}
		})
	}
}
