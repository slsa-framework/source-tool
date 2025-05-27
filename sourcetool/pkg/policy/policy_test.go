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
	spb "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/attest"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/gh_control"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/slsa_types"
)

var fixedTime = time.Unix(1678886400, 0) // March 15, 2023 00:00:00 UTC
var earlierFixedTime = fixedTime.Add(-time.Hour)
var laterFixedTime = fixedTime.Add(time.Hour)

func createTestBranchPolicy(branch string) ProtectedBranch {
	return ProtectedBranch{
		Name:                  branch,
		Since:                 fixedTime,
		TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel2,
		RequireReview:         true,
	}
}

func createTestPolicy(pb ProtectedBranch) RepoPolicy {
	return RepoPolicy{
		CanonicalRepo: "the-canonical-repo",
		ProtectedBranches: []ProtectedBranch{
			pb,
		},
		ProtectedTag: &ProtectedTag{
			Since:         fixedTime,
			ImmutableTags: true,
		},
	}

}

// Helper to create spb.Statement - moved here to be accessible by new test functions
func createStatementForTest(t *testing.T, predicateContent interface{}, predType string) *spb.Statement {
	t.Helper()
	var predicateAsStructPb *structpb.Struct
	if predicateContent != nil {
		jsonBytes, err := json.Marshal(predicateContent)
		if err != nil {
			t.Fatalf("Failed to marshal predicate content: %v", err)
		}
		predicateAsStructPb = &structpb.Struct{}
		if err := protojson.Unmarshal(jsonBytes, predicateAsStructPb); err != nil {
			t.Fatalf("Failed to unmarshal predicate JSON to structpb.Struct: %v", err)
		}
	}

	return &spb.Statement{
		Type:          spb.StatementTypeUri,
		Subject:       []*spb.ResourceDescriptor{{Name: "_"}},
		PredicateType: predType,
		Predicate:     predicateAsStructPb,
	}
}

// Helper to create a test GH Branch connection with no client.
func newTestGhBranchConnection(owner, repo, branch string) *gh_control.GitHubConnection {
	return gh_control.NewGhConnectionWithClient(owner, repo, gh_control.BranchToFullRef(branch), nil)
}

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
	tempGhConn := newTestGhBranchConnection(expectedPolicyOwner, expectedPolicyRepo, expectedPolicyBranch)
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

func TestEvaluateSourceProv_Success(t *testing.T) {
	// Controls for mock provenance
	continuityEnforcedEarlier := slsa_types.Control{Name: slsa_types.ContinuityEnforced, Since: earlierFixedTime}
	provenanceAvailableEarlier := slsa_types.Control{Name: slsa_types.ProvenanceAvailable, Since: earlierFixedTime}
	reviewEnforcedEarlier := slsa_types.Control{Name: slsa_types.ReviewEnforced, Since: earlierFixedTime}
	immutableTagsEarlier := slsa_types.Control{Name: slsa_types.ImmutableTags, Since: earlierFixedTime}

	// Valid Provenance Predicate (attest.SourceProvenancePred)
	validProvPredicateL3Controls := attest.SourceProvenancePred{
		Controls: slsa_types.Controls{continuityEnforcedEarlier, provenanceAvailableEarlier, reviewEnforcedEarlier, immutableTagsEarlier},
	}

	provenanceStatement := createStatementForTest(t, validProvPredicateL3Controls, attest.SourceProvPredicateType)

	pb := ProtectedBranch{
		Name:                  "main",
		TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel3,
		RequireReview:         true,
		Since:                 fixedTime,
	}
	rp := createTestPolicy(pb)
	rp.ProtectedTag.Since = fixedTime
	rp.ProtectedTag.ImmutableTags = true

	expectedPolicyFilePath := createTempPolicyFile(t, rp)
	defer os.Remove(expectedPolicyFilePath)
	pe := &PolicyEvaluator{UseLocalPolicy: expectedPolicyFilePath}

	ghConn := newTestGhBranchConnection("local", "local", "main")

	verifiedLevels, policyPath, err := pe.EvaluateSourceProv(context.Background(), ghConn, provenanceStatement)

	if err != nil {
		t.Errorf("EvaluateSourceProv() error = %v, want nil", err)
	}
	if policyPath != expectedPolicyFilePath {
		t.Errorf("EvaluateSourceProv() policyPath = %q, want %q", policyPath, expectedPolicyFilePath)
	}
	expectedLevels := slsa_types.SourceVerifiedLevels{string(slsa_types.SlsaSourceLevel3), slsa_types.ReviewEnforced, slsa_types.ImmutableTags}
	if !reflect.DeepEqual(verifiedLevels, expectedLevels) {
		t.Errorf("EvaluateSourceProv() verifiedLevels = %v, want %v", verifiedLevels, expectedLevels)
	}
}

func TestEvaluateSourceProv_Failure(t *testing.T) {
	// Controls for mock provenance
	continuityEnforcedEarlier := slsa_types.Control{Name: slsa_types.ContinuityEnforced, Since: earlierFixedTime}
	provenanceAvailableEarlier := slsa_types.Control{Name: slsa_types.ProvenanceAvailable, Since: earlierFixedTime}
	reviewEnforcedEarlier := slsa_types.Control{Name: slsa_types.ReviewEnforced, Since: earlierFixedTime}
	immutableTagsEarlier := slsa_types.Control{Name: slsa_types.ImmutableTags, Since: earlierFixedTime}

	// Policies
	policyL3ReviewTagsNow := RepoPolicy{
		ProtectedBranches: []ProtectedBranch{
			{Name: "main", TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel3, RequireReview: true, Since: fixedTime},
		},
		ProtectedTag: &ProtectedTag{Since: fixedTime, ImmutableTags: true},
	}
	policyL1NoExtrasNow := RepoPolicy{ // Policy for default/branch not found cases
		ProtectedBranches: []ProtectedBranch{
			{Name: "otherbranch", TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel1, Since: fixedTime},
		},
		ProtectedTag: nil,
	}

	// Valid Provenance Predicate (attest.SourceProvenancePred)
	validProvPredicateL3Controls := attest.SourceProvenancePred{
		Controls: slsa_types.Controls{continuityEnforcedEarlier, provenanceAvailableEarlier, reviewEnforcedEarlier, immutableTagsEarlier},
	}
	validProvPredicateL2Controls := attest.SourceProvenancePred{
		Controls: slsa_types.Controls{continuityEnforcedEarlier, reviewEnforcedEarlier}, // Missing provenanceAvailable for L3
	}

	tests := []struct {
		name                  string
		policyContent         interface{} // RepoPolicy or string for malformed policy
		provenanceStatement   *spb.Statement
		ghConnBranch          string
		expectedErrorContains string
	}{
		{
			name:                  "Valid L2 Prov, Policy L3 -> Error (controls don't meet policy)",
			policyContent:         policyL3ReviewTagsNow,                                                                   // Expects L3
			provenanceStatement:   createStatementForTest(t, validProvPredicateL2Controls, attest.SourceProvPredicateType), // Prov only has L2 controls
			ghConnBranch:          "main",
			expectedErrorContains: "policy sets target level SLSA_SOURCE_LEVEL_3, but branch is only eligible for SLSA_SOURCE_LEVEL_2",
		},
		{
			name:                  "Malformed Policy JSON -> Error",
			policyContent:         "not valid policy json",
			provenanceStatement:   createStatementForTest(t, validProvPredicateL3Controls, attest.SourceProvPredicateType),
			ghConnBranch:          "main",
			expectedErrorContains: "invalid character 'o' in literal null (expecting 'u')", // Error from getPolicy via getLocalPolicy
		},
		{
			name:                  "Non-existent Policy File -> Error",
			policyContent:         nil, // Signal to not create a temp file for this test
			provenanceStatement:   createStatementForTest(t, validProvPredicateL3Controls, attest.SourceProvPredicateType),
			ghConnBranch:          "main",
			expectedErrorContains: "no such file or directory", // Error from os.ReadFile in getLocalPolicy
		},
		{
			name:                  "Malformed Provenance - Nil Statement -> Error",
			policyContent:         policyL1NoExtrasNow, // Policy doesn't matter as much here
			provenanceStatement:   nil,
			ghConnBranch:          "main",
			expectedErrorContains: "nil statement", // Error from attest.GetProvPred
		},
		{
			name:                  "Malformed Provenance - Empty Statement (no predicate type) -> Error",
			policyContent:         policyL1NoExtrasNow,
			provenanceStatement:   &spb.Statement{Subject: []*spb.ResourceDescriptor{{Name: "_"}}}, // Empty statement, missing Type and PredicateType
			ghConnBranch:          "main",
			expectedErrorContains: "unsupported predicate type: ", // Error from attest.GetProvPred (empty predicate type)
		},
		{
			name:                  "Malformed Provenance - Wrong PredicateType -> Error",
			policyContent:         policyL1NoExtrasNow,
			provenanceStatement:   createStatementForTest(t, validProvPredicateL3Controls, "WRONG_PREDICATE_TYPE"),
			ghConnBranch:          "main",
			expectedErrorContains: "unsupported predicate type: WRONG_PREDICATE_TYPE", // Error from attest.GetProvPred
		},
		{
			name:          "Malformed Provenance - Nil Predicate in Statement -> Error",
			policyContent: policyL1NoExtrasNow,
			provenanceStatement: &spb.Statement{ // Predicate is nil
				Type:          spb.StatementTypeUri,
				Subject:       []*spb.ResourceDescriptor{{Name: "_"}},
				PredicateType: attest.SourceProvPredicateType,
				Predicate:     nil, // Explicitly nil predicate
			},
			ghConnBranch:          "main",
			expectedErrorContains: "nil predicate in statement", // Error from attest.GetProvPred
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			pe := &PolicyEvaluator{}
			var ghConn *gh_control.GitHubConnection

			if tt.name == "Non-existent Policy File -> Error" {
				pe.UseLocalPolicy = "/path/to/nonexistent/test/policy.json" // Specific path for this test
			} else if tt.policyContent != nil {
				policyFilePath := createTempPolicyFile(t, tt.policyContent)
				defer os.Remove(policyFilePath)
				pe.UseLocalPolicy = policyFilePath
			}
			ghConn = newTestGhBranchConnection("local", "local", tt.ghConnBranch)

			_, _, err := pe.EvaluateSourceProv(ctx, ghConn, tt.provenanceStatement)

			if err == nil {
				t.Errorf("EvaluateSourceProv() error = nil, want non-nil error containing %q", tt.expectedErrorContains)
			} else if !strings.Contains(err.Error(), tt.expectedErrorContains) {
				t.Errorf("EvaluateSourceProv() error = %q, want error containing %q", err.Error(), tt.expectedErrorContains)
			}
		})
	}
}

func TestEvaluateControl_Success(t *testing.T) {
	// Controls
	continuityEnforcedEarlier := slsa_types.Control{Name: slsa_types.ContinuityEnforced, Since: earlierFixedTime}
	provenanceAvailableEarlier := slsa_types.Control{Name: slsa_types.ProvenanceAvailable, Since: earlierFixedTime}
	reviewEnforcedEarlier := slsa_types.Control{Name: slsa_types.ReviewEnforced, Since: earlierFixedTime}
	immutableTagsEarlier := slsa_types.Control{Name: slsa_types.ImmutableTags, Since: earlierFixedTime}

	// Policies
	policyL3ReviewTagsNow := RepoPolicy{
		ProtectedBranches: []ProtectedBranch{
			{Name: "main", TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel3, RequireReview: true, Since: fixedTime},
		},
		ProtectedTag: &ProtectedTag{
			Since:         fixedTime,
			ImmutableTags: true,
		},
	}
	policyL1NoExtrasNow := RepoPolicy{
		ProtectedBranches: []ProtectedBranch{
			{Name: "main", TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel1, Since: fixedTime},
		},
	}

	tests := []struct {
		name               string
		policyContent      interface{} // RepoPolicy or string for malformed
		controlStatus      *gh_control.GhControlStatus
		ghConnBranch       string // Branch for GitHub connection
		expectedLevels     slsa_types.SourceVerifiedLevels
		expectedPolicyPath string
	}{
		{
			name:          "Commit time before policy Since -> SLSA Level 1",
			policyContent: policyL3ReviewTagsNow,
			controlStatus: &gh_control.GhControlStatus{
				CommitPushTime: earlierFixedTime, // Commit time before policyL3ReviewTagsNow.Since (now)
				Controls:       slsa_types.Controls{continuityEnforcedEarlier, provenanceAvailableEarlier, reviewEnforcedEarlier, immutableTagsEarlier},
			},
			ghConnBranch:       "main",
			expectedLevels:     slsa_types.SourceVerifiedLevels{string(slsa_types.SlsaSourceLevel1)}, // Expect L1 because commit time is before policy enforcement
			expectedPolicyPath: "TEMP_POLICY_FILE_PATH",                                              // Placeholder, will be replaced by actual temp file path
		},
		{
			name:          "Commit time after policy Since, controls meet policy -> Expected levels",
			policyContent: policyL3ReviewTagsNow,
			controlStatus: &gh_control.GhControlStatus{
				CommitPushTime: laterFixedTime,
				Controls:       slsa_types.Controls{continuityEnforcedEarlier, provenanceAvailableEarlier, reviewEnforcedEarlier, immutableTagsEarlier},
			},
			ghConnBranch:       "main",
			expectedLevels:     slsa_types.SourceVerifiedLevels{string(slsa_types.SlsaSourceLevel3), slsa_types.ReviewEnforced, slsa_types.ImmutableTags},
			expectedPolicyPath: "TEMP_POLICY_FILE_PATH",
		},
		{
			name:          "Branch not in policy, commit after default policy since -> Default policy (SLSA L1)",
			policyContent: policyL1NoExtrasNow, // main is in policy, but we test "develop"
			controlStatus: &gh_control.GhControlStatus{
				CommitPushTime: laterFixedTime,
				Controls:       slsa_types.Controls{continuityEnforcedEarlier, provenanceAvailableEarlier, reviewEnforcedEarlier, immutableTagsEarlier},
			},
			ghConnBranch:       "develop",                                                            // Testing "develop" branch
			expectedLevels:     slsa_types.SourceVerifiedLevels{string(slsa_types.SlsaSourceLevel1)}, // Default is L1
			expectedPolicyPath: "DEFAULT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			pe := &PolicyEvaluator{}
			var ghConn *gh_control.GitHubConnection
			actualPolicyPath := tt.expectedPolicyPath // May be overridden for local temp file

			if tt.policyContent != nil {
				policyFilePath := createTempPolicyFile(t, tt.policyContent)
				defer os.Remove(policyFilePath)
				pe.UseLocalPolicy = policyFilePath
				if tt.expectedPolicyPath == "TEMP_POLICY_FILE_PATH" {
					actualPolicyPath = policyFilePath
				}
			}
			ghConn = newTestGhBranchConnection("local", "local", tt.ghConnBranch)

			verifiedLevels, policyPath, err := pe.EvaluateControl(ctx, ghConn, tt.controlStatus)

			if err != nil {
				t.Errorf("EvaluateControl() error = %v, want nil", err)
			}

			if policyPath != actualPolicyPath {
				t.Errorf("EvaluateControl() policyPath = %q, want %q", policyPath, actualPolicyPath)
			}

			if !reflect.DeepEqual(verifiedLevels, tt.expectedLevels) {
				if !(len(verifiedLevels) == 0 && len(tt.expectedLevels) == 0) {
					t.Errorf("EvaluateControl() verifiedLevels = %v, want %v", verifiedLevels, tt.expectedLevels)
				}
			}
		})
	}
}

func TestEvaluateControl_Failure(t *testing.T) {
	now := time.Now()
	earlier := now.Add(-time.Hour)
	later := now.Add(time.Hour)

	// Controls
	continuityEnforcedEarlier := slsa_types.Control{Name: slsa_types.ContinuityEnforced, Since: earlier}

	// Policies
	policyL3Review := RepoPolicy{
		ProtectedBranches: []ProtectedBranch{
			{Name: "main", TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel3, RequireReview: true, Since: now},
		},
	}

	tests := []struct {
		name                  string
		policyContent         interface{} // RepoPolicy or string for malformed
		controlStatus         *gh_control.GhControlStatus
		ghConnBranch          string // Branch for GitHub connection
		expectedErrorContains string
	}{
		{
			name:          "Commit time after policy Since, controls DO NOT meet policy -> Error",
			policyContent: policyL3Review, // Requires L3, Review, Tags
			controlStatus: &gh_control.GhControlStatus{
				CommitPushTime: later,                                          // Commit time after policy.Since
				Controls:       slsa_types.Controls{continuityEnforcedEarlier}, // Only meets L2
			},
			ghConnBranch:          "main",
			expectedErrorContains: "policy sets target level SLSA_SOURCE_LEVEL_3, but branch is only eligible for SLSA_SOURCE_LEVEL_2",
		},
		{
			name:          "Malformed JSON -> Error",
			policyContent: "not json",
			controlStatus: &gh_control.GhControlStatus{
				CommitPushTime: later,
				Controls:       slsa_types.Controls{},
			},
			ghConnBranch:          "main",
			expectedErrorContains: "invalid character 'o' in literal null (expecting 'u')", // Error from json.Unmarshal
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			pe := &PolicyEvaluator{}
			var ghConn *gh_control.GitHubConnection
			policyFilePath := "" // Default to empty, will be set if policyContent is not nil

			if tt.policyContent != nil {
				// For failure cases, the exact policy path might not be relevant if error occurs early,
				// but we still need to handle policy file creation if content is provided.
				// Using a specific name for clarity in failure tests, if needed, or just use createTempPolicyFile.
				if strContent, ok := tt.policyContent.(string); ok && strContent == "not json" {
					// Specific handling for malformed JSON if needed, otherwise createTempPolicyFile handles it.
					policyFilePath = createTempPolicyFile(t, tt.policyContent)
				} else if tt.policyContent != nil { // General case for valid policy structure in a failure scenario
					policyFilePath = createTempPolicyFile(t, tt.policyContent)
				}
				if policyFilePath != "" { // Ensure removal only if a file was created
					defer os.Remove(policyFilePath)
				}
				pe.UseLocalPolicy = policyFilePath
			}

			ghConn = newTestGhBranchConnection("local", "local", tt.ghConnBranch)

			_, _, err := pe.EvaluateControl(ctx, ghConn, tt.controlStatus)

			if err == nil {
				t.Errorf("EvaluateControl() error = nil, want non-nil error containing %q", tt.expectedErrorContains)
			} else if !strings.Contains(err.Error(), tt.expectedErrorContains) {
				t.Errorf("EvaluateControl() error = %q, want error containing %q", err.Error(), tt.expectedErrorContains)
			}
		})
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

	ghConn := gh_control.NewGhConnectionWithClient(targetOwner, targetRepo, targetBranch, ghClient)
	return ghConn, server
}

// assertProtectedBranchEquals compares two ProtectedBranch structs for equality,
// optionally ignoring the 'Since' field. It provides a detailed error message
// if they are not equal.
func assertProtectedBranchEquals(t *testing.T, got *ProtectedBranch, expected ProtectedBranch, ignoreSince bool) {
	t.Helper()

	if got == nil {
		// If we expected a non-zero struct but got nil, it's a failure.
		// A more sophisticated check could see if 'expected' is a zero-value struct,
		// implying that a nil 'got' might be acceptable. However, for this helper,
		// we assume if 'expected' is provided, 'got' should be non-nil.
		if expected != (ProtectedBranch{}) {
			t.Fatalf("Expected a non-nil ProtectedBranch, but got nil. Expected: %+v.", expected)
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

func TestComputeEligibleSlsaLevel(t *testing.T) {
	continuityEnforcedControl := slsa_types.Control{Name: slsa_types.ContinuityEnforced, Since: fixedTime}
	provenanceAvailableControl := slsa_types.Control{Name: slsa_types.ProvenanceAvailable, Since: fixedTime}

	tests := []struct {
		name           string
		controls       slsa_types.Controls
		expectedLevel  slsa_types.SlsaSourceLevel
		expectedReason string
	}{
		{
			name:           "SLSA Level 3",
			controls:       slsa_types.Controls{continuityEnforcedControl, provenanceAvailableControl},
			expectedLevel:  slsa_types.SlsaSourceLevel3,
			expectedReason: "continuity is enable and provenance is available",
		},
		{
			name:           "SLSA Level 2",
			controls:       slsa_types.Controls{continuityEnforcedControl},
			expectedLevel:  slsa_types.SlsaSourceLevel2,
			expectedReason: "continuity is enabled but provenance is not available",
		},
		{
			name:           "SLSA Level 1 - ProvenanceAvailable only",
			controls:       slsa_types.Controls{provenanceAvailableControl},
			expectedLevel:  slsa_types.SlsaSourceLevel1,
			expectedReason: "continuity is not enabled",
		},
		{
			name:           "SLSA Level 1 - ContinuityEnforced control absent",
			controls:       nil, // Represents absence of ContinuityEnforced; could also use slsa_types.Controls{}
			expectedLevel:  slsa_types.SlsaSourceLevel1,
			expectedReason: "continuity is not enabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level, reason := computeEligibleSlsaLevel(tt.controls)
			if level != tt.expectedLevel {
				t.Errorf("computeEligibleSlsaLevel() level = %v, want %v", level, tt.expectedLevel)
			}
			if reason != tt.expectedReason {
				t.Errorf("computeEligibleSlsaLevel() reason = %q, want %q", reason, tt.expectedReason)
			}
		})
	}
}

func TestEvaluateBranchControls(t *testing.T) {
	// Controls
	continuityEnforcedEarlier := slsa_types.Control{Name: slsa_types.ContinuityEnforced, Since: earlierFixedTime}
	provenanceAvailableEarlier := slsa_types.Control{Name: slsa_types.ProvenanceAvailable, Since: earlierFixedTime}
	reviewEnforcedEarlier := slsa_types.Control{Name: slsa_types.ReviewEnforced, Since: earlierFixedTime}
	immutableTagsEarlier := slsa_types.Control{Name: slsa_types.ImmutableTags, Since: earlierFixedTime}
	immutableTagsNow := slsa_types.Control{Name: slsa_types.ImmutableTags, Since: fixedTime}

	// Branch Policies
	policyL3Review := ProtectedBranch{TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel3, RequireReview: true, Since: fixedTime}
	policyL1NoExtras := ProtectedBranch{TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel1, RequireReview: false, Since: fixedTime}
	policyL2Review := ProtectedBranch{TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel2, RequireReview: true, Since: fixedTime}
	policyL2NoReview := ProtectedBranch{TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel2, RequireReview: false, Since: fixedTime}

	// Tag policies
	immutableTagPolicy := ProtectedTag{Since: fixedTime, ImmutableTags: true}
	noImmutableTagPolicy := ProtectedTag{Since: fixedTime, ImmutableTags: false}

	// Policy Since 'earlier' for testing control.Since > policy.Since
	policyL2TagsEarlier := ProtectedBranch{TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel2, RequireReview: false, Since: earlierFixedTime}

	tests := []struct {
		name                  string
		branchPolicy          *ProtectedBranch
		tagPolicy             *ProtectedTag
		controls              slsa_types.Controls
		expectedLevels        slsa_types.SourceVerifiedLevels
		expectError           bool
		expectedErrorContains string
	}{
		{
			name:           "Success - All Met (L3, Review, Tags)",
			branchPolicy:   &policyL3Review,
			tagPolicy:      &immutableTagPolicy,
			controls:       slsa_types.Controls{continuityEnforcedEarlier, provenanceAvailableEarlier, reviewEnforcedEarlier, immutableTagsEarlier},
			expectedLevels: slsa_types.SourceVerifiedLevels{string(slsa_types.SlsaSourceLevel3), slsa_types.ReviewEnforced, slsa_types.ImmutableTags},
			expectError:    false,
		},
		{
			name:           "Success - Only SLSA Level (L1)",
			branchPolicy:   &policyL1NoExtras,
			tagPolicy:      &noImmutableTagPolicy,
			controls:       slsa_types.Controls{}, // L1 is met by default if policy targets L1 and other conditions pass
			expectedLevels: slsa_types.SourceVerifiedLevels{string(slsa_types.SlsaSourceLevel1)},
			expectError:    false,
		},
		{
			name:           "Success - SLSA & Review (L2, Review)",
			branchPolicy:   &policyL2Review,
			tagPolicy:      &noImmutableTagPolicy,
			controls:       slsa_types.Controls{continuityEnforcedEarlier, reviewEnforcedEarlier}, // Provenance not needed for L2
			expectedLevels: slsa_types.SourceVerifiedLevels{string(slsa_types.SlsaSourceLevel2), slsa_types.ReviewEnforced},
			expectError:    false,
		},
		{
			name:           "Success - SLSA & Tags (L2, Tags)",
			branchPolicy:   &policyL2NoReview,
			tagPolicy:      &immutableTagPolicy,
			controls:       slsa_types.Controls{continuityEnforcedEarlier, immutableTagsEarlier}, // Provenance not needed for L2
			expectedLevels: slsa_types.SourceVerifiedLevels{string(slsa_types.SlsaSourceLevel2), slsa_types.ImmutableTags},
			expectError:    false,
		},
		{
			name:                  "Error - computeSlsaLevel Fails (Policy L3, Controls L1)",
			branchPolicy:          &policyL3Review, // Wants L3
			tagPolicy:             &noImmutableTagPolicy,
			controls:              slsa_types.Controls{}, // Only eligible for L1
			expectedLevels:        slsa_types.SourceVerifiedLevels{},
			expectError:           true,
			expectedErrorContains: "error computing slsa level: policy sets target level SLSA_SOURCE_LEVEL_3, but branch is only eligible for SLSA_SOURCE_LEVEL_1",
		},
		{
			name:                  "Error - computeReviewEnforced Fails (Policy L2+Review, Review control missing)",
			branchPolicy:          &policyL2Review, // Wants L2 & Review
			tagPolicy:             &noImmutableTagPolicy,
			controls:              slsa_types.Controls{continuityEnforcedEarlier}, // Eligible for L2, but Review control missing
			expectedLevels:        slsa_types.SourceVerifiedLevels{},
			expectError:           true,
			expectedErrorContains: "error computing review enforced: policy requires review, but that control is not enabled",
		},
		{
			name:                  "Error - computeImmutableTags Fails (Policy L2+Tags, Tag control Since later than Policy Since)",
			branchPolicy:          &policyL2TagsEarlier, // Wants L2 & Tags, Policy.Since = earlier
			tagPolicy:             &ProtectedTag{Since: earlierFixedTime, ImmutableTags: true},
			controls:              slsa_types.Controls{continuityEnforcedEarlier, immutableTagsNow}, // Eligible L2, Tag.Since = now
			expectedLevels:        slsa_types.SourceVerifiedLevels{},
			expectError:           true,
			expectedErrorContains: "error computing tag immutability enforced: policy requires immutable tags since", // ... but that control has only been enabled since ...
		},
		{
			name:         "Success - Mixed Requirements (L3, Review, No Tags)",
			branchPolicy: &policyL3Review,
			tagPolicy:    &noImmutableTagPolicy,
			// Wants L3, Review, No Tags
			controls:       slsa_types.Controls{continuityEnforcedEarlier, provenanceAvailableEarlier, reviewEnforcedEarlier}, // Satisfies L3 & Review
			expectedLevels: slsa_types.SourceVerifiedLevels{string(slsa_types.SlsaSourceLevel3), slsa_types.ReviewEnforced},
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLevels, err := evaluateBranchControls(tt.branchPolicy, tt.tagPolicy, tt.controls)

			if tt.expectError {
				if err == nil {
					t.Errorf("evaluateBranchControls() error = nil, want non-nil error containing %q", tt.expectedErrorContains)
				} else if !strings.Contains(err.Error(), tt.expectedErrorContains) {
					t.Errorf("evaluateBranchControls() error = %q, want error containing %q", err.Error(), tt.expectedErrorContains)
				}
			} else {
				if err != nil {
					t.Errorf("evaluateBranchControls() error = %v, want nil", err)
				}
			}

			// Sort slices for robust comparison
			// slsa_types.SourceVerifiedLevels is []string, so we can use sort.Strings
			// Need to import "sort"
			// For now, let's assume the order is fixed by the implementation or ensure expectedLevels are in that order.
			// If tests become flaky due to order, uncomment and import "sort":
			// sort.Strings(gotLevels)
			// sort.Strings(tt.expectedLevels)

			if !reflect.DeepEqual(gotLevels, tt.expectedLevels) {
				// To make debugging easier when DeepEqual fails on slices:
				if len(gotLevels) == 0 && len(tt.expectedLevels) == 0 && tt.expectedLevels == nil && gotLevels != nil {
					// This handles the specific case where expected is nil []string but got is empty non-nil []string
					// reflect.DeepEqual(nil, []string{}) is false.
					// For our purposes, an empty list of verified levels is the same whether it's nil or an empty slice.
					// So if expected is nil and got is empty, we treat as equal.
				} else if len(gotLevels) == 0 && tt.expectedLevels == nil {
					// similar to above, if got is empty and expected is nil
				} else {
					t.Errorf("evaluateBranchControls() gotLevels = %v, want %v", gotLevels, tt.expectedLevels)
				}
			}
		})
	}
}

func TestComputeImmutableTags(t *testing.T) {
	now := time.Now()
	earlier := now.Add(-time.Hour)

	// Branch Policies
	policyRequiresImmutableTagsNow := ProtectedTag{ImmutableTags: true, Since: now}
	policyRequiresImmutableTagsEarlier := ProtectedTag{ImmutableTags: true, Since: earlier}
	policyNotRequiresImmutableTags := ProtectedTag{ImmutableTags: false, Since: now}

	// Controls
	immutableTagsControlEnabledNow := slsa_types.Control{Name: slsa_types.ImmutableTags, Since: now}
	// immutableTagsControlEnabledEarlier := slsa_types.Control{Name: slsa_types.ImmutableTags, Since: earlier} // No longer directly used in a test case

	tests := []struct {
		name                      string
		tagPolicy                 *ProtectedTag
		controls                  slsa_types.Controls
		expectedImmutableEnforced bool
		expectError               bool
		expectedErrorContains     string
	}{
		{
			name:                      "Policy requires immutable tags, control compliant (Policy.Since >= Control.Since)",
			tagPolicy:                 &policyRequiresImmutableTagsNow,
			controls:                  slsa_types.Controls{immutableTagsControlEnabledNow}, // Policy.Since == Control.Since
			expectedImmutableEnforced: true,
			expectError:               false,
		},
		{
			name:                      "Policy does not require immutable tags - control state irrelevant",
			tagPolicy:                 &policyNotRequiresImmutableTags,
			controls:                  slsa_types.Controls{}, // Control state explicitly shown as irrelevant
			expectedImmutableEnforced: false,
			expectError:               false,
		},
		{
			name:                      "Policy requires immutable tags, control not present: fail",
			tagPolicy:                 &policyRequiresImmutableTagsNow,
			controls:                  slsa_types.Controls{}, // Immutable tags control missing
			expectedImmutableEnforced: false,
			expectError:               true,
			expectedErrorContains:     "policy requires immutable tags, but that control is not enabled",
		},
		{
			name:                      "Policy requires immutable tags, control enabled, Policy.Since < Control.Since: fail",
			tagPolicy:                 &policyRequiresImmutableTagsEarlier,                 // Policy.Since is 'earlier'
			controls:                  slsa_types.Controls{immutableTagsControlEnabledNow}, // Control.Since is 'now'
			expectedImmutableEnforced: false,
			expectError:               true,
			expectedErrorContains:     "policy requires immutable tags since", // ...but that control has only been enabled since...
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotEnforced, err := computeImmutableTags(tt.tagPolicy, tt.controls)

			if tt.expectError {
				if err == nil {
					t.Errorf("computeImmutableTags() error = nil, want non-nil error containing %q", tt.expectedErrorContains)
				} else if !strings.Contains(err.Error(), tt.expectedErrorContains) {
					t.Errorf("computeImmutableTags() error = %q, want error containing %q", err.Error(), tt.expectedErrorContains)
				}
			} else {
				if err != nil {
					t.Errorf("computeImmutableTags() error = %v, want nil", err)
				}
			}

			if gotEnforced != tt.expectedImmutableEnforced {
				t.Errorf("computeImmutableTags() gotEnforced = %v, want %v", gotEnforced, tt.expectedImmutableEnforced)
			}
		})
	}
}

func TestComputeReviewEnforced(t *testing.T) {
	now := time.Now()
	earlier := now.Add(-time.Hour)
	// later := now.Add(time.Hour) // Unused

	// Branch Policies
	policyRequiresReviewNow := ProtectedBranch{RequireReview: true, Since: now}
	policyRequiresReviewEarlier := ProtectedBranch{RequireReview: true, Since: earlier}
	policyNotRequiresReview := ProtectedBranch{RequireReview: false, Since: now}

	// Controls
	reviewControlEnabledNow := slsa_types.Control{Name: slsa_types.ReviewEnforced, Since: now}
	// reviewControlEnabledEarlier := slsa_types.Control{Name: slsa_types.ReviewEnforced, Since: earlier} // Not used directly in new structure

	tests := []struct {
		name                   string
		branchPolicy           *ProtectedBranch
		controls               slsa_types.Controls
		expectedReviewEnforced bool
		expectError            bool
		expectedErrorContains  string
	}{
		{
			name:                   "Policy requires review, control compliant (Policy.Since >= Control.Since)",
			branchPolicy:           &policyRequiresReviewNow,
			controls:               slsa_types.Controls{reviewControlEnabledNow}, // Policy.Since == Control.Since
			expectedReviewEnforced: true,
			expectError:            false,
		},
		{
			name:                   "Policy does not require review - control state irrelevant",
			branchPolicy:           &policyNotRequiresReview,
			controls:               slsa_types.Controls{}, // Control state explicitly shown as irrelevant
			expectedReviewEnforced: false,
			expectError:            false,
		},
		{
			name:                   "Policy requires review, control not present: fail",
			branchPolicy:           &policyRequiresReviewNow,
			controls:               slsa_types.Controls{}, // Review control missing
			expectedReviewEnforced: false,
			expectError:            true,
			expectedErrorContains:  "policy requires review, but that control is not enabled",
		},
		{
			name:                   "Policy requires review, control enabled, Policy.Since < Control.Since: fail",
			branchPolicy:           &policyRequiresReviewEarlier,                 // Policy.Since is 'earlier'
			controls:               slsa_types.Controls{reviewControlEnabledNow}, // Control.Since is 'now'
			expectedReviewEnforced: false,
			expectError:            true,
			expectedErrorContains:  "policy requires review since", // ...but that control has only been enabled since...
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotEnforced, err := computeReviewEnforced(tt.branchPolicy, tt.controls)

			if tt.expectError {
				if err == nil {
					t.Errorf("computeReviewEnforced() error = nil, want non-nil error containing %q", tt.expectedErrorContains)
				} else if !strings.Contains(err.Error(), tt.expectedErrorContains) {
					t.Errorf("computeReviewEnforced() error = %q, want error containing %q", err.Error(), tt.expectedErrorContains)
				}
			} else {
				if err != nil {
					t.Errorf("computeReviewEnforced() error = %v, want nil", err)
				}
			}

			if gotEnforced != tt.expectedReviewEnforced {
				t.Errorf("computeReviewEnforced() gotEnforced = %v, want %v", gotEnforced, tt.expectedReviewEnforced)
			}
		})
	}
}

func TestComputeSlsaLevel(t *testing.T) {
	now := time.Now()
	earlier := now.Add(-time.Hour)
	// later := now.Add(time.Hour) // Unused

	// Controls
	continuityEnforcedNow := slsa_types.Control{Name: slsa_types.ContinuityEnforced, Since: now}
	provenanceAvailableNow := slsa_types.Control{Name: slsa_types.ProvenanceAvailable, Since: now}
	continuityEnforcedEarlier := slsa_types.Control{Name: slsa_types.ContinuityEnforced, Since: earlier}
	provenanceAvailableEarlier := slsa_types.Control{Name: slsa_types.ProvenanceAvailable, Since: earlier}

	// Branch Policies
	policyL3Now := ProtectedBranch{TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel3, Since: now}
	// policyL3Later := ProtectedBranch{TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel3, Since: later} // Unused
	policyL2Now := ProtectedBranch{TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel2, Since: now}
	// policyL1Now := ProtectedBranch{TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel1, Since: now} // Unused
	policyUnknownLevel := ProtectedBranch{TargetSlsaSourceLevel: "UNKNOWN_LEVEL", Since: now}

	tests := []struct {
		name                  string
		branchPolicy          *ProtectedBranch
		controls              slsa_types.Controls
		expectedLevel         slsa_types.SlsaSourceLevel
		expectError           bool
		expectedErrorContains string
	}{
		{
			name:          "Controls L3-eligible (since 'earlier'), Policy L2 (since 'now'): success",
			branchPolicy:  &policyL2Now,                                                               // Policy L2, Since 'now'
			controls:      slsa_types.Controls{continuityEnforcedEarlier, provenanceAvailableEarlier}, // Eligible L3 since 'earlier'
			expectedLevel: slsa_types.SlsaSourceLevel2,
			expectError:   false,
		},
		{
			name:                  "Controls L1-eligible, Policy L2: fail (eligibility)",
			branchPolicy:          &policyL2Now,          // Policy L2
			controls:              slsa_types.Controls{}, // Eligible L1
			expectedLevel:         "",
			expectError:           true,
			expectedErrorContains: "policy sets target level SLSA_SOURCE_LEVEL_2, but branch is only eligible for SLSA_SOURCE_LEVEL_1",
		},
		{
			name:          "Eligible L3 (since 'earlier'), Policy L3 (since 'now'): compliant Policy.Since",
			branchPolicy:  &policyL3Now,                                                               // Policy L3, Since 'now'
			controls:      slsa_types.Controls{continuityEnforcedEarlier, provenanceAvailableEarlier}, // Eligible L3 since 'earlier'
			expectedLevel: slsa_types.SlsaSourceLevel3,                                                // Policy.Since ('now') is not before EligibleSince ('earlier')
			expectError:   false,
		},
		{
			name:                  "Controls L3-eligible (since 'now'), Policy L3 (since 'earlier'): fail (Policy.Since too early)",
			branchPolicy:          &ProtectedBranch{TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel3, Since: earlier}, // Policy L3, Since 'earlier'
			controls:              slsa_types.Controls{continuityEnforcedNow, provenanceAvailableNow},                   // Eligible L3 since 'now'
			expectedLevel:         "",
			expectError:           true,
			expectedErrorContains: "policy sets target level SLSA_SOURCE_LEVEL_3 since", // ...but it has only been eligible for that level since...
		},
		{
			name:                  "Policy L?'UNKNOWN' (controls L3-eligible): fail (policy target unknown)",
			branchPolicy:          &policyUnknownLevel,                                                // Policy "UNKNOWN_LEVEL"
			controls:              slsa_types.Controls{continuityEnforcedNow, provenanceAvailableNow}, // Eligible L3
			expectedLevel:         "",
			expectError:           true,
			expectedErrorContains: "policy sets target level UNKNOWN_LEVEL, but branch is only eligible for",
		},
		// This single case covers eligibility failure where target > eligible.
		// It replaces the two previous similar cases:
		// "computeEligibleSince returns nil (controls insufficient for target level)" which was L2 controls for L3 policy
		// "Controls for L1, Policy L3, computeEligibleSince for L3 returns nil" which was L1 controls for L3 policy
		{
			name:                  "Controls L1-eligible, Policy L3: fail (eligibility)",
			branchPolicy:          &policyL3Now,          // Policy L3
			controls:              slsa_types.Controls{}, // Eligible L1
			expectedLevel:         "",
			expectError:           true,
			expectedErrorContains: "policy sets target level SLSA_SOURCE_LEVEL_3, but branch is only eligible for SLSA_SOURCE_LEVEL_1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLevel, err := computeSlsaLevel(tt.branchPolicy, tt.controls)

			if tt.expectError {
				if err == nil {
					t.Errorf("computeSlsaLevel() error = nil, want non-nil error containing %q", tt.expectedErrorContains)
				} else if !strings.Contains(err.Error(), tt.expectedErrorContains) {
					t.Errorf("computeSlsaLevel() error = %q, want error containing %q", err.Error(), tt.expectedErrorContains)
				}
			} else {
				if err != nil {
					t.Errorf("computeSlsaLevel() error = %v, want nil", err)
				}
			}

			if gotLevel != tt.expectedLevel {
				t.Errorf("computeSlsaLevel() gotLevel = %v, want %v", gotLevel, tt.expectedLevel)
			}
		})
	}
}

func TestComputeEligibleSince(t *testing.T) {
	time1 := time.Now()
	time2 := time1.Add(time.Hour)
	zeroTime := time.Time{}

	continuityEnforcedT1 := slsa_types.Control{Name: slsa_types.ContinuityEnforced, Since: time1}
	provenanceAvailableT1 := slsa_types.Control{Name: slsa_types.ProvenanceAvailable, Since: time1}
	continuityEnforcedT2 := slsa_types.Control{Name: slsa_types.ContinuityEnforced, Since: time2}
	provenanceAvailableT2 := slsa_types.Control{Name: slsa_types.ProvenanceAvailable, Since: time2}
	continuityEnforcedZero := slsa_types.Control{Name: slsa_types.ContinuityEnforced, Since: zeroTime}
	provenanceAvailableZero := slsa_types.Control{Name: slsa_types.ProvenanceAvailable, Since: zeroTime}

	tests := []struct {
		name          string
		controls      slsa_types.Controls
		level         slsa_types.SlsaSourceLevel
		expectedTime  *time.Time
		expectError   bool
		expectedError string
	}{
		{
			name:         "L3 eligible (ProvLater), L3 requested: expect Prov.Since",       // Was: "Eligible for SLSA Level 3 - time1 later"
			controls:     slsa_types.Controls{continuityEnforcedT1, provenanceAvailableT2}, // Prov.Since (time2) > Cont.Since (time1)
			level:        slsa_types.SlsaSourceLevel3,
			expectedTime: &time2, // Expect later of the two: time2 (Prov.Since)
			expectError:  false,
		},
		{
			name:         "L3 eligible (ContLater), L3 requested: expect Cont.Since",       // Was: "Eligible for SLSA Level 3 - time2 later"
			controls:     slsa_types.Controls{continuityEnforcedT2, provenanceAvailableT1}, // Cont.Since (time2) > Prov.Since (time1)
			level:        slsa_types.SlsaSourceLevel3,
			expectedTime: &time2, // Expect later of the two: time2 (Cont.Since)
			expectError:  false,
		},
		{
			name:         "L2 eligible (ContOnly), L2 requested: expect Cont.Since", // Was: "Eligible for SLSA Level 2"
			controls:     slsa_types.Controls{continuityEnforcedT1},
			level:        slsa_types.SlsaSourceLevel2,
			expectedTime: &time1,
			expectError:  false,
		},
		{
			name:         "L1 eligible (NoControls), L1 requested: expect ZeroTime", // Was: "Eligible for SLSA Level 1"
			controls:     slsa_types.Controls{},
			level:        slsa_types.SlsaSourceLevel1,
			expectedTime: &zeroTime,
			expectError:  false,
		},
		{
			name:         "L3 eligible, L2 requested: expect Cont.Since",                   // Was: "Controls for Level 3, requesting Level 2"
			controls:     slsa_types.Controls{continuityEnforcedT1, provenanceAvailableT2}, // Eligible for L3 (Cont.Since T1, Prov.Since T2)
			level:        slsa_types.SlsaSourceLevel2,                                      // Requesting L2
			expectedTime: &time1,                                                           // Expect Cont.Since (T1)
			expectError:  false,
		},
		{
			name:         "L2 eligible, L3 requested: expect nil, no error", // Was: "Controls for Level 2, requesting Level 3"
			controls:     slsa_types.Controls{continuityEnforcedT1},         // Eligible for L2
			level:        slsa_types.SlsaSourceLevel3,                       // Requesting L3
			expectedTime: nil,                                               // Not eligible for L3
			expectError:  false,
		},
		{
			name:          "Unknown level requested: expect nil, error", // Was: "Unknown SLSA level"
			controls:      slsa_types.Controls{},
			level:         slsa_types.SlsaSourceLevel("UNKNOWN_LEVEL"),
			expectedTime:  nil,
			expectError:   true,
			expectedError: "unknown level UNKNOWN_LEVEL",
		},
		{
			name:         "L3 eligible (ContZero, ProvNonZero), L3 requested: expect Prov.Since", // Was: "Controls for SLSA Level 3, continuity zero time"
			controls:     slsa_types.Controls{continuityEnforcedZero, provenanceAvailableT2},     // Prov.Since (time2) is non-zero
			level:        slsa_types.SlsaSourceLevel3,
			expectedTime: &time2, // Expect Prov.Since
			expectError:  false,
		},
		{
			name:         "L3 eligible (ContNonZero, ProvZero), L3 requested: expect Cont.Since", // Was: "Controls for SLSA Level 3, provenance zero time"
			controls:     slsa_types.Controls{continuityEnforcedT1, provenanceAvailableZero},     // Cont.Since (time1) is non-zero
			level:        slsa_types.SlsaSourceLevel3,
			expectedTime: &time1, // Expect Cont.Since
			expectError:  false,
		},
		{
			name:         "L3 eligible (BothZero), L3 requested: expect ZeroTime", // Was: "Controls for SLSA Level 3, both zero time"
			controls:     slsa_types.Controls{continuityEnforcedZero, provenanceAvailableZero},
			level:        slsa_types.SlsaSourceLevel3,
			expectedTime: &zeroTime,
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotTime, err := computeEligibleSince(tt.controls, tt.level)

			if tt.expectError {
				if err == nil {
					t.Errorf("computeEligibleSince() error = nil, want non-nil error")
				} else if err.Error() != tt.expectedError {
					t.Errorf("computeEligibleSince() error = %q, want %q", err.Error(), tt.expectedError)
				}
			} else {
				if err != nil {
					t.Errorf("computeEligibleSince() error = %v, want nil", err)
				}
			}

			if tt.expectedTime == nil {
				if gotTime != nil {
					t.Errorf("computeEligibleSince() gotTime = %v, want nil", gotTime)
				}
			} else {
				if gotTime == nil {
					t.Errorf("computeEligibleSince() gotTime = nil, want %v", *tt.expectedTime)
				} else if !gotTime.Equal(*tt.expectedTime) {
					t.Errorf("computeEligibleSince() gotTime = %v, want %v", *gotTime, *tt.expectedTime)
				}
			}
		})
	}
}

func assertPolicyResultEquals(t *testing.T, ctx context.Context, ghConn *gh_control.GitHubConnection, pe *PolicyEvaluator, expectedPolicy *RepoPolicy, expectedBranchPolicy *ProtectedBranch, expectedPath string) {
	rp, gotPath, err := pe.getPolicy(ctx, ghConn)

	if err != nil {
		t.Fatalf("getPolicy() error = %v, want nil", err)
	}
	if gotPath != expectedPath {
		t.Errorf("getPolicy() gotPath = %q, want %q (temp file path)", gotPath, expectedPath)
	}
	if expectedPolicy == nil {
		if rp != nil {
			t.Fatalf("getPolicy() expectedPolicy == nil but got non-nil policy %+v", rp)
		}
		return // quite while we're ahead
	}

	if rp == nil {
		t.Fatalf("getPolicy() rp is nil but expectedPolicy is not")
	}

	// TODO: check the rest of the contents of expectedPolicy?

	gotPb := rp.getBranchPolicy(gh_control.GetBranchFromRef(ghConn.GetFullRef()))

	if expectedBranchPolicy == nil {
		if gotPb != nil {
			t.Fatalf("getPolicy() expectedBranchPolicy == nil but got non-nil branch policy %+v", rp)
		}
		return
	}

	assertProtectedBranchEquals(t, gotPb, *expectedBranchPolicy, false)
}

func TestGetPolicy_Local_SpecificFound(t *testing.T) {
	pb := createTestBranchPolicy("feature")
	policyToCreate := createTestPolicy(pb)

	ctx := context.Background()
	ghConn := newTestGhBranchConnection("any", "any", "feature")
	pe := &PolicyEvaluator{}

	policyFilePath := createTempPolicyFile(t, policyToCreate)
	defer os.Remove(policyFilePath)
	pe.UseLocalPolicy = policyFilePath

	assertPolicyResultEquals(t, ctx, ghConn, pe, &policyToCreate, &pb, policyFilePath)
}

func TestGetPolicy_Local_NotFoundCases(t *testing.T) {
	tests := []struct {
		name           string
		branchName     string
		policyToCreate RepoPolicy
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
			name:           "local policy exists, ProtectedBranches nil",
			branchName:     "main",
			policyToCreate: RepoPolicy{ProtectedBranches: nil},
		},
		{
			name:           "local policy exists, ProtectedBranches empty",
			branchName:     "main",
			policyToCreate: RepoPolicy{ProtectedBranches: []ProtectedBranch{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			ghConn := newTestGhBranchConnection("any", "any", tt.branchName)
			pe := &PolicyEvaluator{}

			policyFilePath := createTempPolicyFile(t, tt.policyToCreate)
			defer os.Remove(policyFilePath)
			pe.UseLocalPolicy = policyFilePath

			assertPolicyResultEquals(t, ctx, ghConn, pe, &tt.policyToCreate, nil, policyFilePath)
		})
	}
}

func TestGetPolicy_Local_ErrorCases(t *testing.T) {
	tests := []struct {
		name               string
		branchName         string
		policyFileContent  interface{} // RepoPolicy or string for malformed
		useLocalPolicyPath string      // "CREATE_TEMP", or specific path for non-existent
	}{
		{
			name:               "local policy file is malformed JSON",
			branchName:         "main",
			policyFileContent:  "this is not valid json",
			useLocalPolicyPath: "CREATE_TEMP",
		},
		{
			name:               "local policy file does not exist",
			branchName:         "main",
			policyFileContent:  nil, // No file created for this case
			useLocalPolicyPath: "/path/to/nonexistent/policy.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			ghConn := newTestGhBranchConnection("any", "any", tt.branchName)
			pe := &PolicyEvaluator{}
			var policyFilePath string

			if tt.useLocalPolicyPath == "CREATE_TEMP" {
				if tt.policyFileContent == nil {
					t.Fatal("policyFileContent cannot be nil when useLocalPolicyPath is CREATE_TEMP for error cases")
				}
				policyFilePath = createTempPolicyFile(t, tt.policyFileContent)
				defer os.Remove(policyFilePath) // Ensure cleanup even if test expects error
				pe.UseLocalPolicy = policyFilePath
			} else {
				pe.UseLocalPolicy = tt.useLocalPolicyPath // For non-existent file
			}

			gotRp, gotPath, err := pe.getPolicy(ctx, ghConn)

			if err == nil {
				t.Errorf("getPolicy() error = nil, want non-nil error")
			}
			if gotRp != nil {
				t.Errorf("getPolicy() gotRp = %v, want nil", gotRp)
			}
			if gotPath != "" {
				t.Errorf("getPolicy() gotPath = %q, want \"\"", gotPath)
			}
		})
	}
}

func TestGetPolicy_Remote_SpecificFound(t *testing.T) {
	mockPolicyPath := "https://github.example.com/policy.json"
	targetOwner := "owner"
	targetBranch := "feature"
	targetRepo := "repo"
	pb := createTestBranchPolicy(targetBranch)
	expectedPolicy := createTestPolicy(pb)

	ctx := context.Background()
	pe := &PolicyEvaluator{UseLocalPolicy: ""}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		validateMockServerRequestPath(t, r, targetOwner, targetRepo, targetBranch)
		w.WriteHeader(http.StatusOK) // Always OK for this test function
		policyJSON, err := json.Marshal(expectedPolicy)
		if err != nil {
			t.Fatalf("Failed to marshal RepoPolicy for mock: %v", err)
		}
		encodedContent := base64.StdEncoding.EncodeToString(policyJSON)
		mockFileContent := &github.RepositoryContent{
			Type:     github.String("file"),
			Encoding: github.String("base64"),
			Content:  github.String(encodedContent),
			HTMLURL:  github.String(mockPolicyPath),
		}
		respData, err := json.Marshal(mockFileContent)
		if err != nil {
			t.Fatalf("Failed to marshal mock RepositoryContent: %v", err)
		}
		_, _ = w.Write(respData)
	})

	ghConn, mockServer := setupMockGitHubTestEnv(t, targetOwner, targetRepo, targetBranch, handler)
	defer mockServer.Close()

	assertPolicyResultEquals(t, ctx, ghConn, pe, &expectedPolicy, &pb, mockPolicyPath)
}

func TestGetPolicy_Remote_NotFoundCases(t *testing.T) {
	mockPolicyPath := "https://github.example.com/policy.json"
	targetOwner := "test-owner"
	targetRepo := "test-repo"

	tests := []struct {
		name               string
		targetBranch       string
		mockHTTPStatus     int
		mockPolicyContent  *RepoPolicy // Pointer to allow nil for 404 case
		expectedPolicyPath string
	}{
		{
			name:           "remote policy fetch success, branch not found",
			targetBranch:   "develop",
			mockHTTPStatus: http.StatusOK,
			mockPolicyContent: &RepoPolicy{
				ProtectedBranches: []ProtectedBranch{
					{Name: "main", Since: fixedTime, TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel3},
				},
			},
			expectedPolicyPath: mockPolicyPath,
		},
		{
			name:               "remote policy fetch success, empty protected branches",
			targetBranch:       "main",
			mockHTTPStatus:     http.StatusOK,
			mockPolicyContent:  &RepoPolicy{ProtectedBranches: []ProtectedBranch{}},
			expectedPolicyPath: mockPolicyPath,
		},
		{
			name:               "remote policy fetch success, nil protected branches",
			targetBranch:       "main",
			mockHTTPStatus:     http.StatusOK,
			mockPolicyContent:  &RepoPolicy{ProtectedBranches: nil},
			expectedPolicyPath: mockPolicyPath,
		},
		{
			name:               "remote policy API returns 404 Not Found",
			targetBranch:       "main",
			mockHTTPStatus:     http.StatusNotFound,
			mockPolicyContent:  nil, // No policy content for 404
			expectedPolicyPath: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			pe := &PolicyEvaluator{UseLocalPolicy: ""}

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				validateMockServerRequestPath(t, r, targetOwner, targetRepo, tt.targetBranch)
				w.WriteHeader(tt.mockHTTPStatus)
				if tt.mockHTTPStatus == http.StatusOK && tt.mockPolicyContent != nil {
					policyJSON, err := json.Marshal(*tt.mockPolicyContent)
					if err != nil {
						t.Fatalf("Failed to marshal RepoPolicy for mock: %v", err)
					}
					encodedContent := base64.StdEncoding.EncodeToString(policyJSON)
					mockFileContent := &github.RepositoryContent{
						Type:     github.Ptr("file"),
						Encoding: github.Ptr("base64"),
						Content:  github.Ptr(encodedContent),
						HTMLURL:  github.Ptr(mockPolicyPath),
					}
					respData, err := json.Marshal(mockFileContent)
					if err != nil {
						t.Fatalf("Failed to marshal mock RepositoryContent: %v", err)
					}
					_, _ = w.Write(respData)
				}
			})

			ghConn, mockServer := setupMockGitHubTestEnv(t, targetOwner, targetRepo, tt.targetBranch, handler)
			defer mockServer.Close()

			assertPolicyResultEquals(t, ctx, ghConn, pe, tt.mockPolicyContent, nil, tt.expectedPolicyPath)
		})
	}
}

func TestGetPolicy_Remote_ServerError(t *testing.T) {
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

	pe := PolicyEvaluator{UseLocalPolicy: ""}
	// ghConn is now returned by setupMockGitHubTestEnv

	gotPolicy, gotPath, err := pe.getPolicy(ctx, ghConn)
	if err == nil {
		t.Errorf("Expected an error for server-side issues, got nil")
	}
	if gotPolicy != nil {
		t.Errorf("Expected policy to be nil on server error, got %v", gotPolicy)
	}
	if gotPath != "" {
		t.Errorf("Expected path to be empty on server error, got %q", gotPath)
	}
}

func TestGetPolicy_Remote_MalformedJSON(t *testing.T) {
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

			pe := PolicyEvaluator{UseLocalPolicy: ""}

			gotPolicy, gotPath, err := pe.getPolicy(ctx, ghConn)
			if err == nil {
				t.Errorf("Expected an error for malformed JSON, got nil")
			}
			if gotPolicy != nil {
				t.Errorf("Expected policy to be nil on malformed JSON, got %v", gotPolicy)
			}
			if gotPath != "" { // Path should be empty as we error out before using HTMLURL
				t.Errorf("Expected path to be empty on malformed JSON, got %q", gotPath)
			}
		})
	}
}
