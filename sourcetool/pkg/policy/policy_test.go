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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v69/github" // Use v69
	spb "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/attest"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/ghcontrol"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/slsa"
)

const (
	testRepo       = "test-repo"
	testOwner      = "test-owner"
	mockPolicyPath = "https://github.example.com/policy.json"
)

var (
	fixedTime        = time.Unix(1678886400, 0) // March 15, 2023 00:00:00 UTC
	earlierFixedTime = fixedTime.Add(-time.Hour)
	laterFixedTime   = fixedTime.Add(time.Hour)
)

func createTestBranchPolicy(branch string) ProtectedBranch {
	return ProtectedBranch{
		Name:                  branch,
		Since:                 fixedTime,
		TargetSlsaSourceLevel: slsa.SlsaSourceLevel2,
		RequireReview:         true,
	}
}

func createTestPolicy(pb *ProtectedBranch) RepoPolicy {
	return RepoPolicy{
		CanonicalRepo: "the-canonical-repo",
		ProtectedBranches: []ProtectedBranch{
			*pb,
		},
		ProtectedTag: &ProtectedTag{
			Since:      fixedTime,
			TagHygiene: true,
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
func newTestGhBranchConnection(owner, repo, branch string) *ghcontrol.GitHubConnection {
	return ghcontrol.NewGhConnectionWithClient(owner, repo, ghcontrol.BranchToFullRef(branch), nil)
}

// createTempPolicyFile creates a temporary file with the given policy data.
// If policyData is a RepoPolicy, it's marshalled to JSON.
// If policyData is a string, it's written directly.
func createTempPolicyFile(t *testing.T, policyData interface{}) string {
	t.Helper()
	tmpFile, err := os.CreateTemp(t.TempDir(), "test-policy-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp policy file: %v", err)
	}
	defer tmpFile.Close() //nolint:errcheck

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
	continuityEnforcedEarlier := slsa.Control{Name: slsa.ContinuityEnforced, Since: earlierFixedTime}
	provenanceAvailableEarlier := slsa.Control{Name: slsa.ProvenanceAvailable, Since: earlierFixedTime}
	reviewEnforcedEarlier := slsa.Control{Name: slsa.ReviewEnforced, Since: earlierFixedTime}
	tagHygieneEarlier := slsa.Control{Name: slsa.TagHygiene, Since: earlierFixedTime}
	orgTestControl := slsa.Control{Name: "GH_REQUIRED_CHECK_test", Since: earlierFixedTime}

	// Valid Provenance Predicate (attest.SourceProvenancePred)
	validProvPredicateL3Controls := attest.SourceProvenancePred{
		Controls: slsa.Controls{continuityEnforcedEarlier, provenanceAvailableEarlier, reviewEnforcedEarlier, tagHygieneEarlier, orgTestControl},
	}

	provenanceStatement := createStatementForTest(t, validProvPredicateL3Controls, attest.SourceProvPredicateType)

	pb := ProtectedBranch{
		Name:                  "main",
		TargetSlsaSourceLevel: slsa.SlsaSourceLevel3,
		RequireReview:         true,
		Since:                 fixedTime,
		RequiredStatusChecks: []OrgStatusCheckControl{
			{
				CheckName:    "test",
				PropertyName: "ORG_SOURCE_TESTED",
				Since:        fixedTime,
			},
		},
	}
	rp := createTestPolicy(&pb)
	rp.ProtectedTag.Since = fixedTime
	rp.ProtectedTag.TagHygiene = true

	expectedPolicyFilePath := createTempPolicyFile(t, rp)
	defer os.Remove(expectedPolicyFilePath) //nolint:errcheck
	pe := &PolicyEvaluator{UseLocalPolicy: expectedPolicyFilePath}

	ghConn := newTestGhBranchConnection("local", "local", "main")

	verifiedLevels, policyPath, err := pe.EvaluateSourceProv(t.Context(), ghConn, provenanceStatement)
	if err != nil {
		t.Errorf("EvaluateSourceProv() error = %v, want nil", err)
	}
	if policyPath != expectedPolicyFilePath {
		t.Errorf("EvaluateSourceProv() policyPath = %q, want %q", policyPath, expectedPolicyFilePath)
	}
	expectedLevels := slsa.SourceVerifiedLevels{slsa.ControlName(slsa.SlsaSourceLevel3), slsa.ReviewEnforced, slsa.TagHygiene, "ORG_SOURCE_TESTED"}
	if !slices.Equal(verifiedLevels, expectedLevels) {
		t.Errorf("EvaluateSourceProv() verifiedLevels = %v, want %v", verifiedLevels, expectedLevels)
	}
}

func TestEvaluateSourceProv_Failure(t *testing.T) {
	// Controls for mock provenance
	continuityEnforcedEarlier := slsa.Control{Name: slsa.ContinuityEnforced, Since: earlierFixedTime}
	provenanceAvailableEarlier := slsa.Control{Name: slsa.ProvenanceAvailable, Since: earlierFixedTime}
	reviewEnforcedEarlier := slsa.Control{Name: slsa.ReviewEnforced, Since: earlierFixedTime}
	tagHygieneEarlier := slsa.Control{Name: slsa.TagHygiene, Since: earlierFixedTime}

	// Policies
	policyL3ReviewTagsNow := RepoPolicy{
		ProtectedBranches: []ProtectedBranch{
			{Name: "main", TargetSlsaSourceLevel: slsa.SlsaSourceLevel3, RequireReview: true, Since: fixedTime},
		},
		ProtectedTag: &ProtectedTag{Since: fixedTime, TagHygiene: true},
	}
	policyL1NoExtrasNow := RepoPolicy{ // Policy for default/branch not found cases
		ProtectedBranches: []ProtectedBranch{
			{Name: "otherbranch", TargetSlsaSourceLevel: slsa.SlsaSourceLevel1, Since: fixedTime},
		},
		ProtectedTag: nil,
	}

	// Valid Provenance Predicate (attest.SourceProvenancePred)
	validProvPredicateL3Controls := attest.SourceProvenancePred{
		Controls: slsa.Controls{continuityEnforcedEarlier, provenanceAvailableEarlier, reviewEnforcedEarlier, tagHygieneEarlier},
	}
	validProvPredicateL2Controls := attest.SourceProvenancePred{
		Controls: slsa.Controls{continuityEnforcedEarlier, tagHygieneEarlier, reviewEnforcedEarlier}, // Missing provenanceAvailable for L3
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
			expectedErrorContains: "policy sets target level SLSA_SOURCE_LEVEL_3 which requires [CONTINUITY_ENFORCED TAG_HYGIENE PROVENANCE_AVAILABLE], but branch is only eligible for SLSA_SOURCE_LEVEL_2 because it only has [CONTINUITY_ENFORCED TAG_HYGIENE REVIEW_ENFORCED]",
		},
		{
			name:                  "Malformed Policy JSON -> Error",
			policyContent:         "not valid policy json",
			provenanceStatement:   createStatementForTest(t, validProvPredicateL3Controls, attest.SourceProvPredicateType),
			ghConnBranch:          "main",
			expectedErrorContains: "invalid character 'o' in literal null (expecting 'u')", // Error from GetPolicy via getLocalPolicy
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
			ctx := t.Context()
			pe := &PolicyEvaluator{}
			var ghConn *ghcontrol.GitHubConnection

			if tt.name == "Non-existent Policy File -> Error" {
				pe.UseLocalPolicy = "/path/to/nonexistent/test/policy.json" // Specific path for this test
			} else if tt.policyContent != nil {
				policyFilePath := createTempPolicyFile(t, tt.policyContent)
				defer os.Remove(policyFilePath) //nolint:errcheck
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

func createVsaSummary(ref string, verifiedLevels []slsa.ControlName) attest.VsaSummary {
	return attest.VsaSummary{
		SourceRefs:     []string{ref},
		VerifiedLevels: verifiedLevels,
	}
}

func TestEvaluateTagProv_Success(t *testing.T) {
	// Controls for mock provenance
	tagHygieneEarlier := slsa.Control{Name: slsa.TagHygiene, Since: earlierFixedTime}
	origL2ReviewedSummary := createVsaSummary("refs/heads/orig", []slsa.ControlName{
		slsa.ControlName(slsa.SlsaSourceLevel2), slsa.ReviewEnforced,
	})
	mainL3Summary := createVsaSummary("refs/heads/main", []slsa.ControlName{
		slsa.ControlName(slsa.SlsaSourceLevel3),
	})

	tests := []struct {
		name               string
		protectedTagPolicy *ProtectedTag
		vsaSummaries       []attest.VsaSummary
		expectedLevels     slsa.SourceVerifiedLevels
	}{
		{
			name: "Policy has protected_tag setting, and enabled",
			protectedTagPolicy: &ProtectedTag{
				Since:      fixedTime,
				TagHygiene: true,
			},
			vsaSummaries:   []attest.VsaSummary{origL2ReviewedSummary},
			expectedLevels: slsa.SourceVerifiedLevels{slsa.ReviewEnforced, slsa.ControlName(slsa.SlsaSourceLevel2)},
		},
		{
			name: "Policy has protected_tag setting, and multiple summaries",
			protectedTagPolicy: &ProtectedTag{
				Since:      fixedTime,
				TagHygiene: true,
			},
			vsaSummaries: []attest.VsaSummary{origL2ReviewedSummary, mainL3Summary},
			// The spec says we MUST NOT return multiple levels per track in a VSA...
			expectedLevels: slsa.SourceVerifiedLevels{
				slsa.ReviewEnforced, slsa.ControlName(slsa.SlsaSourceLevel3),
			},
		},
		{
			name: "Policy has protected_tag setting, and it's not enabled",
			protectedTagPolicy: &ProtectedTag{
				Since:      fixedTime,
				TagHygiene: false,
			},
			vsaSummaries:   []attest.VsaSummary{origL2ReviewedSummary},
			expectedLevels: slsa.SourceVerifiedLevels{slsa.ControlName(slsa.SlsaSourceLevel1)},
		},
		{
			name: "Policy has protected_tag setting, and it's earlier than the control",
			protectedTagPolicy: &ProtectedTag{
				Since:      earlierFixedTime,
				TagHygiene: false,
			},
			vsaSummaries:   []attest.VsaSummary{origL2ReviewedSummary},
			expectedLevels: slsa.SourceVerifiedLevels{slsa.ControlName(slsa.SlsaSourceLevel1)},
		},
		{
			name:               "Policy has no protected_tag setting",
			protectedTagPolicy: nil,
			vsaSummaries:       []attest.VsaSummary{origL2ReviewedSummary},
			expectedLevels:     slsa.SourceVerifiedLevels{slsa.ControlName(slsa.SlsaSourceLevel1)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Valid Provenance Predicate (attest.SourceProvenancePred)
			tagProvPred := attest.TagProvenancePred{
				Controls:     slsa.Controls{tagHygieneEarlier},
				VsaSummaries: tt.vsaSummaries,
			}

			provenanceStatement := createStatementForTest(t, tagProvPred, attest.TagProvPredicateType)

			pb := ProtectedBranch{
				Name:                  "main",
				TargetSlsaSourceLevel: slsa.SlsaSourceLevel2,
				RequireReview:         true,
				Since:                 fixedTime,
			}
			rp := createTestPolicy(&pb)
			rp.ProtectedTag = tt.protectedTagPolicy

			expectedPolicyFilePath := createTempPolicyFile(t, rp)
			defer os.Remove(expectedPolicyFilePath) //nolint:errcheck
			pe := &PolicyEvaluator{UseLocalPolicy: expectedPolicyFilePath}

			ghConn := newTestGhBranchConnection("local", "local", "main")

			verifiedLevels, policyPath, err := pe.EvaluateTagProv(t.Context(), ghConn, provenanceStatement)
			if err != nil {
				t.Errorf("EvaluateTagProv() error = %v, want nil", err)
			}
			if policyPath != expectedPolicyFilePath {
				t.Errorf("EvaluateTagProv() policyPath = %q, want %q", policyPath, expectedPolicyFilePath)
			}
			if !slices.Equal(verifiedLevels, tt.expectedLevels) {
				t.Errorf("EvaluateTagProv() verifiedLevels = %v, want %v", verifiedLevels, tt.expectedLevels)
			}
		})
	}
}

func TestEvaluateControl_Success(t *testing.T) {
	// Controls
	continuityEnforcedEarlier := slsa.Control{Name: slsa.ContinuityEnforced, Since: earlierFixedTime}
	provenanceAvailableEarlier := slsa.Control{Name: slsa.ProvenanceAvailable, Since: earlierFixedTime}
	reviewEnforcedEarlier := slsa.Control{Name: slsa.ReviewEnforced, Since: earlierFixedTime}
	tagHygieneEarlier := slsa.Control{Name: slsa.TagHygiene, Since: earlierFixedTime}
	orgTestControl := slsa.Control{Name: "GH_REQUIRED_CHECK_test", Since: earlierFixedTime}

	// Policies
	fullPolicy := RepoPolicy{
		ProtectedBranches: []ProtectedBranch{
			{
				Name:                  "main",
				TargetSlsaSourceLevel: slsa.SlsaSourceLevel3,
				RequireReview:         true,
				Since:                 fixedTime,
				RequiredStatusChecks: []OrgStatusCheckControl{
					{
						CheckName:    "test",
						Since:        fixedTime,
						PropertyName: "ORG_SOURCE_TESTED",
					},
				},
			},
		},
		ProtectedTag: &ProtectedTag{
			Since:      fixedTime,
			TagHygiene: true,
		},
	}
	basicPolicy := RepoPolicy{
		ProtectedBranches: []ProtectedBranch{
			{Name: "main", TargetSlsaSourceLevel: slsa.SlsaSourceLevel1, Since: fixedTime},
		},
	}

	tests := []struct {
		name               string
		policyContent      interface{} // RepoPolicy or string for malformed
		controlStatus      *ghcontrol.GhControlStatus
		ghConnBranch       string // Branch for GitHub connection
		expectedLevels     slsa.SourceVerifiedLevels
		expectedPolicyPath string
	}{
		{
			name:          "Commit time before policy Since -> SLSA Level 1",
			policyContent: fullPolicy,
			controlStatus: &ghcontrol.GhControlStatus{
				CommitPushTime: earlierFixedTime, // Commit time before policyL3ReviewTagsNow.Since (now)
				Controls:       slsa.Controls{continuityEnforcedEarlier, provenanceAvailableEarlier, reviewEnforcedEarlier, tagHygieneEarlier, orgTestControl},
			},
			ghConnBranch:       "main",
			expectedLevels:     slsa.SourceVerifiedLevels{slsa.ControlName(slsa.SlsaSourceLevel1)}, // Expect L1 because commit time is before policy enforcement
			expectedPolicyPath: "TEMP_POLICY_FILE_PATH",                                            // Placeholder, will be replaced by actual temp file path
		},
		{
			name:          "Commit time after policy Since, controls meet policy -> Expected levels",
			policyContent: fullPolicy,
			controlStatus: &ghcontrol.GhControlStatus{
				CommitPushTime: laterFixedTime,
				Controls:       slsa.Controls{continuityEnforcedEarlier, provenanceAvailableEarlier, reviewEnforcedEarlier, tagHygieneEarlier, orgTestControl},
			},
			ghConnBranch:       "main",
			expectedLevels:     slsa.SourceVerifiedLevels{slsa.ControlName(slsa.SlsaSourceLevel3), slsa.ReviewEnforced, slsa.TagHygiene, "ORG_SOURCE_TESTED"},
			expectedPolicyPath: "TEMP_POLICY_FILE_PATH",
		},
		{
			name:          "Branch not in policy, commit after default policy since -> Default policy (SLSA L1)",
			policyContent: basicPolicy, // main is in policy, but we test "develop"
			controlStatus: &ghcontrol.GhControlStatus{
				CommitPushTime: laterFixedTime,
				Controls:       slsa.Controls{continuityEnforcedEarlier, provenanceAvailableEarlier, reviewEnforcedEarlier, tagHygieneEarlier, orgTestControl},
			},
			ghConnBranch:       "develop",                                                          // Testing "develop" branch
			expectedLevels:     slsa.SourceVerifiedLevels{slsa.ControlName(slsa.SlsaSourceLevel1)}, // Default is L1
			expectedPolicyPath: "DEFAULT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			pe := &PolicyEvaluator{}
			var ghConn *ghcontrol.GitHubConnection
			actualPolicyPath := tt.expectedPolicyPath // May be overridden for local temp file

			if tt.policyContent != nil {
				policyFilePath := createTempPolicyFile(t, tt.policyContent)
				defer os.Remove(policyFilePath) //nolint:errcheck
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
				if len(verifiedLevels) != 0 || len(tt.expectedLevels) != 0 {
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
	continuityEnforcedEarlier := slsa.Control{Name: slsa.ContinuityEnforced, Since: earlier}
	tagHygieneEarlier := slsa.Control{Name: slsa.TagHygiene, Since: earlier}

	// Policies
	policyL3Review := RepoPolicy{
		ProtectedBranches: []ProtectedBranch{
			{Name: "main", TargetSlsaSourceLevel: slsa.SlsaSourceLevel3, RequireReview: true, Since: now},
		},
	}

	tests := []struct {
		name                  string
		policyContent         interface{} // RepoPolicy or string for malformed
		controlStatus         *ghcontrol.GhControlStatus
		ghConnBranch          string // Branch for GitHub connection
		expectedErrorContains string
	}{
		{
			name:          "Commit time after policy Since, controls DO NOT meet policy -> Error",
			policyContent: policyL3Review, // Requires L3, Review, Tags
			controlStatus: &ghcontrol.GhControlStatus{
				CommitPushTime: later,                                                       // Commit time after policy.Since
				Controls:       slsa.Controls{continuityEnforcedEarlier, tagHygieneEarlier}, // Only meets L2
			},
			ghConnBranch:          "main",
			expectedErrorContains: "but branch is only eligible for SLSA_SOURCE_LEVEL_2",
		},
		{
			name:          "Malformed JSON -> Error",
			policyContent: "not json",
			controlStatus: &ghcontrol.GhControlStatus{
				CommitPushTime: later,
				Controls:       slsa.Controls{},
			},
			ghConnBranch:          "main",
			expectedErrorContains: "invalid character 'o' in literal null (expecting 'u')", // Error from json.Unmarshal
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			pe := &PolicyEvaluator{}
			var ghConn *ghcontrol.GitHubConnection
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
					defer os.Remove(policyFilePath) //nolint:errcheck
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
func setupMockGitHubTestEnv(t *testing.T, targetOwner, targetRepo, targetBranch string, handler http.HandlerFunc) (*ghcontrol.GitHubConnection, *httptest.Server) {
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

	ghConn := ghcontrol.NewGhConnectionWithClient(targetOwner, targetRepo, targetBranch, ghClient)
	return ghConn, server
}

// assertProtectedBranchEquals compares two ProtectedBranch structs for equality,
// optionally ignoring the 'Since' field. It provides a detailed error message
// if they are not equal.
func assertProtectedBranchEquals(t *testing.T, got, expected *ProtectedBranch, ignoreSince bool) {
	t.Helper()
	if got == nil {
		return
	}

	actual := *got
	actualCopy := actual
	expectedCopy := *expected
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
		t.Error(errorMessage.String())
	}
}

// Constants for policy hosting repo, mirror what's in policy.go
const (
	sourcePolicyRepoOwner = "slsa-framework"
	sourcePolicyRepo      = "slsa-source-poc"
)

func TestComputeEligibleSlsaLevel(t *testing.T) {
	continuityEnforcedControl := slsa.Control{Name: slsa.ContinuityEnforced, Since: fixedTime}
	provenanceAvailableControl := slsa.Control{Name: slsa.ProvenanceAvailable, Since: fixedTime}
	reviewEnforcedControl := slsa.Control{Name: slsa.ReviewEnforced, Since: fixedTime}
	tagHygieneControl := slsa.Control{Name: slsa.TagHygiene, Since: fixedTime}

	tests := []struct {
		name           string
		controls       slsa.Controls
		expectedLevel  slsa.SlsaSourceLevel
		expectedReason string
	}{
		{
			name:          "SLSA Level 4",
			controls:      slsa.Controls{continuityEnforcedControl, provenanceAvailableControl, reviewEnforcedControl, tagHygieneControl},
			expectedLevel: slsa.SlsaSourceLevel4,
		},
		{
			name:          "SLSA Level 3",
			controls:      slsa.Controls{continuityEnforcedControl, provenanceAvailableControl, tagHygieneControl},
			expectedLevel: slsa.SlsaSourceLevel3,
		},
		{
			name:          "SLSA Level 2",
			controls:      slsa.Controls{continuityEnforcedControl, tagHygieneControl},
			expectedLevel: slsa.SlsaSourceLevel2,
		},
		{
			name:          "SLSA Level 1 - ProvenanceAvailable only",
			controls:      slsa.Controls{provenanceAvailableControl},
			expectedLevel: slsa.SlsaSourceLevel1,
		},
		{
			name:          "SLSA Level 1 - ContinuityEnforced control absent",
			controls:      nil, // Represents absence of ContinuityEnforced; could also use slsa.Controls{}
			expectedLevel: slsa.SlsaSourceLevel1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level := computeEligibleSlsaLevel(tt.controls)
			if level != tt.expectedLevel {
				t.Errorf("computeEligibleSlsaLevel() level = %v, want %v", level, tt.expectedLevel)
			}
		})
	}
}

func TestEvaluateBranchControls(t *testing.T) {
	// Controls
	continuityEnforcedEarlier := slsa.Control{Name: slsa.ContinuityEnforced, Since: earlierFixedTime}
	provenanceAvailableEarlier := slsa.Control{Name: slsa.ProvenanceAvailable, Since: earlierFixedTime}
	reviewEnforcedEarlier := slsa.Control{Name: slsa.ReviewEnforced, Since: earlierFixedTime}
	tagHygieneEarlier := slsa.Control{Name: slsa.TagHygiene, Since: earlierFixedTime}
	tagHygieneNow := slsa.Control{Name: slsa.TagHygiene, Since: fixedTime}

	// Branch Policies
	policyL3Review := ProtectedBranch{TargetSlsaSourceLevel: slsa.SlsaSourceLevel3, RequireReview: true, Since: fixedTime}
	policyL4 := ProtectedBranch{TargetSlsaSourceLevel: slsa.SlsaSourceLevel4, Since: fixedTime}
	policyL1NoExtras := ProtectedBranch{TargetSlsaSourceLevel: slsa.SlsaSourceLevel1, RequireReview: false, Since: fixedTime}
	policyL2Review := ProtectedBranch{TargetSlsaSourceLevel: slsa.SlsaSourceLevel2, RequireReview: true, Since: fixedTime}
	policyL2NoReview := ProtectedBranch{TargetSlsaSourceLevel: slsa.SlsaSourceLevel2, RequireReview: false, Since: fixedTime}

	// Tag policies
	tagHygienePolicy := ProtectedTag{Since: fixedTime, TagHygiene: true}
	noTagHygienePolicy := ProtectedTag{Since: fixedTime, TagHygiene: false}

	// Policy Since 'earlier' for testing control.Since > policy.Since
	policyL1Earlier := ProtectedBranch{TargetSlsaSourceLevel: slsa.SlsaSourceLevel1, RequireReview: false, Since: earlierFixedTime}

	tests := []struct {
		name                  string
		branchPolicy          *ProtectedBranch
		tagPolicy             *ProtectedTag
		controls              slsa.Controls
		expectedLevels        slsa.SourceVerifiedLevels
		expectError           bool
		expectedErrorContains string
	}{
		{
			name:           "Success - L3, Review, Tags",
			branchPolicy:   &policyL3Review,
			tagPolicy:      &tagHygienePolicy,
			controls:       slsa.Controls{continuityEnforcedEarlier, provenanceAvailableEarlier, reviewEnforcedEarlier, tagHygieneEarlier},
			expectedLevels: slsa.SourceVerifiedLevels{slsa.ControlName(slsa.SlsaSourceLevel3), slsa.ReviewEnforced, slsa.TagHygiene},
			expectError:    false,
		},
		{
			name:           "Success - L1",
			branchPolicy:   &policyL1NoExtras,
			tagPolicy:      &noTagHygienePolicy,
			controls:       slsa.Controls{}, // L1 is met by default if policy targets L1 and other conditions pass
			expectedLevels: slsa.SourceVerifiedLevels{slsa.ControlName(slsa.SlsaSourceLevel1)},
			expectError:    false,
		},
		{
			name:           "Success - L2 & Review",
			branchPolicy:   &policyL2Review,
			tagPolicy:      &noTagHygienePolicy,
			controls:       slsa.Controls{continuityEnforcedEarlier, reviewEnforcedEarlier, tagHygieneEarlier}, // Provenance not needed for L2
			expectedLevels: slsa.SourceVerifiedLevels{slsa.ControlName(slsa.SlsaSourceLevel2), slsa.ReviewEnforced},
			expectError:    false,
		},
		{
			name:           "Success - L2 & Tags",
			branchPolicy:   &policyL2NoReview,
			tagPolicy:      &tagHygienePolicy,
			controls:       slsa.Controls{continuityEnforcedEarlier, tagHygieneEarlier}, // Provenance not needed for L2
			expectedLevels: slsa.SourceVerifiedLevels{slsa.ControlName(slsa.SlsaSourceLevel2), slsa.TagHygiene},
			expectError:    false,
		},
		{
			name:           "Success - L4",
			branchPolicy:   &policyL4,
			tagPolicy:      &tagHygienePolicy,
			controls:       slsa.Controls{continuityEnforcedEarlier, provenanceAvailableEarlier, reviewEnforcedEarlier, tagHygieneEarlier},
			expectedLevels: slsa.SourceVerifiedLevels{slsa.ControlName(slsa.SlsaSourceLevel4), slsa.TagHygiene},
			expectError:    false,
		},
		{
			name:                  "Error - computeSlsaLevel Fails (Policy L3, Controls L1)",
			branchPolicy:          &policyL3Review, // Wants L3
			tagPolicy:             &noTagHygienePolicy,
			controls:              slsa.Controls{}, // Only eligible for L1
			expectedLevels:        slsa.SourceVerifiedLevels{},
			expectError:           true,
			expectedErrorContains: "but branch is only eligible for SLSA_SOURCE_LEVEL_1",
		},
		{
			name:                  "Error - computeReviewEnforced Fails (Policy L2+Review, Review control missing)",
			branchPolicy:          &policyL2Review, // Wants L2 & Review
			tagPolicy:             &noTagHygienePolicy,
			controls:              slsa.Controls{continuityEnforcedEarlier, tagHygieneEarlier}, // Eligible for L2, but Review control missing
			expectedLevels:        slsa.SourceVerifiedLevels{},
			expectError:           true,
			expectedErrorContains: "policy requires review, but that control is not enabled",
		},
		{
			name:                  "Error - computeTagHygiene Fails (Policy L1+Tags, Tag control Since later than Policy Since)",
			branchPolicy:          &policyL1Earlier, // Wants L1 & Tags, Policy.Since = earlier
			tagPolicy:             &ProtectedTag{Since: earlierFixedTime, TagHygiene: true},
			controls:              slsa.Controls{continuityEnforcedEarlier, tagHygieneNow}, // Eligible L1, Tag.Since = now
			expectedLevels:        slsa.SourceVerifiedLevels{},
			expectError:           true,
			expectedErrorContains: "policy requires tag hygiene since", // ... but that control has only been enabled since ...
		},
		{
			name:           "Success - Mixed Requirements (L3, Review, No Tags)",
			branchPolicy:   &policyL3Review,
			tagPolicy:      &noTagHygienePolicy,
			controls:       slsa.Controls{continuityEnforcedEarlier, provenanceAvailableEarlier, reviewEnforcedEarlier, tagHygieneEarlier},
			expectedLevels: slsa.SourceVerifiedLevels{slsa.ControlName(slsa.SlsaSourceLevel3), slsa.ReviewEnforced},
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
			// slsa.SourceVerifiedLevels is []string, so we can use sort.Strings
			// Need to import "sort"
			// For now, let's assume the order is fixed by the implementation or ensure expectedLevels are in that order.
			// If tests become flaky due to order, uncomment and import "sort":
			// sort.Strings(gotLevels)
			// sort.Strings(tt.expectedLevels)

			if !reflect.DeepEqual(gotLevels, tt.expectedLevels) {
				switch {
				// To make debugging easier when DeepEqual fails on slices:
				case len(gotLevels) == 0 && len(tt.expectedLevels) == 0 && tt.expectedLevels == nil && gotLevels != nil:
					// This handles the specific case where expected is nil []string but got is empty non-nil []string
					// reflect.DeepEqual(nil, []string{}) is false.
					// For our purposes, an empty list of verified levels is the same whether it's nil or an empty slice.
					// So if expected is nil and got is empty, we treat as equal.
				case len(gotLevels) == 0 && tt.expectedLevels == nil:
					// similar to above, if got is empty and expected is nil
				default:
					t.Errorf("evaluateBranchControls() gotLevels = %v, want %v", gotLevels, tt.expectedLevels)
				}
			}
		})
	}
}

func TestComputeTagHygiene(t *testing.T) {
	now := time.Now()
	earlier := now.Add(-time.Hour)

	// Branch Policies
	policyRequiresTagHygieneNow := ProtectedTag{TagHygiene: true, Since: now}
	policyRequiresTagHygieneEarlier := ProtectedTag{TagHygiene: true, Since: earlier}
	policyNotRequiresTagHygiene := ProtectedTag{TagHygiene: false, Since: now}

	// Controls
	tagHygieneControlEnabledNow := slsa.Control{Name: slsa.TagHygiene, Since: now}

	tests := []struct {
		name                  string
		tagPolicy             *ProtectedTag
		controls              slsa.Controls
		expectedControls      []slsa.ControlName
		expectError           bool
		expectedErrorContains string
	}{
		{
			name:             "Policy requires tag hygiene, control compliant (Policy.Since >= Control.Since)",
			tagPolicy:        &policyRequiresTagHygieneNow,
			controls:         slsa.Controls{tagHygieneControlEnabledNow}, // Policy.Since == Control.Since
			expectedControls: []slsa.ControlName{slsa.TagHygiene},
			expectError:      false,
		},
		{
			name:             "Policy does not require tag hygiene - control state irrelevant",
			tagPolicy:        &policyNotRequiresTagHygiene,
			controls:         slsa.Controls{}, // Control state explicitly shown as irrelevant
			expectedControls: []slsa.ControlName{},
			expectError:      false,
		},
		{
			name:                  "Policy requires tag hygiene, control not present: fail",
			tagPolicy:             &policyRequiresTagHygieneNow,
			controls:              slsa.Controls{}, // Tag Hygiene control missing
			expectedControls:      []slsa.ControlName{},
			expectError:           true,
			expectedErrorContains: "policy requires tag hygiene, but that control is not enabled",
		},
		{
			name:                  "Policy requires tag hygiene, control enabled, Policy.Since < Control.Since: fail",
			tagPolicy:             &policyRequiresTagHygieneEarlier,           // Policy.Since is 'earlier'
			controls:              slsa.Controls{tagHygieneControlEnabledNow}, // Control.Since is 'now'
			expectedControls:      []slsa.ControlName{},
			expectError:           true,
			expectedErrorContains: "policy requires tag hygiene since", // ...but that control has only been enabled since...
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotControls, err := computeTagHygiene(nil, tt.tagPolicy, tt.controls)

			if tt.expectError {
				if err == nil {
					t.Errorf("computeTagHygiene() error = nil, want non-nil error containing %q", tt.expectedErrorContains)
				} else if !strings.Contains(err.Error(), tt.expectedErrorContains) {
					t.Errorf("computeTagHygiene() error = %q, want error containing %q", err.Error(), tt.expectedErrorContains)
				}
			} else {
				if err != nil {
					t.Errorf("computeTagHygiene() error = %v, want nil", err)
				}
			}

			if !slices.Equal(gotControls, tt.expectedControls) {
				t.Errorf("computeTagHygiene() gotControls = %v, want %v", gotControls, tt.expectedControls)
			}
		})
	}
}

func TestComputeReviewEnforced(t *testing.T) {
	now := time.Now()
	earlier := now.Add(-time.Hour)

	// Branch Policies
	policyRequiresReviewNow := ProtectedBranch{RequireReview: true, Since: now}
	policyRequiresReviewEarlier := ProtectedBranch{RequireReview: true, Since: earlier}
	policyNotRequiresReview := ProtectedBranch{RequireReview: false, Since: now}

	// Controls
	reviewControlEnabledNow := slsa.Control{Name: slsa.ReviewEnforced, Since: now}

	tests := []struct {
		name                  string
		branchPolicy          *ProtectedBranch
		controls              slsa.Controls
		expectedControls      []slsa.ControlName
		expectError           bool
		expectedErrorContains string
	}{
		{
			name:             "Policy requires review, control compliant (Policy.Since >= Control.Since)",
			branchPolicy:     &policyRequiresReviewNow,
			controls:         slsa.Controls{reviewControlEnabledNow}, // Policy.Since == Control.Since
			expectedControls: []slsa.ControlName{slsa.ReviewEnforced},
			expectError:      false,
		},
		{
			name:             "Policy does not require review - control state irrelevant",
			branchPolicy:     &policyNotRequiresReview,
			controls:         slsa.Controls{}, // Control state explicitly shown as irrelevant
			expectedControls: []slsa.ControlName{},
			expectError:      false,
		},
		{
			name:                  "Policy requires review, control not present: fail",
			branchPolicy:          &policyRequiresReviewNow,
			controls:              slsa.Controls{}, // Review control missing
			expectedControls:      []slsa.ControlName{},
			expectError:           true,
			expectedErrorContains: "policy requires review, but that control is not enabled",
		},
		{
			name:                  "Policy requires review, control enabled, Policy.Since < Control.Since: fail",
			branchPolicy:          &policyRequiresReviewEarlier,           // Policy.Since is 'earlier'
			controls:              slsa.Controls{reviewControlEnabledNow}, // Control.Since is 'now'
			expectedControls:      []slsa.ControlName{},
			expectError:           true,
			expectedErrorContains: "policy requires review since", // ...but that control has only been enabled since...
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotControls, err := computeReviewEnforced(tt.branchPolicy, nil, tt.controls)

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

			if !slices.Equal(gotControls, tt.expectedControls) {
				t.Errorf("computeReviewEnforced() gotEnforced = %v, want %v", gotControls, tt.expectedControls)
			}
		})
	}
}

func TestComputeOrgControls(t *testing.T) {
	now := time.Now()
	earlier := now.Add(-time.Hour)

	// StatusCheckControls
	testedControlPolicy := OrgStatusCheckControl{PropertyName: "ORG_SOURCE_TESTED", Since: now, CheckName: "test"}
	lintedControlPolicy := OrgStatusCheckControl{PropertyName: "ORG_SOURCE_LINTED", Since: now, CheckName: "run-the-linter"}
	earlierTestedControlPolicy := OrgStatusCheckControl{PropertyName: "ORG_SOURCE_TESTED", Since: earlier, CheckName: "test"}
	invalidPropertyNameControlPolicy := OrgStatusCheckControl{PropertyName: "SLSA_TESTED", Since: now, CheckName: "test"}

	// Controls
	testedControl := slsa.Control{Name: "GH_REQUIRED_CHECK_test", Since: now}
	lintedControl := slsa.Control{Name: "GH_REQUIRED_CHECK_run-the-linter", Since: now}
	notListedControl := slsa.Control{Name: "GH_REQUIRED_CHECK_not-configured-in-policy", Since: now}

	tests := []struct {
		name                  string
		orgCheckPolicies      []OrgStatusCheckControl
		controls              slsa.Controls
		expectedControls      []slsa.ControlName
		expectError           bool
		expectedErrorContains string
	}{
		{
			name:             "Single check handled",
			orgCheckPolicies: []OrgStatusCheckControl{testedControlPolicy},
			controls:         slsa.Controls{testedControl},
			expectedControls: []slsa.ControlName{"ORG_SOURCE_TESTED"},
			expectError:      false,
		},
		{
			name:             "Multiple checks handled",
			orgCheckPolicies: []OrgStatusCheckControl{testedControlPolicy, lintedControlPolicy},
			controls:         slsa.Controls{testedControl, lintedControl},
			expectedControls: []slsa.ControlName{"ORG_SOURCE_TESTED", "ORG_SOURCE_LINTED"},
			expectError:      false,
		},
		{
			name:             "Not configured control should not be returned",
			orgCheckPolicies: []OrgStatusCheckControl{testedControlPolicy},
			controls:         slsa.Controls{testedControl, notListedControl},
			expectedControls: []slsa.ControlName{"ORG_SOURCE_TESTED"},
			expectError:      false,
		},
		{
			name:                  "Policy requires control but it is not present",
			orgCheckPolicies:      []OrgStatusCheckControl{testedControlPolicy, lintedControlPolicy},
			controls:              slsa.Controls{lintedControl},
			expectedControls:      []slsa.ControlName{},
			expectError:           true,
			expectedErrorContains: "policy requires check 'test', but",
		},
		{
			name:                  "Control not enabled long enough fails",
			orgCheckPolicies:      []OrgStatusCheckControl{earlierTestedControlPolicy},
			controls:              slsa.Controls{testedControl},
			expectedControls:      []slsa.ControlName{},
			expectError:           true,
			expectedErrorContains: "policy requires check 'test' since",
		},
		{
			name:                  "Invalid property name fails",
			orgCheckPolicies:      []OrgStatusCheckControl{testedControlPolicy, invalidPropertyNameControlPolicy},
			controls:              slsa.Controls{testedControl},
			expectedControls:      []slsa.ControlName{},
			expectError:           true,
			expectedErrorContains: "policy specifies an invalid property name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			branchPolicy := ProtectedBranch{RequiredStatusChecks: tt.orgCheckPolicies}
			gotControls, err := computeOrgControls(&branchPolicy, nil, tt.controls)

			if tt.expectError {
				if err == nil {
					t.Errorf("computeOrgControls() error = nil, want non-nil error containing %q", tt.expectedErrorContains)
				} else if !strings.Contains(err.Error(), tt.expectedErrorContains) {
					t.Errorf("computeOrgControls() error = %q, want error containing %q", err.Error(), tt.expectedErrorContains)
				}
			} else {
				if err != nil {
					t.Errorf("computeOrgControls() error = %v, want nil", err)
				}
			}

			if !slices.Equal(gotControls, tt.expectedControls) {
				t.Errorf("computeOrgControls() gotControls = %v, want %v", gotControls, tt.expectedControls)
			}
		})
	}
}

func TestComputeSlsaLevel(t *testing.T) {
	now := time.Now()
	earlier := now.Add(-time.Hour)

	// Controls
	continuityEnforcedNow := slsa.Control{Name: slsa.ContinuityEnforced, Since: now}
	provenanceAvailableNow := slsa.Control{Name: slsa.ProvenanceAvailable, Since: now}
	reviewEnforcedNow := slsa.Control{Name: slsa.ReviewEnforced, Since: now}
	tagHygieneNow := slsa.Control{Name: slsa.TagHygiene, Since: now}
	continuityEnforcedEarlier := slsa.Control{Name: slsa.ContinuityEnforced, Since: earlier}
	provenanceAvailableEarlier := slsa.Control{Name: slsa.ProvenanceAvailable, Since: earlier}
	reviewEnforcedEarlier := slsa.Control{Name: slsa.ReviewEnforced, Since: earlier}
	tagHygieneEarlier := slsa.Control{Name: slsa.TagHygiene, Since: earlier}

	// Branch Policies
	policyL4Now := ProtectedBranch{TargetSlsaSourceLevel: slsa.SlsaSourceLevel4, Since: now}
	policyL3Now := ProtectedBranch{TargetSlsaSourceLevel: slsa.SlsaSourceLevel3, Since: now}
	policyL2Now := ProtectedBranch{TargetSlsaSourceLevel: slsa.SlsaSourceLevel2, Since: now}
	policyUnknownLevel := ProtectedBranch{TargetSlsaSourceLevel: "UNKNOWN_LEVEL", Since: now}

	tests := []struct {
		name                  string
		branchPolicy          *ProtectedBranch
		controls              slsa.Controls
		expectedLevels        []slsa.ControlName
		expectError           bool
		expectedErrorContains string
	}{
		{
			name:           "Controls L4-eligible (since 'earlier'), Policy L4 (since 'now'): success",
			branchPolicy:   &policyL4Now,
			controls:       slsa.Controls{continuityEnforcedEarlier, provenanceAvailableEarlier, reviewEnforcedEarlier, tagHygieneEarlier},
			expectedLevels: []slsa.ControlName{slsa.ControlName(slsa.SlsaSourceLevel4)},
			expectError:    false,
		},
		{
			name:           "Controls L3-eligible (since 'earlier'), Policy L2 (since 'now'): success",
			branchPolicy:   &policyL2Now,                                                                            // Policy L2, Since 'now'
			controls:       slsa.Controls{continuityEnforcedEarlier, provenanceAvailableEarlier, tagHygieneEarlier}, // Eligible L3 since 'earlier'
			expectedLevels: []slsa.ControlName{slsa.ControlName(slsa.SlsaSourceLevel2)},
			expectError:    false,
		},
		{
			name:                  "Controls L1-eligible, Policy L2: fail (eligibility)",
			branchPolicy:          &policyL2Now,    // Policy L2
			controls:              slsa.Controls{}, // Eligible L1
			expectedLevels:        []slsa.ControlName{},
			expectError:           true,
			expectedErrorContains: "but branch is only eligible for SLSA_SOURCE_LEVEL_1",
		},
		{
			name:           "Eligible L3 (since 'earlier'), Policy L3 (since 'now'): compliant Policy.Since",
			branchPolicy:   &policyL3Now,                                                                            // Policy L3, Since 'now'
			controls:       slsa.Controls{continuityEnforcedEarlier, provenanceAvailableEarlier, tagHygieneEarlier}, // Eligible L3 since 'earlier'
			expectedLevels: []slsa.ControlName{slsa.ControlName(slsa.SlsaSourceLevel3)},                             // Policy.Since ('now') is not before EligibleSince ('earlier')
			expectError:    false,
		},
		{
			name:                  "Controls L4-eligible (since 'now'), Policy L4 (since 'earlier'): fail (Policy.Since too early)",
			branchPolicy:          &ProtectedBranch{TargetSlsaSourceLevel: slsa.SlsaSourceLevel4, Since: earlier},
			controls:              slsa.Controls{continuityEnforcedNow, provenanceAvailableNow, reviewEnforcedNow, tagHygieneNow},
			expectedLevels:        []slsa.ControlName{},
			expectError:           true,
			expectedErrorContains: "policy sets target level SLSA_SOURCE_LEVEL_4 since", // ...but it has only been eligible for that level since...
		},
		{
			name:                  "Controls L3-eligible (since 'now'), Policy L3 (since 'earlier'): fail (Policy.Since too early)",
			branchPolicy:          &ProtectedBranch{TargetSlsaSourceLevel: slsa.SlsaSourceLevel3, Since: earlier}, // Policy L3, Since 'earlier'
			controls:              slsa.Controls{continuityEnforcedNow, provenanceAvailableNow, tagHygieneNow},    // Eligible L3 since 'now'
			expectedLevels:        []slsa.ControlName{},
			expectError:           true,
			expectedErrorContains: "policy sets target level SLSA_SOURCE_LEVEL_3 since",
		},
		{
			name:                  "Controls L2-eligible (since 'now'), Policy L2 (since 'earlier'): fail (Policy.Since too early)",
			branchPolicy:          &ProtectedBranch{TargetSlsaSourceLevel: slsa.SlsaSourceLevel2, Since: earlier},
			controls:              slsa.Controls{continuityEnforcedEarlier, tagHygieneNow},
			expectedLevels:        []slsa.ControlName{},
			expectError:           true,
			expectedErrorContains: "policy sets target level SLSA_SOURCE_LEVEL_2 since",
		},
		{
			name:                  "Policy L?'UNKNOWN' (controls L3-eligible): fail (policy target unknown)",
			branchPolicy:          &policyUnknownLevel,                                          // Policy "UNKNOWN_LEVEL"
			controls:              slsa.Controls{continuityEnforcedNow, provenanceAvailableNow}, // Eligible L3
			expectedLevels:        []slsa.ControlName{},
			expectError:           true,
			expectedErrorContains: "policy sets target level UNKNOWN_LEVEL",
		},
		// This single case covers eligibility failure where target > eligible.
		// It replaces the two previous similar cases:
		// "computeEligibleSince returns nil (controls insufficient for target level)" which was L2 controls for L3 policy
		// "Controls for L1, Policy L3, computeEligibleSince for L3 returns nil" which was L1 controls for L3 policy
		{
			name:                  "Controls L1-eligible, Policy L3: fail (eligibility)",
			branchPolicy:          &policyL3Now,    // Policy L3
			controls:              slsa.Controls{}, // Eligible L1
			expectedLevels:        []slsa.ControlName{},
			expectError:           true,
			expectedErrorContains: "but branch is only eligible for SLSA_SOURCE_LEVEL_1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLevels, err := computeSlsaLevel(tt.branchPolicy, nil, tt.controls)

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

			if !slices.Equal(gotLevels, tt.expectedLevels) {
				t.Errorf("computeSlsaLevel() gotLevel = %v, want %v", gotLevels, tt.expectedLevels)
			}
		})
	}
}

func TestComputeEligibleSince(t *testing.T) {
	time1 := time.Now()
	time2 := time1.Add(time.Hour)
	zeroTime := time.Time{}

	continuityEnforcedT1 := slsa.Control{Name: slsa.ContinuityEnforced, Since: time1}
	provenanceAvailableT1 := slsa.Control{Name: slsa.ProvenanceAvailable, Since: time1}
	reviewEnforcedT1 := slsa.Control{Name: slsa.ReviewEnforced, Since: time1}
	tagHygieneT1 := slsa.Control{Name: slsa.TagHygiene, Since: time1}
	continuityEnforcedT2 := slsa.Control{Name: slsa.ContinuityEnforced, Since: time2}
	provenanceAvailableT2 := slsa.Control{Name: slsa.ProvenanceAvailable, Since: time2}
	reviewEnforcedT2 := slsa.Control{Name: slsa.ReviewEnforced, Since: time2}
	tagHygieneZero := slsa.Control{Name: slsa.TagHygiene, Since: zeroTime}
	continuityEnforcedZero := slsa.Control{Name: slsa.ContinuityEnforced, Since: zeroTime}
	provenanceAvailableZero := slsa.Control{Name: slsa.ProvenanceAvailable, Since: zeroTime}

	tests := []struct {
		name          string
		controls      slsa.Controls
		level         slsa.SlsaSourceLevel
		expectedTime  *time.Time
		expectError   bool
		expectedError string
	}{
		{
			name:         "L4 eligible (prov, review later)",
			controls:     slsa.Controls{continuityEnforcedT1, provenanceAvailableT2, reviewEnforcedT2, tagHygieneT1},
			level:        slsa.SlsaSourceLevel4,
			expectedTime: &time2,
			expectError:  false,
		},
		{
			name:         "L4 eligible (continuity later)",
			controls:     slsa.Controls{continuityEnforcedT2, provenanceAvailableT1, reviewEnforcedT1, tagHygieneT1},
			level:        slsa.SlsaSourceLevel4,
			expectedTime: &time2,
			expectError:  false,
		},
		{
			name:         "L3 eligible (ProvLater), L3 requested: expect Prov.Since",
			controls:     slsa.Controls{continuityEnforcedT1, provenanceAvailableT2, tagHygieneT1},
			level:        slsa.SlsaSourceLevel3,
			expectedTime: &time2,
			expectError:  false,
		},
		{
			name:         "L3 eligible (ContLater), L3 requested: expect Cont.Since",
			controls:     slsa.Controls{continuityEnforcedT2, provenanceAvailableT1, tagHygieneT1},
			level:        slsa.SlsaSourceLevel3,
			expectedTime: &time2,
			expectError:  false,
		},
		{
			name:         "L2 eligible (Cont&HygieneOnly), L2 requested: expect Cont.Since", // Was: "Eligible for SLSA Level 2"
			controls:     slsa.Controls{continuityEnforcedT1, tagHygieneT1},
			level:        slsa.SlsaSourceLevel2,
			expectedTime: &time1,
			expectError:  false,
		},
		{
			name:         "L1 eligible (NoControls), L1 requested: expect ZeroTime", // Was: "Eligible for SLSA Level 1"
			controls:     slsa.Controls{},
			level:        slsa.SlsaSourceLevel1,
			expectedTime: &zeroTime,
			expectError:  false,
		},
		{
			name:         "L3 eligible, L2 requested: expect Cont.Since",
			controls:     slsa.Controls{continuityEnforcedT1, provenanceAvailableT2, tagHygieneT1},
			level:        slsa.SlsaSourceLevel2,
			expectedTime: &time1,
			expectError:  false,
		},
		{
			name:         "L2 eligible, L3 requested: expect nil, no error",
			controls:     slsa.Controls{continuityEnforcedT1, tagHygieneT1},
			level:        slsa.SlsaSourceLevel3,
			expectedTime: nil,
			expectError:  false,
		},
		{
			name:         "Unknown level requested: expect nil, error",
			controls:     slsa.Controls{},
			level:        slsa.SlsaSourceLevel("UNKNOWN_LEVEL"),
			expectedTime: &zeroTime,
			expectError:  false,
		},
		{
			name:         "L3 eligible (ContZero, ProvNonZero, TagNoZero), L3 requested: expect Prov.Since",
			controls:     slsa.Controls{continuityEnforcedZero, provenanceAvailableT2, tagHygieneT1},
			level:        slsa.SlsaSourceLevel3,
			expectedTime: &time2,
			expectError:  false,
		},
		{
			name:         "L3 eligible (ContNonZero, ProvZero, TagNoZero), L3 requested: expect Cont.Since",
			controls:     slsa.Controls{continuityEnforcedT1, provenanceAvailableZero, tagHygieneT1},
			level:        slsa.SlsaSourceLevel3,
			expectedTime: &time1,
			expectError:  false,
		},
		{
			name:         "L3 eligible (AllZero), L3 requested: expect ZeroTime",
			controls:     slsa.Controls{continuityEnforcedZero, provenanceAvailableZero, tagHygieneZero},
			level:        slsa.SlsaSourceLevel3,
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

func assertPolicyResultEquals(t *testing.T, ctx context.Context, ghConn *ghcontrol.GitHubConnection, pe *PolicyEvaluator, expectedPolicy *RepoPolicy, expectedBranchPolicy *ProtectedBranch, expectedPath string) {
	rp, gotPath, err := pe.GetPolicy(ctx, ghConn)
	if err != nil {
		t.Fatalf("GetPolicy() error = %v, want nil", err)
	}
	if gotPath != expectedPath {
		t.Errorf("GetPolicy() gotPath = %q, want %q (temp file path)", gotPath, expectedPath)
	}
	if expectedPolicy == nil {
		if rp != nil {
			t.Fatalf("GetPolicy() expectedPolicy == nil but got non-nil policy %+v", rp)
		}
		return // quite while we're ahead
	}

	if rp == nil {
		t.Fatalf("GetPolicy() rp is nil but expectedPolicy is not")
	}

	// TODO: check the rest of the contents of expectedPolicy?

	gotPb := rp.getBranchPolicy(ghcontrol.GetBranchFromRef(ghConn.GetFullRef()))

	if expectedBranchPolicy == nil {
		if gotPb != nil {
			t.Fatalf("GetPolicy() expectedBranchPolicy == nil but got non-nil branch policy %+v", rp)
		}
		return
	}
	assertProtectedBranchEquals(t, gotPb, expectedBranchPolicy, false)
}

func TestGetPolicy_Local_SpecificFound(t *testing.T) {
	pb := createTestBranchPolicy("feature")
	policyToCreate := createTestPolicy(&pb)

	ctx := t.Context()
	ghConn := newTestGhBranchConnection("any", "any", "feature")
	pe := &PolicyEvaluator{}

	policyFilePath := createTempPolicyFile(t, policyToCreate)
	defer os.Remove(policyFilePath) //nolint:errcheck
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
					{Name: "feature", Since: fixedTime, TargetSlsaSourceLevel: slsa.SlsaSourceLevel2},
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
			ctx := t.Context()
			ghConn := newTestGhBranchConnection("any", "any", tt.branchName)
			pe := &PolicyEvaluator{}

			policyFilePath := createTempPolicyFile(t, tt.policyToCreate)
			defer os.Remove(policyFilePath) //nolint:errcheck
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
			ctx := t.Context()
			ghConn := newTestGhBranchConnection("any", "any", tt.branchName)
			pe := &PolicyEvaluator{}
			var policyFilePath string

			if tt.useLocalPolicyPath == "CREATE_TEMP" {
				if tt.policyFileContent == nil {
					t.Fatal("policyFileContent cannot be nil when useLocalPolicyPath is CREATE_TEMP for error cases")
				}
				policyFilePath = createTempPolicyFile(t, tt.policyFileContent)
				defer os.Remove(policyFilePath) //nolint:errcheck // Ensure cleanup even if test expects error
				pe.UseLocalPolicy = policyFilePath
			} else {
				pe.UseLocalPolicy = tt.useLocalPolicyPath // For non-existent file
			}

			gotRp, gotPath, err := pe.GetPolicy(ctx, ghConn)

			if err == nil {
				t.Errorf("GetPolicy() error = nil, want non-nil error")
			}
			if gotRp != nil {
				t.Errorf("GetPolicy() gotRp = %v, want nil", gotRp)
			}
			if gotPath != "" {
				t.Errorf("GetPolicy() gotPath = %q, want \"\"", gotPath)
			}
		})
	}
}

func TestGetPolicy_Remote_SpecificFound(t *testing.T) {
	targetOwner := "owner"
	targetBranch := "feature"
	targetRepo := "repo"
	pb := createTestBranchPolicy(targetBranch)
	expectedPolicy := createTestPolicy(&pb)

	ctx := t.Context()
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
			Type:     github.Ptr("file"),
			Encoding: github.Ptr("base64"),
			Content:  github.Ptr(encodedContent),
			HTMLURL:  github.Ptr(mockPolicyPath),
		}
		respData, err := json.Marshal(mockFileContent)
		if err != nil {
			t.Fatalf("Failed to marshal mock RepositoryContent: %v", err)
		}
		if _, err := w.Write(respData); err != nil {
			t.Fatalf("writing data: %v", err)
		}
	})

	ghConn, mockServer := setupMockGitHubTestEnv(t, targetOwner, targetRepo, targetBranch, handler)
	defer mockServer.Close()

	assertPolicyResultEquals(t, ctx, ghConn, pe, &expectedPolicy, &pb, mockPolicyPath)
}

func TestGetPolicy_Remote_NotFoundCases(t *testing.T) {
	targetOwner := testOwner
	targetRepo := testRepo

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
					{Name: "main", Since: fixedTime, TargetSlsaSourceLevel: slsa.SlsaSourceLevel3},
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
			ctx := t.Context()
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
					if _, err := w.Write(respData); err != nil {
						t.Fatalf("writing data: %v", err)
					}
				}
			})

			ghConn, mockServer := setupMockGitHubTestEnv(t, targetOwner, targetRepo, tt.targetBranch, handler)
			defer mockServer.Close()

			assertPolicyResultEquals(t, ctx, ghConn, pe, tt.mockPolicyContent, nil, tt.expectedPolicyPath)
		})
	}
}

func TestGetPolicy_Remote_ServerError(t *testing.T) {
	ctx := t.Context()
	targetOwner := testOwner
	targetRepo := testRepo
	targetBranch := "main"

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		validateMockServerRequestPath(t, r, targetOwner, targetRepo, targetBranch)
		w.WriteHeader(http.StatusInternalServerError)
	})

	ghConn, mockServer := setupMockGitHubTestEnv(t, targetOwner, targetRepo, targetBranch, handler)
	defer mockServer.Close()

	pe := PolicyEvaluator{UseLocalPolicy: ""}
	// ghConn is now returned by setupMockGitHubTestEnv

	gotPolicy, gotPath, err := pe.GetPolicy(ctx, ghConn)
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
	mockHTMLURL := mockPolicyPath // Still needed for one case
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
			ctx := t.Context()
			targetOwner := testOwner
			targetRepo := testRepo
			targetBranch := "main"

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				validateMockServerRequestPath(t, r, targetOwner, targetRepo, targetBranch)
				w.WriteHeader(http.StatusOK) // Status is OK, but content is bad
				if tt.malformedOuterJSON {
					if _, err := w.Write([]byte("this is not valid RepositoryContent JSON")); err != nil {
						t.Fatalf("Writing data: %v", err)
					}
				} else if tt.badBase64Content {
					mockFileContent := &github.RepositoryContent{
						Type:     github.Ptr("file"),
						Encoding: github.Ptr("base64"),
						Content:  github.Ptr("this-is-not-base64"),
						HTMLURL:  github.Ptr(mockHTMLURL),
					}
					respData, err := json.Marshal(mockFileContent)
					if err != nil {
						t.Fatalf("Failed to marshal mock RepositoryContent: %v", err)
					}
					_, err = w.Write(respData)
					if err != nil {
						t.Fatalf("Failed writing response: %v", err)
					}
				}
			})

			ghConn, mockServer := setupMockGitHubTestEnv(t, targetOwner, targetRepo, targetBranch, handler)
			defer mockServer.Close()

			pe := PolicyEvaluator{UseLocalPolicy: ""}

			gotPolicy, gotPath, err := pe.GetPolicy(ctx, ghConn)
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
